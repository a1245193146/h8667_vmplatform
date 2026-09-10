import ssl
import time
import logging

from django.conf import settings

from pyVim.connect import SmartConnect
from pyVim.connect import Disconnect

from pyVmomi import vim

logger = logging.getLogger(__name__)

MAX_ADD_GB = 500
SAFE_RESERVED_GB = 100


def connect_vcenter():

    logger.info('连接vCenter')

    context = ssl._create_unverified_context()

    si = SmartConnect(
        host=settings.VCENTER_CONFIG['HOST'],
        user=settings.VCENTER_CONFIG['USERNAME'],
        pwd=settings.VCENTER_CONFIG['PASSWORD'],
        sslContext=context
    )

    return si


def find_vm_by_ip(content, ip):
    """按 IP 查找虚拟机。

    优先使用 searchIndex.FindByIp（vCenter 服务端索引，O(1)），
    失败时回退 ContainerView 全量遍历（用完必须 Destroy），
    并额外尝试按虚拟机名称匹配（用户可能输入主机名）。
    """

    # 优先: 服务端索引查询
    try:

        vm = content.searchIndex.FindByIp(ip=ip, vmSearch=True)

        if vm:
            return vm

    except Exception:
        logger.warning(
            f'searchIndex.FindByIp 查询失败，回退遍历: {ip}'
        )

    # 回退: 全量遍历
    container = content.viewManager.CreateContainerView(
        content.rootFolder,
        [vim.VirtualMachine],
        True
    )

    try:

        for vm in container.view:

            try:

                vm_ip = vm.guest.ipAddress

                if vm_ip == ip:
                    return vm

            except Exception:
                continue

            # 用户可能输入主机名而非 IP
            try:

                if vm.name == ip:
                    return vm

            except Exception:
                continue

        return None

    finally:

        container.Destroy()


def wait_for_task(task, timeout=600):
    """轮询等待 vCenter 任务完成。

    每 2 秒查询一次任务状态；超过 timeout 秒抛超时异常，
    避免原 pass 死循环忙等待导致的 CPU 空转与无限挂起。
    """

    elapsed = 0
    interval = 2

    while task.info.state not in [
        vim.TaskInfo.State.success,
        vim.TaskInfo.State.error
    ]:

        if elapsed >= timeout:
            raise Exception('vCenter任务超时')

        time.sleep(interval)
        elapsed += interval

    if task.info.state == vim.TaskInfo.State.error:

        error = getattr(task.info, 'error', None)
        error_msg = getattr(error, 'msg', None) or 'vCenter任务失败'

        raise Exception(error_msg)


def _collect_vm_disks(vm):
    """收集 VM 的磁盘列表（含 datastore 剩余空间）。"""

    disks = []

    # 构建 SCSI controller 映射
    scsi_controllers = {}
    for dev in vm.config.hardware.device:
        if isinstance(
            dev, vim.vm.device.VirtualSCSIController
        ):
            scsi_controllers[dev.key] = dev

    for dev in vm.config.hardware.device:

        if not isinstance(
            dev, vim.vm.device.VirtualDisk
        ):
            continue

        disk_gb = int(
            dev.capacityInKB / 1024 / 1024
        )

        controller = scsi_controllers.get(
            dev.controllerKey
        )
        if controller:
            scsi_id = (
                f'{controller.busNumber}'
                f':{dev.unitNumber}'
            )
        else:
            scsi_id = f'?:{dev.unitNumber}'

        disk_key = (
            f'scsi{dev.controllerKey}'
            f':{dev.unitNumber}'
        )

        # 获取 datastore 信息
        datastore = dev.backing.datastore
        ds_name = datastore.name
        free_space_gb = int(
            datastore.summary.freeSpace
            / 1024 / 1024 / 1024
        )

        disks.append({
            'disk_key': disk_key,
            'label': dev.deviceInfo.label,
            'size_gb': disk_gb,
            'datastore': ds_name,
            'free_space_gb': free_space_gb,
            'scsi_id': scsi_id,
        })

    return disks


def get_vm_info(vm_ip):
    """单次 vCenter 连接，返回 VM 的完整信息。

    返回:
    {
        'vm_name': str,
        'power_state': 'poweredOn' | 'poweredOff' | 'suspended',
        'has_snapshot': bool,
        'disks': [
            {
                'disk_key': 'scsi1000:0',
                'label': 'Hard disk 1',
                'size_gb': 100,
                'datastore': 'datastore1',
                'free_space_gb': 500,
                'scsi_id': '0:0',
            },
            ...
        ],
    }

    找不到 VM 抛 Exception('未找到虚拟机')。
    """
    si = None

    try:

        si = connect_vcenter()
        content = si.RetrieveContent()
        vm = find_vm_by_ip(content, vm_ip)

        if not vm:
            raise Exception('未找到虚拟机')

        has_snapshot = (
            vm.snapshot is not None
            and vm.snapshot.rootSnapshotList
        )

        return {
            'vm_name': vm.name,
            'power_state': str(vm.runtime.powerState),
            'has_snapshot': bool(has_snapshot),
            'disks': _collect_vm_disks(vm),
        }

    finally:

        if si:
            Disconnect(si)


def get_vm_disk_list(vm_ip):
    """查询 VM 的所有磁盘列表，供前端下拉选择。

    基于 get_vm_info 的薄封装（保持原返回结构，向后兼容）。
    """

    return get_vm_info(vm_ip)['disks']


def check_vm_status(vm_ip):
    """检查 VM 状态: 快照和电源。

    基于 get_vm_info 的薄封装（保持原返回结构，向后兼容）。

    返回:
    {
        'has_snapshot': bool,
        'power_state': 'poweredOn' | 'poweredOff' | 'suspended',
        'vm_name': str,
    }
    """

    info = get_vm_info(vm_ip)

    return {
        'has_snapshot': info['has_snapshot'],
        'power_state': info['power_state'],
        'vm_name': info['vm_name'],
    }


def resize_vm_disk(
        vm_ip,
        disk_key,
        add_size
):
    """扩容指定磁盘。

    通过 disk_key (scsi{controllerKey}:{unitNumber})
    精确定位磁盘，解决同大小磁盘无法区分的问题。

    返回:
    {
        'success': True,
        'message': str,
        'power_state': str,
        'vm_name': str,
        'old_size_gb': int,
        'new_size_gb': int,
    }
    失败一律 raise Exception。
    """

    if add_size > MAX_ADD_GB:

        raise Exception(
            f'单次扩容不能超过 {MAX_ADD_GB} GB'
        )

    si = None

    try:

        si = connect_vcenter()

        content = si.RetrieveContent()

        logger.info(f'查找虚拟机: {vm_ip}')

        vm = find_vm_by_ip(content, vm_ip)

        if not vm:

            raise Exception('未找到虚拟机')

        logger.info(f'找到虚拟机: {vm.name}')

        # 需求 #8: 快照检测
        if (
            vm.snapshot is not None
            and vm.snapshot.rootSnapshotList
        ):
            raise Exception(
                '虚拟机存在快照，无法在原磁盘扩容。'
                '请先删除快照后重试。'
            )

        # 通过 disk_key 精确匹配磁盘 (需求 #6)
        # disk_key 格式: "scsi{controllerKey}:{unitNumber}"
        parts = disk_key.replace('scsi', '').split(':')
        target_controller_key = int(parts[0])
        target_unit_number = int(parts[1])

        target_disk = None

        for dev in vm.config.hardware.device:

            if not isinstance(
                dev, vim.vm.device.VirtualDisk
            ):
                continue

            if (
                dev.controllerKey == target_controller_key
                and dev.unitNumber == target_unit_number
            ):
                target_disk = dev
                break

        if not target_disk:

            raise Exception(
                f'未找到磁盘: {disk_key}'
            )

        current_size_gb = int(
            target_disk.capacityInKB / 1024 / 1024
        )

        logger.info(
            f'目标磁盘: '
            f'{target_disk.deviceInfo.label} '
            f'{current_size_gb}GB '
            f'key={disk_key}'
        )

        # 需求 #4: 存储空间预检查
        datastore = target_disk.backing.datastore

        free_space_gb = int(
            datastore.summary.freeSpace
            / 1024 / 1024 / 1024
        )

        logger.info(
            f'datastore剩余空间: '
            f'{free_space_gb}GB'
        )

        if free_space_gb < (
                add_size + SAFE_RESERVED_GB
        ):

            raise Exception(
                f'datastore空间不足: '
                f'剩余{free_space_gb}GB, '
                f'需要{add_size + SAFE_RESERVED_GB}GB'
                f'(含{SAFE_RESERVED_GB}GB安全预留)'
            )

        new_size_kb = (
            target_disk.capacityInKB +
            (add_size * 1024 * 1024)
        )

        new_size_gb = int(
            new_size_kb / 1024 / 1024
        )

        logger.info(
            f'开始扩容: '
            f'{current_size_gb}GB '
            f'-> '
            f'{new_size_gb}GB'
        )

        spec = vim.vm.ConfigSpec()

        disk_spec = vim.vm.device.VirtualDeviceSpec()

        disk_spec.operation = (
            vim.vm.device.VirtualDeviceSpec
            .Operation.edit
        )

        disk_spec.device = target_disk

        disk_spec.device.capacityInKB = (
            new_size_kb
        )

        spec.deviceChange = [disk_spec]

        vc_task = vm.ReconfigVM_Task(spec)

        logger.info('已提交扩容任务')

        wait_for_task(vc_task)

        logger.info('vCenter扩容成功')

        # 需求 #7: 检查电源状态
        power_state = str(vm.runtime.powerState)

        if power_state != 'poweredOn':

            message = (
                f'vCenter磁盘扩容成功 '
                f'({current_size_gb}GB → {new_size_gb}GB)。'
                f'虚拟机当前处于关机状态，'
                f'请开机后手动扩容文件系统。'
            )
        else:

            message = (
                f'vCenter磁盘扩容成功 '
                f'({current_size_gb}GB → {new_size_gb}GB)'
            )

        return {
            'success': True,
            'message': message,
            'power_state': power_state,
            'vm_name': vm.name,
            'old_size_gb': current_size_gb,
            'new_size_gb': new_size_gb,
        }

    finally:

        if si:
            Disconnect(si)
