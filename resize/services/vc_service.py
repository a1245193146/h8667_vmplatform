import ssl
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

    container = content.viewManager.CreateContainerView(
        content.rootFolder,
        [vim.VirtualMachine],
        True
    )

    for vm in container.view:

        try:

            vm_ip = vm.guest.ipAddress

            if vm_ip == ip:
                return vm

        except Exception:
            continue

    return None


def wait_for_task(task):

    while task.info.state not in [
        vim.TaskInfo.State.success,
        vim.TaskInfo.State.error
    ]:
        pass

    if task.info.state == vim.TaskInfo.State.error:

        error_msg = task.info.error.msg

        raise Exception(error_msg)


def get_vm_disk_list(vm_ip):
    """查询 VM 的所有磁盘列表，供前端下拉选择。

    返回格式:
    [
        {
            'disk_key': 'scsi1000:0',
            'label': 'Hard disk 1',
            'size_gb': 100,
            'datastore': 'datastore1',
            'free_space_gb': 500,
            'scsi_id': '0:0',
        },
        ...
    ]
    """
    si = None

    try:

        si = connect_vcenter()
        content = si.RetrieveContent()
        vm = find_vm_by_ip(content, vm_ip)

        if not vm:
            raise Exception('未找到虚拟机')

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

    finally:

        if si:
            Disconnect(si)


def check_vm_status(vm_ip):
    """检查 VM 状态: 快照和电源。

    返回:
    {
        'has_snapshot': bool,
        'power_state': 'poweredOn' | 'poweredOff' | 'suspended',
        'vm_name': str,
    }
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

        power_state = vm.runtime.powerState

        return {
            'has_snapshot': bool(has_snapshot),
            'power_state': str(power_state),
            'vm_name': vm.name,
        }

    finally:

        if si:
            Disconnect(si)


def resize_vm_disk(
        vm_ip,
        disk_key,
        add_size
):
    """扩容指定磁盘。

    通过 disk_key (scsi{controllerKey}:{unitNumber})
    精确定位磁盘，解决同大小磁盘无法区分的问题。

    返回提示消息字符串。
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

        task = vm.ReconfigVM_Task(spec)

        logger.info('已提交扩容任务')

        wait_for_task(task)

        logger.info('vCenter扩容成功')

        # 需求 #7: 检查电源状态
        power_state = vm.runtime.powerState

        if str(power_state) != 'poweredOn':

            return (
                f'vCenter磁盘扩容成功 '
                f'({current_size_gb}GB → {new_size_gb}GB)。'
                f'虚拟机当前处于关机状态，'
                f'请开机后手动扩容文件系统。'
            )

        return (
            f'vCenter磁盘扩容成功 '
            f'({current_size_gb}GB → {new_size_gb}GB)'
        )

    finally:

        if si:
            Disconnect(si)
