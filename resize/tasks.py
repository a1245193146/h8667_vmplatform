# pyright: reportAttributeAccessIssue=false
import logging

from celery import shared_task
from django.utils import timezone

from .models import DiskResizeTask
from .models import DomainTask
from .models import ServerAuthTask
from .models import TrustSiteTask

from .services.vc_service import resize_vm_disk

from .services.ansible_service import (
    resize_windows_partition
)

from .services.domain_service import execute_domain_config

from .services.server_auth_service import execute_server_auth

from .services.trust_site_service import execute_trust_site

logger = logging.getLogger(__name__)


@shared_task(bind=True, max_retries=20)
def execute_resize_task(self, task_id):
    """Celery 异步执行磁盘扩容。

    流程:
    1. resize_vm_disk: vCenter 磁盘扩容
       - 自动检查快照 (#8)
       - 自动检查存储空间 (#4)
       - 通过 disk_key 精确匹配磁盘 (#6)
       - 返回 dict，含 power_state (#7)
    2. 若 VM 在线: ansible 扩容文件系统
    3. 若 VM 关机: 跳过 ansible，提示手动扩容

    并发守卫: 同一 VM 已有 running 任务时，
    30 秒后重试等待对方完成。
    """

    try:
        task = DiskResizeTask.objects.get(
            id=task_id
        )
    except DiskResizeTask.DoesNotExist:
        logger.error(
            f'扩容任务不存在，放弃执行: id={task_id}'
        )
        return

    # 并发守卫: 同 VM 不允许并行扩容
    conflict = DiskResizeTask.objects.filter(
        vm_ip=task.vm_ip,
        status='running'
    ).exclude(id=task.id).exists()

    if conflict:
        logger.info(
            f'VM {task.vm_ip} 存在执行中的扩容任务，'
            f'30秒后重试: task_id={task_id}'
        )
        raise self.retry(countdown=30)

    task.status = 'running'
    task.save()

    try:

        vc_result = resize_vm_disk(
            vm_ip=task.vm_ip,
            disk_key=task.disk_key,
            add_size=task.add_size
        )

    except Exception as e:

        task.status = 'failed'
        task.result = str(e)
        task.finish_time = timezone.now()
        task.save()
        return

    vc_message = vc_result['message']

    # 需求 #7: 关机 VM 只扩 vCenter 磁盘
    # 不执行 ansible 文件系统扩容
    if vc_result['power_state'] != 'poweredOn':

        task.status = 'success'
        task.result = vc_message
        task.finish_time = timezone.now()
        task.save()
        return

    # VM 在线，执行 ansible 文件系统扩容
    try:

        ansible_result = resize_windows_partition(
            vm_ip=task.vm_ip,
            drive_letter=task.drive_letter or ''
        )

        task.status = 'success'
        task.result = (
            f'{vc_message}\n'
            f'文件系统扩容: {ansible_result}'
        )

    except Exception as e:

        # vCenter 磁盘已扩成功，仅文件系统扩容失败，
        # result 中必须保留 vCenter 已成功的事实
        task.status = 'failed'
        task.result = (
            f'{vc_message}，'
            f'但文件系统扩容失败：{e}'
        )

    task.finish_time = timezone.now()
    task.save()


@shared_task
def execute_domain_task(task_id):
    """Celery 异步执行域名配置。

    流程:
    1. execute_domain_config: nginx反代 + DNS + SSL证书
    2. 记录各步骤状态到 result 字段
    """

    try:
        task = DomainTask.objects.get(
            id=task_id
        )
    except DomainTask.DoesNotExist:
        logger.error(
            f'域名配置任务不存在，放弃执行: id={task_id}'
        )
        return

    try:

        task.status = 'running'
        task.save()

        result = execute_domain_config(
            domain=task.domain,
            ip=task.backend_ip,
            port=task.port,
        )

        # 格式化结果: 显示各步骤状态
        result_lines = []
        status_map = {
            'status1': 'nginx反代',
            'status2': '负载均衡',
            'status3': 'DNS记录',
            'status4': 'SSL证书',
        }
        for key, label in status_map.items():
            val = result.get(key, 'False')
            result_lines.append(f'{label}: {"成功" if val == "True" else "失败"}')

        if result.get('mess'):
            result_lines.append('消息: ' + '; '.join(str(m) for m in result['mess']))

        task.status = 'success'
        task.result = '\n'.join(result_lines)

    except Exception as e:

        task.status = 'failed'
        task.result = str(e)

    task.finish_time = timezone.now()
    task.save()


@shared_task
def execute_server_auth_task(task_id):
    """Celery 异步执行服务器授权登录。

    流程:
    1. 解析服务器 IP/主机名
    2. 写入 AD userWorkstations 允许登录
    3. 将账号加入各服务器本地管理员组
    """

    try:
        task = ServerAuthTask.objects.get(
            id=task_id
        )
    except ServerAuthTask.DoesNotExist:
        logger.error(
            f'服务器授权任务不存在，放弃执行: id={task_id}'
        )
        return

    try:

        task.status = 'running'
        task.save()

        result = execute_server_auth(
            account=task.login_account,
            hostname_ip=task.hostname_ip,
            applicant=task.applicant,
        )

        task.status = 'success'
        task.result = result

    except Exception as e:

        task.status = 'failed'
        task.result = str(e)

    task.finish_time = timezone.now()
    task.save()


@shared_task
def execute_trust_site_task(task_id):
    """Celery 异步执行受信任站点设置。

    流程:
    1. 通过 WinRM 执行 GPO 更新
    2. 将域名加入用户 IE/Edge 受信任站点
    """

    try:
        task = TrustSiteTask.objects.get(
            id=task_id
        )
    except TrustSiteTask.DoesNotExist:
        logger.error(
            f'受信任站点任务不存在，放弃执行: id={task_id}'
        )
        return

    try:

        task.status = 'running'
        task.save()

        result = execute_trust_site(
            target_domain=task.domain,
            applicant=task.applicant,
        )

        task.status = 'success'
        task.result = result

    except Exception as e:

        task.status = 'failed'
        task.result = str(e)

    task.finish_time = timezone.now()
    task.save()
