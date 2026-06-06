from celery import shared_task
from django.utils import timezone

from .models import DiskResizeTask

from .services.vc_service import resize_vm_disk

from .services.ansible_service import (
    resize_windows_partition
)


@shared_task
def execute_resize_task(task_id):
    """Celery 异步执行磁盘扩容。

    流程:
    1. resize_vm_disk: vCenter 磁盘扩容
       - 自动检查快照 (#8)
       - 自动检查存储空间 (#4)
       - 通过 disk_key 精确匹配磁盘 (#6)
       - 返回消息含关机提示 (#7)
    2. 若 VM 在线: ansible 扩容文件系统
    3. 若 VM 关机: 跳过 ansible，提示手动扩容
    """

    task = DiskResizeTask.objects.get(
        id=task_id
    )

    try:

        task.status = 'running'
        task.save()

        vc_message = resize_vm_disk(
            vm_ip=task.vm_ip,
            disk_key=task.disk_key,
            add_size=task.add_size
        )

        # 需求 #7: 关机 VM 只扩 vCenter 磁盘
        # 不执行 ansible 文件系统扩容
        if '关机状态' in vc_message:

            task.status = 'success'
            task.result = vc_message
            task.finish_time = timezone.now()
            task.save()
            return

        # VM 在线，执行 ansible 文件系统扩容
        ansible_result = resize_windows_partition(
            vm_ip=task.vm_ip,
        )

        task.status = 'success'
        task.result = (
            f'{vc_message}\n'
            f'文件系统扩容: {ansible_result}'
        )

    except Exception as e:

        task.status = 'failed'
        task.result = str(e)

    task.finish_time = timezone.now()
    task.save()
