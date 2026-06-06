from celery import shared_task
from django.utils import timezone

from .models import DomainTask


@shared_task
def execute_domain_task(task_id):
    """异步执行域名配置任务"""
    task = DomainTask.objects.get(id=task_id)
    task.status = 'running'
    task.save()

    try:
        from .services.nginx_service import execute_domain_setup
        result = execute_domain_setup(task.domain, task.target_ip, task.target_port)

        # Update individual status fields
        task.dns_status = result.get('status3') == 'True'
        task.ssl_status = result.get('status4') == 'True'
        task.nginx_proxy_status = result.get('status1') == 'True'
        task.nginx_upstream_status = result.get('status2') == 'True'

        # Determine overall status
        all_success = all([task.dns_status, task.ssl_status, task.nginx_proxy_status, task.nginx_upstream_status])
        any_success = any([task.dns_status, task.ssl_status, task.nginx_proxy_status, task.nginx_upstream_status])

        if all_success:
            task.status = 'success'
        elif any_success:
            task.status = 'partial_success'
        else:
            task.status = 'failed'

        task.result = str(result)
        task.finish_time = timezone.now()
        task.save()
    except Exception as e:
        task.status = 'failed'
        task.result = str(e)
        task.finish_time = timezone.now()
        task.save()
