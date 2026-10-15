"""系统管理的周期任务：配置覆盖收敛 + 执行留痕清理。

Celery worker 是长驻进程，不会像 web 进程那样随部署重启，所以库里的配置改动
要靠这个周期任务才能收敛到 worker（保存时只 apply 了当前 web 进程）。
"""
import logging

from celery import shared_task

logger = logging.getLogger(__name__)


@shared_task(name='sysmanage.tasks.reapply_config_task')
def reapply_config_task():
    """把数据库里的配置覆盖重新写回本进程的 settings。"""
    from sysmanage.services.config import apply_to_settings
    applied = apply_to_settings()
    return {'applied': len(applied), 'keys': applied}


@shared_task(name='sysmanage.tasks.purge_execlog_task')
def purge_execlog_task():
    """按保留期清理执行留痕。保留天数本身也是可编辑配置。

    分档保留：探活类（ping）量大、事后价值低，短保留；真正的运维命令长保留。
    删除动作自身会写一条留痕，"我们删了什么"必须可查（见 execlog.purge）。
    """
    from sysmanage.services import execlog
    from sysmanage.services.config import effective

    keep = effective('SYS_EXECLOG_KEEP_DAYS') or 90
    keep_probe = effective('SYS_EXECLOG_PROBE_KEEP_DAYS') or 7
    deleted = execlog.purge(keep_days_shell=keep, keep_days_probe=keep_probe)
    logger.info('执行留痕清理完成：%s', deleted)
    return deleted
