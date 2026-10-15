import logging
import sys

from django.apps import AppConfig

logger = logging.getLogger(__name__)

# 这些命令运行时数据库可能还不存在/正在变更，此时读配置表只会刷一屏无用的告警
_SKIP_APPLY_CMDS = {'migrate', 'makemigrations', 'collectstatic', 'dbshell',
                   'showmigrations', 'flush', 'loaddata', 'dumpdata'}


class SysManageConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'sysmanage'
    verbose_name = '系统管理'

    def ready(self):
        """进程启动时把数据库里的配置覆盖写回 settings。

        放在这里而不是各调用点，是为了让平台里几十处 `settings.XXX_CONFIG[...]`
        的直接读取零改动就吃到库里的值（口径见 services/config.py 模块注释）。
        任何失败都只 warning：配置层挂掉不能让整个应用起不来。
        """
        if _SKIP_APPLY_CMDS & set(sys.argv):
            return
        try:
            from sysmanage.services.config import apply_to_settings
            apply_to_settings()
        except Exception:
            logger.warning('启动时应用数据库配置失败（沿用 settings 默认值）',
                           exc_info=True)
