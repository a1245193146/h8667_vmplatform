"""设置受信任站点服务。

通过 WinRM 在域控/服务器上执行组策略 (GPO) 更新，
将指定域名加入用户的 IE/Edge 受信任站点 (ZoneMap)。

逻辑移植自运维脚本 set_domain_trust，凭据集中在 settings.TRUST_SITE_CONFIG。
"""

import logging
import os
from datetime import datetime

from django.conf import settings


logger = logging.getLogger(__name__)


def _cfg():
    return settings.TRUST_SITE_CONFIG


def _build_file_logger():
    """构建按天写入文件的日志记录器（与原运维脚本保持一致）。

    日志目录: settings.TRUST_SITE_CONFIG['LOG_DIR'] (默认 D:\\logs\\ywops\\trust_site)
    返回 (logger, log_file_path)。
    """
    log_dir = _cfg().get('LOG_DIR', r'D:\logs\ywops\trust_site')
    current = datetime.now().strftime('%Y-%m-%d')
    file_log_path = os.path.join(log_dir, f'{current}.log')

    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        logger.warning('无法创建受信任站点日志目录 %s: %s', log_dir, e)
        return logger, None

    file_logger = logging.getLogger(f'trust_site.{current}')
    file_logger.setLevel(logging.INFO)
    file_logger.propagate = False

    if not any(
        isinstance(h, logging.FileHandler)
        and getattr(h, 'baseFilename', '') == os.path.abspath(file_log_path)
        for h in file_logger.handlers
    ):
        handler = logging.FileHandler(file_log_path, mode='a', encoding='utf-8')
        handler.setFormatter(
            logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
        )
        file_logger.addHandler(handler)

    return file_logger, file_log_path


def execute_gpo_update(target_domain, file_logger=None):
    """通过 WinRM 执行 PowerShell GPO 更新，把 target_domain 加入受信任站点。

    返回 (success: bool, message: str)。
    """
    if file_logger is None:
        file_logger, _ = _build_file_logger()

    cfg = _cfg()
    ip = cfg['HOST']
    netbios = cfg.get('NETBIOS', 'hp4307')
    username = cfg['USERNAME']
    password = cfg['PASSWORD']

    import winrm

    try:
        session = winrm.Session(
            f'http://{ip}:5985/wsman',
            auth=(f'{netbios}\\{username}', password),
            transport='ntlm',
        )

        zone_key = (
            'HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion'
            '\\InternetSettings\\ZoneMap\\Domains\\' + target_domain
        )
        powershell_command = (
            'Import-Module GroupPolicy\n'
            'Set-GPPrefRegistryValue -Name "trustiness_sites" -Context "User" '
            f'-Key "{zone_key}" '
            '-ValueName "http" -Type "DWORD" -Value 2 -Action "Update"'
        )

        result = session.run_ps(powershell_command)

        if result.status_code == 0:
            out = result.std_out.decode('utf-8', errors='replace')
            file_logger.info('域名 %s 设置成功', target_domain)
            return True, out
        else:
            error_msg = result.std_err.decode('utf-8', errors='replace')
            file_logger.error(
                '设置失败[%s]: %s', result.status_code, error_msg
            )
            return False, error_msg
    except Exception as e:
        file_logger.exception('执行过程中发生异常')
        return False, str(e)


def execute_trust_site(target_domain, applicant=''):
    """Celery 任务入口: 设置受信任站点。

    Args:
        target_domain: 要加入受信任站点的域名
        applicant: 申请人（用于文件日志）

    Returns:
        str: 可读的执行结果（写入任务 result 字段）。

    Raises:
        Exception: GPO 更新失败时抛出，由 Celery 任务捕获标记失败。
    """
    file_logger, _ = _build_file_logger()

    file_logger.info('收到域名设置请求: %s (申请人: %s)', target_domain, applicant)

    success, message = execute_gpo_update(target_domain, file_logger=file_logger)

    if success:
        return f'信任级别设置成功\n域名: {target_domain}\n详情: {message.strip() or "（无输出）"}'

    raise Exception(f'设置失败: {message}')
