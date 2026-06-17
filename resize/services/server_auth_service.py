"""Windows 服务器授权登录服务。

将指定 AD 域账号授权登录到目标服务器（写入 AD ``userWorkstations`` 属性），
并将该账号加入目标服务器的本地管理员组。

逻辑移植自运维脚本 ad_ldap 模块，凭据集中在 settings.AD_CONFIG。
"""

import logging
import os
import socket
from datetime import datetime

from django.conf import settings


logger = logging.getLogger(__name__)


def _cfg():
    return settings.AD_CONFIG


def _build_file_logger():
    """构建按天写入文件的日志记录器（与原运维脚本保持一致）。

    日志目录: settings.AD_CONFIG['LOG_DIR'] (默认 D:\\logs\\ywops\\server)
    返回 (logger, log_file_path)。若目录不可写则返回 (module logger, None)。
    """
    log_dir = _cfg().get('LOG_DIR', r'D:\logs\ywops\server')
    current = datetime.now().strftime('%Y-%m-%d')
    file_log_path = os.path.join(log_dir, f'{current}.log')

    try:
        os.makedirs(log_dir, exist_ok=True)
    except Exception as e:
        logger.warning('无法创建服务器授权日志目录 %s: %s', log_dir, e)
        return logger, None

    file_logger = logging.getLogger(f'server_auth.{current}')
    file_logger.setLevel(logging.INFO)
    file_logger.propagate = False

    # 避免重复添加 handler
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


def convert_ip_hostname(input_list):
    """将用户输入（IP 或主机名混合）解析为 (ips, machinenames, err_info)。

    - 含 3 个点视为 IP，反查主机名
    - 否则视为主机名，正向解析 IP
    """
    err_info = None
    ips = []
    machinenames = []

    for info in input_list:
        info = info.strip()
        if not info:
            continue
        try:
            if info.count('.') == 3:
                hostname = socket.gethostbyaddr(info)[0]
                machinenames.append(hostname)
                ips.append(info)
            else:
                ip = socket.gethostbyname(info)
                machinenames.append(info)
                ips.append(ip)
        except (socket.herror, socket.gaierror):
            err_info = f'DNS找不到{info}对应的IP地址，该主机可能在域里不存在'
            logger.warning('解析 %s 失败: %s', info, err_info)
            continue

    return ips, machinenames, err_info


def get_user_dn(account):
    """根据 sAMAccountName 返回用户 distinguishedName。

    返回 (user_dn, conn, err)。出错时 user_dn/conn 可能为 None。
    """
    cfg = _cfg()
    user_dn, conn, err = None, None, None
    try:
        from ldap3 import Server, Connection, ALL

        server = Server(
            'ldap://{}'.format(cfg['DOMAIN']),
            use_ssl=False,
            get_info=ALL,
        )
        conn = Connection(
            server,
            user=cfg['USERNAME'],
            password=cfg['PASSWORD'],
            auto_bind=True,
        )
        search_filter = f'(sAMAccountName={account})'
        search_base = cfg['SEARCH_BASE']
        conn.search(
            search_base, search_filter, attributes=['distinguishedName']
        )
        if not conn.entries:
            err = '输入的用户名可能有误，请查询后再重新输入'
            return None, conn, err
        user_dn = conn.entries[0].distinguishedName
        return user_dn, conn, err
    except Exception:
        err = '输入的用户名可能有误，请查询后再重新输入'
        return user_dn, conn, err


def search_workstation(machinenames, account):
    """允许 account 登录到 machinenames 指定的工作站（写入 userWorkstations）。

    返回 (None, err)。userWorkstations 为空表示该用户可登录所有计算机。
    """
    workstations_attr = 'userWorkstations'

    user_dn, conn, err = get_user_dn(account)
    if err:
        return None, err
    if conn is None:
        return None, 'AD 连接失败'

    try:
        conn.search(
            str(user_dn), '(objectClass=*)', attributes=[workstations_attr]
        )
        workstation_value = conn.entries[0][workstations_attr]

        # 为空表示可登录所有计算机，无需修改
        if workstation_value.value is None:
            conn.unbind()
            return None, None

        workstations_list = str(workstation_value).split(',')
        all_workstations = set(workstations_list + list(machinenames))
        modify_attrs = {
            'userWorkstations': [
                ('MODIFY_REPLACE', [','.join(all_workstations)])
            ]
        }

        if not conn.modify(str(user_dn), modify_attrs):
            err = f'修改 userWorkstations 失败: {conn.result}'

        conn.unbind()
        return None, err
    except Exception as e:
        try:
            conn.unbind()
        except Exception:
            pass
        return None, f'写入工作站登录权限失败: {e}'


def add_account_admin(account, ips):
    """将 account 加入各 IP 服务器的本地管理员组。

    优先使用 WinRM，失败则回退 SSH。返回每台服务器的处理消息列表。
    """
    import paramiko
    import winrm

    cfg = _cfg()
    netbios = cfg.get('NETBIOS', 'hp4307')
    domain_user = cfg['USERNAME']
    domain_password = cfg['PASSWORD']

    messages = []
    command = f'net localgroup Administrators /add "{netbios}\\{account}"'

    for ip in ips:
        winrm_ok = False
        try:
            session = winrm.Session(
                f'http://{ip}:5985/wsman',
                auth=(domain_user, domain_password),
                transport='ntlm',
            )
            result = session.run_ps(command)
            out = result.std_out.decode('utf-8', errors='replace')
            err = result.std_err.decode('utf-8', errors='replace')
            if result.status_code == 0:
                winrm_ok = True
                messages.append(f'[{ip}] 加入管理员组成功(WinRM): {out.strip()}')
            else:
                messages.append(
                    f'[{ip}] WinRM 返回码 {result.status_code}: {err.strip() or out.strip()}'
                )
        except Exception as e:
            messages.append(f'[{ip}] WinRM 连接出错: {e}')

        if winrm_ok:
            continue

        # WinRM 失败，回退 SSH
        client = None
        try:
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            client.connect(
                ip,
                username=domain_user,
                password=domain_password,
                timeout=10,
            )
            _, stdout, stderr = client.exec_command(command)
            out = stdout.read().decode('gbk', errors='replace')
            err = stderr.read().decode('gbk', errors='replace')
            messages.append(f'[{ip}] SSH 执行结果: {(out + err).strip()}')
        except Exception as e:
            messages.append(f'[{ip}] SSH Error: {e}')
        finally:
            if client is not None:
                client.close()

    return messages


def execute_server_auth(account, hostname_ip, applicant=''):
    """Celery 任务入口: 执行服务器授权登录。

    Args:
        account: 要授权的 AD 域账号
        hostname_ip: 逗号分隔的服务器 IP/主机名
        applicant: 申请人（用于文件日志）

    Returns:
        str: 可读的执行结果（写入任务 result 字段）。

    Raises:
        Exception: 当解析失败等致命错误时抛出，由 Celery 任务捕获标记失败。
    """
    file_logger, _ = _build_file_logger()

    input_list = str(hostname_ip).split(',')
    ips, machinenames, err_info = convert_ip_hostname(input_list)

    file_logger.info(
        '用户【%s】尝试对【%s】授权【%s】', applicant, account, hostname_ip
    )

    if err_info:
        file_logger.error('授权失败: %s', err_info)
        raise Exception(err_info)

    # 写入 AD 工作站登录权限
    _, ws_err = search_workstation(machinenames, account)

    # 加入服务器本地管理员组
    admin_messages = add_account_admin(account, ips)

    result_lines = [
        f'目标服务器: {", ".join(ips)}',
        f'工作站登录授权: {"成功" if not ws_err else "失败 - " + str(ws_err)}',
        '管理员组授权:',
    ]
    result_lines.extend('  ' + m for m in admin_messages)

    result_text = '\n'.join(result_lines)
    file_logger.info('授权执行完成:\n%s', result_text)

    return result_text
