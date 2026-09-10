import re
import logging
import paramiko

from django.conf import settings

logger = logging.getLogger(__name__)


def resize_windows_partition(vm_ip, drive_letter=''):
    """通过 Ansible 扩容 Windows 文件系统分区。

    drive_letter 非空时（如 'D'），向 playbook 传入
    -e drive_letter=X，精准扩容指定分区；为空走原逻辑
    （兼容旧 playbook）。

    Ansible 失败（unreachable/failed 非 0 或退出码非 0）
    一律 raise Exception，让 Celery 任务进入 failed 状态。
    """

    drive_letter = (drive_letter or '').strip().upper()

    if drive_letter:

        if not re.fullmatch(r'[A-Z]', drive_letter):
            raise Exception(f'无效的盘符: {drive_letter}')

    config = settings.ANSIBLE_CONFIG

    ssh = paramiko.SSHClient()

    ssh.set_missing_host_key_policy(
        paramiko.AutoAddPolicy()
    )

    logger.info(
        f'连接Ansible服务器: '
        f'{config["HOST"]}'
    )

    ssh.connect(
        hostname=config['HOST'],
        username=config['USERNAME'],
        password=config['PASSWORD'],
        timeout=30
    )

    # 盘符参数: 精准扩容指定分区
    drive_args = ''
    if drive_letter:
        drive_args = f' -e drive_letter={drive_letter}'

    cmd = f'''
    export PYTHONPATH=/opt/venv/lib/python3.12/site-packages:$PYTHONPATH && \
    cd {config["WORKDIR"]} && \
    /usr/bin/ansible-playbook \
    -i {config["INVENTORY"]} \
    {config["PLAYBOOK"]} \
    -l {vm_ip}{drive_args} \
    -v
    '''

    logger.info(f'执行命令: {cmd}')

    stdin, stdout, stderr = ssh.exec_command(
        cmd,
        timeout=600
    )

    result = stdout.read().decode(errors='ignore')

    error = stderr.read().decode(errors='ignore')
    exit_status = stdout.channel.recv_exit_status()

    ssh.close()
    full_output = result + '\n' + error
    useful_lines = []
    for line in full_output.splitlines():
        line = line.strip()
        # 只保留关键内容
        if (
            'extended successfully' in line.lower()
            or
            'does not need extension' in line.lower()
            or
            'failed=' in line.lower()
            or
            'unreachable=' in line.lower()
        ):
            useful_lines.append(line)
    summary = '\n'.join(useful_lines)

    logger.info(f'退出码: {exit_status}')

    # 解析 PLAY RECAP: unreachable/failed 非 0 即失败
    unreachable = 0
    failed = 0

    for line in full_output.splitlines():

        m = re.search(r'unreachable=(\d+)', line)
        if m:
            unreachable = max(unreachable, int(m.group(1)))

        m = re.search(r'failed=(\d+)', line)
        if m:
            failed = max(failed, int(m.group(1)))

    if unreachable:

        raise Exception(
            f'Ansible主机不可达(unreachable={unreachable}): '
            f'{summary or error or result}'
        )

    if failed:

        raise Exception(
            f'Ansible任务执行失败(failed={failed}): '
            f'{summary or error or result}'
        )

    if exit_status != 0:

        raise Exception(
            f'Ansible执行失败(退出码={exit_status}): '
            f'{summary or error or result}'
        )

    logger.info('Ansible执行完成')

    return summary
