import logging
import paramiko

from django.conf import settings

logger = logging.getLogger(__name__)


def resize_windows_partition(vm_ip):

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

    # cmd = f'''
    # cd /etc/ansible && \
    # ansible-playbook \
    # -i hosts \
    # playbooks/windows_extend.yml \
    # -l {vm_ip} \
    # -v
    # '''
    cmd = f'''
    export PYTHONPATH=/opt/venv/lib/python3.12/site-packages:$PYTHONPATH && \
    cd {config["WORKDIR"]} && \
    /usr/bin/ansible-playbook \
    -i {config["INVENTORY"]} \
    {config["PLAYBOOK"]} \
    -l {vm_ip} \
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
    userful_lines = []
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
            userful_lines.append(line)
    summary = '\n'.join(userful_lines)

    # logger.info(f'退出码：{exit_status}')
    # logger.info(f'STDOUT:\\n{result}')

    # if error:

    #     logger.warning(f'STDERR:\\{error}')

    # if exit_status != 0:
        
    #     raise Exception(f'Ansible执行失败:\\{error}')

    # logger.info('Ansible执行完成')

    return summary
