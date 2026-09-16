"""Ansible 执行器：paramiko SSH 到 Ansible 服务器执行 firewall/ansible/ 下的 playbook。

容错红线：任何异常（SSH 失败/超时/退出码非 0）都不向上抛出，
只写入 AnsibleTaskRecord 并返回 {'ok': False, ...}。
"""
import json
import logging
import re
import uuid

import paramiko
from django.conf import settings
from django.utils import timezone

from firewall.models import AnsibleTaskRecord

logger = logging.getLogger(__name__)


def _shell_single_quote(s: str) -> str:
    """把字符串安全放进单引号：' -> '"'"'"""
    return "'" + s.replace("'", "'\"'\"'") + "'"


def run_playbook(playbook: str, extra_vars: dict, timeout: int = 300,
                 initiated_by: str = 'system', name: str = '') -> dict:
    """paramiko SSH 到 Ansible 服务器(复用 settings.ANSIBLE_CONFIG)执行 ansible-playbook
    firewall/ansible/<playbook> -e extra_vars；记录 AnsibleTaskRecord(task_ref=uuid4)；
    返回 {'ok':bool,'task_ref':str,'stdout':str,'error':str}；超时不抛异常，status='timeout'。"""
    config = settings.ANSIBLE_CONFIG
    extra_vars = extra_vars or {}
    task_ref = uuid.uuid4().hex

    record = AnsibleTaskRecord.objects.create(
        task_ref=task_ref,
        name=name or playbook,
        playbook=playbook,
        target_hosts=str(extra_vars.get('target_host', '') or ''),
        status='running',
        initiated_by=initiated_by or 'system',
    )

    extra_json = json.dumps(extra_vars, ensure_ascii=False)
    cmd = (
        f'cd {config["WORKDIR"]} && '
        f'/usr/bin/ansible-playbook '
        f'-i {config["INVENTORY"]} '
        f'firewall/ansible/{playbook} '
        f'-e {_shell_single_quote(extra_json)}'
    )
    logger.info('执行 Ansible playbook: %s task_ref=%s cmd=%s', playbook, task_ref, cmd)

    ssh = None
    try:
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        ssh.connect(
            hostname=config['HOST'],
            username=config['USERNAME'],
            password=config['PASSWORD'],
            timeout=30,
        )
        _, stdout, stderr = ssh.exec_command(cmd, timeout=timeout)
        out = stdout.read().decode(errors='ignore')
        err = stderr.read().decode(errors='ignore')
        exit_status = stdout.channel.recv_exit_status()

        record.output = (out + '\n' + err).strip()
        record.finished_at = timezone.now()
        if exit_status == 0:
            record.status = 'success'
            record.save()
            logger.info('playbook %s 执行成功 task_ref=%s', playbook, task_ref)
            return {'ok': True, 'task_ref': task_ref, 'stdout': out, 'error': ''}

        record.status = 'failed'
        record.save()
        logger.warning('playbook %s 执行失败 exit=%s task_ref=%s', playbook, exit_status, task_ref)
        # stderr 常只有无害 WARNING（如 group name 提示），真正的 fatal 在 stdout。
        # 优先提取 stdout 中的 fatal/FAILED/ERROR 行作为错误摘要，便于日志直接定位。
        fatal_lines = [ln.strip() for ln in out.splitlines()
                       if ('fatal:' in ln or 'FAILED!' in ln or 'ERROR!' in ln)]
        parts = []
        if fatal_lines:
            parts.append(' | '.join(fatal_lines[-3:])[:1000])
        if err.strip():
            parts.append(err.strip()[:500])
        error_summary = ' ; '.join(parts)[:1500] or f'ansible-playbook 退出码={exit_status}'
        return {
            'ok': False,
            'task_ref': task_ref,
            'stdout': out,
            'error': error_summary,
        }
    except TimeoutError as exc:
        # paramiko exec_command 超时抛 socket.timeout（即 TimeoutError）
        record.status = 'timeout'
        record.output = f'执行超时(>{timeout}s): {exc}'
        record.finished_at = timezone.now()
        record.save()
        logger.error('playbook %s 执行超时 task_ref=%s', playbook, task_ref)
        return {'ok': False, 'task_ref': task_ref, 'stdout': '', 'error': f'timeout: {exc}'}
    except Exception as exc:  # SSH 失败等一切异常均不抛出
        record.status = 'failed'
        record.output = f'{type(exc).__name__}: {exc}'
        record.finished_at = timezone.now()
        record.save()
        logger.exception('playbook %s 执行异常 task_ref=%s', playbook, task_ref)
        return {'ok': False, 'task_ref': task_ref, 'stdout': '', 'error': str(exc)}
    finally:
        if ssh is not None:
            try:
                ssh.close()
            except Exception:
                pass


def parse_host_json(stdout: str, host_ip: str) -> dict | None:
    """从 ansible 输出中提取该主机的 JSON（ok:true 时解析 data；失败/unreachable 返回 None）。

    playbook 用 `debug: var=result.stdout` 打印 ps1 的单行 JSON，输出中混有
    PLAY/TASK/RECAP 行。定位 `ok: [host_ip]` 段，取第一个 `{` 到最后一个 `}` 解析。
    兼容：`[ip -> localhost]` 委派段、stdout_lines 分行、CLIXML 包裹、stdout 夹带噪声行。
    """
    if not stdout or not host_ip:
        return None

    escaped = re.escape(host_ip)
    # unreachable / fatal / failed 段直接判失败
    if re.search(rf'(?:unreachable|fatal|failed):\s*\[{escaped}\]', stdout):
        logger.warning('主机 %s unreachable/failed，无法提取 JSON', host_ip)
        return None

    # 同一主机可能有多个 ok/changed 段（run script、debug 等），逐段尝试提取。
    # 注意 delegate_to: localhost 的段形如 `ok: [ip -> localhost]`，也允许匹配。
    matches = list(re.finditer(
        rf'(?:ok|changed):\s*\[{escaped}(?:\s*->\s*[^\]]+)?\][^\n]*', stdout))
    if not matches:
        logger.warning('ansible 输出中未找到主机 %s 的 ok 段', host_ip)
        return None

    for m in matches:
        segment = stdout[m.start():]
        # 截断到下一个 TASK/PLAY 标题，避免串到后续主机/RECAP
        nxt = re.search(r'\n(?:TASK|PLAY)\b', segment)
        if nxt:
            segment = segment[:nxt.start()]

        payload = _loads_brace_json(segment)
        if payload is None:
            continue

        # 解包 debug var=result.stdout 的外层 {"result.stdout": ...}
        # 新版 ansible-core 回调会把"内容是合法JSON的字符串"直接渲染成嵌套字典，
        # 因此 val 可能是 dict（已解析好）也可能是 str（需自行解析），两种都要兼容。
        if isinstance(payload, dict):
            unwrapped = None
            for key in ('result.stdout', 'stdout', 'msg'):
                val = payload.get(key)
                if isinstance(val, dict) and 'ok' in val:
                    unwrapped = val            # 回调已把 JSON 字符串渲染成字典
                    break
                if isinstance(val, str) and '{' in val:
                    unwrapped = _extract_ok_json(val)
                    break
            if unwrapped is None:
                # win_shell 的 stdout_lines：按行拼接后再试（CLIXML/换行切分场景）
                lines = payload.get('result.stdout_lines') or payload.get('stdout_lines')
                if isinstance(lines, list):
                    unwrapped = _extract_ok_json('\n'.join(str(x) for x in lines))
            if unwrapped is not None:
                payload = unwrapped

        if not isinstance(payload, dict) or 'ok' not in payload:
            continue
        if payload.get('ok') is not True:
            logger.warning('主机 %s 脚本返回 ok=%r error=%s', host_ip,
                           payload.get('ok'), payload.get('error'))
            return None
        return payload.get('data')

    # 解析失败时输出 stdout 片段，便于直接定位真实格式（只截断不遗漏）
    logger.warning('主机 %s 的 ansible 输出中未提取到有效 JSON，stdout 前600字符: %r',
                   host_ip, stdout[:600])
    return None


def _extract_ok_json(text: str):
    """从一段字符串中提取 ps1 输出的 {"ok":...} JSON 本体。
    先直接 json.loads；失败则剥离 CLIXML/XML 标签、截取 {"ok" 起至配对的尾括号。"""
    try:
        return json.loads(text)
    except (ValueError, TypeError):
        pass
    # CLIXML 包裹（powershell 子进程经 WinRM 时可能出现）：剥掉所有 <...> 标签
    if '#< CLIXML' in text or '<Objs' in text:
        text = re.sub(r'<[^>]+>', '', text)
    inner = text.find('{"ok"')
    if inner == -1:
        return None
    try:
        return json.loads(text[inner:text.rfind('}') + 1])
    except (ValueError, TypeError):
        return None


def _loads_brace_json(text: str):
    """取 text 中第一个 `{` 到最后一个 `}` 的子串做 json.loads；
    失败时回退定位内层 `{"ok"` 开头的 JSON。"""
    start = text.find('{')
    end = text.rfind('}')
    if start == -1 or end <= start:
        return None
    try:
        return json.loads(text[start:end + 1])
    except (ValueError, TypeError):
        pass
    # 回退：直接找 ps1 输出的 {"ok":...} 本体
    inner = text.find('{"ok"')
    if inner != -1:
        try:
            return json.loads(text[inner:end + 1])
        except (ValueError, TypeError):
            return None
    return None
