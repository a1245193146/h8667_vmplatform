"""运维问答窗：把"记不住命令"这件事交给内网大模型。

需求来源很实在：运维要在几十台 Windows/Linux 上排查问题，命令语法记不全，
又不可能每次都去翻文档。但把大模型接进一个【可写】的模块，边界必须写死：

  - 模型【没有执行能力】。它只产出命令文本；要落到机器上必须回到命令控制台，
    照常走判级 / 必填原因 / 灰度 / 留痕。不存在"模型触发了执行"这条路径。
  - 模型输出只能落在"建议"。凡涉及对现场状态的断言，提示词强制标注
    【推测】/【待验证】，与运维分析模块的 fact/inference 分离口径一致。
  - 送进模型的一切文本都先过 llm.redact()：用户很可能把带密码的日志行直接粘进来。
  - 提示词里不含任何凭据（内网虽允许服务端持有明文，但不允许它经模型外泄）。

模型是思考型（Qwen3 系），首字慢、单次 10~60s，故问答一律走 Celery + 轮询，
不在 HTTP 请求里同步等——nginx 的读超时比模型短，同步等必然偶发 504。
"""
import logging

from opsanalysis.services import llm

logger = logging.getLogger(__name__)

# 一次问答带给模型的历史轮数。带太多会挤占证据预算（MAX_CHARS），
# 带太少模型会忘了前文；6 轮（3 问 3 答）对命令行咨询足够。
HISTORY_TURNS = 6
# 单条历史消息截断长度：用户可能粘了一整屏日志
HISTORY_CLIP = 3000

SYSTEM_PROMPT = """你是内网服务器运维平台的命令行顾问。用户是隔离内网（无公网）的 \
Windows / Linux 服务器运维工程师，他记不住所有命令的语法，需要你给出可直接执行的命令。

运行环境（回答必须贴合这些约束）：
- Windows 服务器：Windows Server，PowerShell 5.1。没有 pwsh 7 的语法（不支持 \
`??`、三元运算符 `? :`、`ForEach-Object -Parallel`），不要使用。
- Linux 服务器：CentOS 7.9，bash，Python 2/3 可能并存。
- 有 Ansible 控制机可批量下发；目标机通过 WinRM(Windows) / SSH(Linux) 连接。
- 内网隔离：任何需要访问公网的命令（curl 外网、pip install、apt update）都不可用，\
不要建议用户去下载东西。

输出要求（务必逐条遵守）：
1. 命令一律放进 ```powershell 或 ```bash 代码块，一条命令一个代码块，便于逐条复制。
2. 命令必须能在目标机上直接执行。不要写伪代码、不要写"请替换为你的路径"；\
如果必须用变量，就在代码块里的第一行给出赋值语句。
3. 顺序：先给【只读排查】命令，再给【变更】命令。每条变更命令上方单独标注 \
【会改变系统状态】；不可逆或会中断业务的，标注【危险：不可逆 / 会中断业务】并说明后果。
4. 读取 Windows 事件日志必须用 `Get-WinEvent -FilterHashtable @{...}` 并带 `-MaxEvents` \
上限。绝对不要写 `Get-WinEvent -LogName X | Where-Object ...`——那样会把整机日志读进内存，\
曾导致采集超时。
5. 凡是对现场状态的判断（"这台机器大概是磁盘满了"），必须标注【推测】或【待验证】，\
并紧跟一条用于验证的命令。不要把推测写成事实。
6. 不确定就直说不确定，并给出"如何确认"的命令。绝对不要编造服务名、文件路径、\
事件 ID、注册表键名。
7. 不要建议清除事件日志或 shell 历史。本平台把"事件日志被清除"(事件 ID 104) \
当作事故信号，清日志会让故障分析失去证据。
8. 用中文回答，简洁，不客套，不复述用户的问题。

重要：你【没有执行能力】。你只能给出命令文本，由用户自己决定是否执行。\
永远不要说"我已经帮你执行了""正在为你运行"这类话。"""


def _clip(text, keep):
    s = text if isinstance(text, str) else ('' if text is None else str(text))
    if len(s) <= keep:
        return s
    return s[:keep] + '\n…[已截断 %d 字符]' % (len(s) - keep)


def build_messages(question, os_type='', host='', history=None):
    """拼装发给模型的 messages。所有用户可控文本都先脱敏再入提示词。

    messages 里【只能有一条 system，且必须在索引 0】：内网这个 OpenAI 兼容端点
    会校验，多一条或位置靠后就直接回 HTTP 400
    "System message must be at the beginning."。所以目标系统/主机这类上下文是
    拼进那唯一一条 system 的末尾，不能另起一条——早先就是另起了一条，
    导致"选了服务器提问必挂、不选反而能通"这种看着毫无规律的故障。
    opsanalysis/services/llm.py 的 build_messages 一直是单条 system，故那边无恙。
    """
    ctx = []
    if os_type:
        ctx.append('目标系统：%s' % ('Windows（PowerShell 5.1）' if os_type == 'windows'
                                     else 'Linux（CentOS 7.9 / bash）'))
    if host:
        ctx.append('目标主机：%s' % llm.redact(host))

    system = SYSTEM_PROMPT
    if ctx:
        system += '\n\n本次提问的上下文：' + '；'.join(ctx)
    msgs = [{'role': 'system', 'content': system}]

    for m in (history or [])[-HISTORY_TURNS:]:
        role = 'assistant' if getattr(m, 'role', 'user') == 'assistant' else 'user'
        msgs.append({'role': role,
                     'content': _clip(llm.redact(m.content or ''), HISTORY_CLIP)})

    msgs.append({'role': 'user', 'content': _clip(llm.redact(question or ''), 8000)})
    return msgs


def ask(question, os_type='', host='', history=None, timeout=None):
    """问一次。返回 {'ok','text','error','model','latency_ms'}；绝不抛异常。"""
    if not llm.enabled():
        return {'ok': False, 'text': '', 'model': '',
                'error': '大模型未启用：%s' % (llm.disabled_reason() or '未知原因')}
    if not (question or '').strip():
        return {'ok': False, 'text': '', 'model': '', 'error': '问题为空'}

    msgs = build_messages(question, os_type=os_type, host=host, history=history)
    res = llm.chat(msgs, timeout=timeout)
    if not res.get('ok'):
        return {'ok': False, 'text': '', 'model': res.get('model', ''),
                'latency_ms': res.get('latency_ms', 0),
                'error': res.get('error') or '模型未返回内容'}
    text = (res.get('text') or '').strip()
    if not text:
        # llm.chat 自己会把"content 为空"判成失败，这里是防它将来放宽口径：
        # 一条 ok=True 但正文为空的记录，在页面上会显示成"模型已回答（空）"，
        # 比直接报错更难查。宁可当失败处理。
        return {'ok': False, 'text': '', 'model': res.get('model', ''),
                'latency_ms': res.get('latency_ms', 0),
                'error': '模型返回了空内容（HTTP 成功但正文为空）。'
                         '思考型模型在输出预算被思维链耗尽时会这样，'
                         '请确认 LLM_MAX_TOKENS 为 0（不带上限）后重试。'}
    return {'ok': True, 'text': text, 'model': res.get('model', ''),
            'latency_ms': res.get('latency_ms', 0), 'error': ''}
