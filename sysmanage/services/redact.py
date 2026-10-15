"""凭据脱敏：留痕、日志、提示词三条路径共用的唯一实现。

为什么放在 sysmanage 而不是各业务 app：这是平台级的安全兜底。
隔离内网允许服务端持有明文凭据（用户已确认），但"明文进数据库留痕/
进模型提示词/进前端接口"是另一回事——那三条路都可能把凭据带出机器。
故统一在写入前过一遍，不依赖各调用点自觉。

正则与 opsanalysis/services/llm.py 里的原实现同源；llm.redact 已改为
委托本函数（导入失败时退回其内联副本），避免两份实现各自漂移。
"""
import re

_KV_SECRET = re.compile(
    # 允许可选前缀（ansible_password / vault_password / my_secret 之类）：
    # 只匹配裸 password 会漏掉 ansible 最常用的 ansible_password=xxx。
    # 前缀必须以 _ 或 - 结尾，故 xxpassword 这种"更长标识符的一部分"不会误命中。
    r'(?i)\b((?:[A-Za-z0-9]*[_\-])?'
    r'(?:password|passwd|pwd|passphrase|secret|token|access[_-]?key|secret[_-]?key'
    r'|api[_-]?key|apikey|credential|authorization|proxy-authorization|cookie|set-cookie'
    r'|private[_-]?key|ssh-rsa))\b(\s*[=:]\s*)'
    # 值是 Basic/Bearer 时交给 _BEARER 处理，否则这里只会吃掉"Bearer"这个词、把真令牌留下
    r'(?!(?:basic|bearer)\s)'
    # 值可带一对引号：password: "abc123" / password='abc' 是 YAML/ini 里最常见的写法，
    # 若把引号排除在字符类之外就整条匹配不上，密码会原样留下
    r'(["\']?[^\s,;"\'&]{1,200}["\']?)')
_BEARER = re.compile(r'(?i)\b(basic|bearer)\s+[A-Za-z0-9+/=\-_.]{8,}')
_URL_USERINFO = re.compile(r'(?i)\b(https?://)([^/\s:@]+):([^/\s@]+)@')
_LONG_B64 = re.compile(r'\b[A-Za-z0-9+/]{40,}={0,2}\b')
_JWT = re.compile(r'\beyJ[A-Za-z0-9_\-]*\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]*')

MASK = '***'


def redact_text(text, long_b64=True):
    """把文本里可能出现的凭据打码。空值安全，永不抛异常。

    long_b64=True（默认，提示词路径用）：连"40 字符以上的裸 base64/hex 串"一起打码。
    证据文本里这种串几乎只可能是令牌，宁可错杀。

    long_b64=False（执行留痕路径必须用）：**不能**开这一条。命令输出里长串
    字母数字无处不在——文件 SHA256、任务 ID、win_shell 下发的 base64 PowerShell——
    一刀切会把整段输出抹成 ***，留痕就失去了追溯价值（实测 12000 字符的
    ansible 输出被打码成 3 个字符）。留痕只依赖带锚点的精确规则：
    key=value / Bearer / user:pass@ / JWT，这些才是凭据真正会出现的形态。
    """
    if not text:
        return ''
    try:
        s = str(text)
        s = _BEARER.sub(lambda m: '%s %s' % (m.group(1), MASK), s)
        s = _JWT.sub(MASK, s)
        s = _KV_SECRET.sub(lambda m: '%s%s%s' % (m.group(1), m.group(2), MASK), s)
        s = _URL_USERINFO.sub(lambda m: '%s%s:%s@' % (m.group(1), MASK, MASK), s)
        if long_b64:
            s = _LONG_B64.sub(MASK, s)
        return s
    except Exception:
        # 脱敏本身出错时，宁可不返回原文（可能含凭据），返回占位说明
        return '[脱敏处理异常，内容已隐去]'


def mask_value(value):
    """配置项的值摘要：凭据类只露长度，非凭据类露前若干字符。

    用于配置页与审计日志——审计必须能看出"改了什么"，但绝不能把
    凭据明文写进审计表（审计表通常保留期最长、被读的次数最多）。
    """
    if value is None:
        return '(空)'
    if isinstance(value, bool):
        return '是' if value else '否'
    s = value if isinstance(value, str) else str(value)
    if not s:
        return '(空)'
    if len(s) <= 40:
        return s
    return '%s…(共%d字符)' % (s[:40], len(s))


def mask_secret(value):
    """凭据值的掩码：只保留长度信息，一个字符都不露。

    长度本身是有用信息（能看出"是不是没填"和"填的是不是明显太短"），
    但绝不留首尾字符——首尾字符足以让人在别处认出这是哪个凭据。
    """
    if value is None or value == '':
        return '(未设置)'
    s = value if isinstance(value, str) else str(value)
    return '已设置（%d 字符，内容不显示）' % len(s)
