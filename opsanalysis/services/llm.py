"""运维分析——内网大模型辅助分析（只读，非结论）。

用途：把"已经采集到并结构化"的排查/影响分析证据打包成文本，交给内网 OpenAI 兼容
接口（vLLM）生成一段辅助分析意见，供人工决策参考。

红线（务必遵守）：
1. 模型输出只能落在"推测/建议"层面，绝不写入 fact；页面上以独立卡片呈现并显式标注
   "大模型辅助分析（非结论，需人工核实）"，不与已确认事实混排。提示词强制每条结论
   以【已确认事实】/【推测】/【待验证】开头，"可能的故障原因"一节只允许推测。
2. 绝不因为模型给了意见就删减/覆盖任何真实采集数据——模型结果单独存
   analysis['llm']（完整留痕另存 LlmAnalysisRecord），原始 snapshot/analysis 原样保留。
3. 模型无任何执行能力：本模块只做 HTTP 问答，不触发重启/停服/改配置/部署。
   给模型的系统提示里也明确要求"建议只能是只读排查动作"。
4. 提示词里不得出现任何凭据：证据文本统一过 redact() 脱敏（password/token/
   Authorization/Cookie/URL 内嵌账号密码）。
5. 不把日志一股脑塞给模型：只用系统已有的筛选/聚合结果（facts、时间线、按服务标识
   过滤的 OS 事件、Nginx 窗口统计），按段落重要度装进字数预算；装不下就分批问、
   最后一次汇总，批数用尽仍送不出的段落如实写进提示词与页面（"没给到"≠"没有"）。
6. 每条证据行都带主机、时间戳、日志源/组件等元数据，且元数据排在正文之前，
   便于模型做跨主机关联，也保证单行被截断时这些定位信息不会丢。
"""
import json
import logging
import re
import socket
import time
import urllib.error
import urllib.request

from django.conf import settings
from django.utils import timezone

from opsanalysis.services import oslogs

logger = logging.getLogger(__name__)

SCOPES = ('impact', 'troubleshoot')

LINE_CAP = 400          # 单行日志/事件最长保留字符
MIN_ROOM = 200          # 剩余预算低于此值就不再塞新段，避免塞进半句
DEFAULT_BUDGET = 12000  # settings 未配 MAX_CHARS 时的证据字数上限


# ------------------------------------------------------------------ 配置

def config():
    """读取 OPS_LLM_CONFIG，缺失项给安全默认值（绝不抛异常）。"""
    cfg = getattr(settings, 'OPS_LLM_CONFIG', {}) or {}

    def _int(key, default):
        try:
            return int(cfg.get(key, default))
        except (TypeError, ValueError):
            return default

    def _float(key, default):
        try:
            return float(cfg.get(key, default))
        except (TypeError, ValueError):
            return default

    return {
        'ENABLED': bool(cfg.get('ENABLED', False)),
        'BASE_URL': str(cfg.get('BASE_URL') or '').strip(),
        'MODEL': str(cfg.get('MODEL') or '').strip(),
        'API_KEY': str(cfg.get('API_KEY') or ''),
        'TEMPERATURE': _float('TEMPERATURE', 0.2),
        'TIMEOUT': max(5, _int('TIMEOUT', 180)),
        # 下面三个 max_tokens 一律默认 0 = 请求体里不带这个字段，完全跟随服务端。
        # 必须允许"不带"：Qwen3 系是思考型模型，回答前先写 reasoning_content，
        # 一旦给了上限，整份预算可能被思考阶段吃光，content 返回空串而 HTTP 仍是 200
        # ——页面上就是"模型返回空内容"。厂内验证过的成功调用体里根本没有 max_tokens。
        # 配成正数才会发送（仅在确认服务端不思考、或已开 DISABLE_THINKING 时才建议配）。
        'MAX_TOKENS': _int('MAX_TOKENS', 0),
        'MAX_CHARS': max(1000, _int('MAX_CHARS', DEFAULT_BUDGET)),
        # 证据超过 MAX_CHARS 时分批问模型（每批独立作答，最后一次汇总）。
        # 批数上限是防止一次点击把内网模型压垮/让 Celery worker 长时间阻塞。
        'MAX_BATCHES': max(1, _int('MAX_BATCHES', 3)),
        'BATCH_MAX_TOKENS': _int('BATCH_MAX_TOKENS', 0),
        'MERGE_MAX_TOKENS': _int('MERGE_MAX_TOKENS', 0),
        # 思考型模型可选开关：True 时在请求体加 chat_template_kwargs.enable_thinking=false，
        # 让模型跳过思考直接作答（更快、也不会再出现"思考吃光预算"）。
        # 默认 False = 请求体与厂内验证过的成功样例逐字一致；若服务端不认这个字段会报 400，
        # 那就保持 False。
        'DISABLE_THINKING': bool(cfg.get('DISABLE_THINKING', False)),
    }


def enabled():
    c = config()
    return bool(c['ENABLED'] and c['BASE_URL'].startswith(('http://', 'https://')) and c['MODEL'])


def disabled_reason():
    """给页面一句可读的"为什么用不了"，避免用户对着灰按钮猜。"""
    c = config()
    if not c['ENABLED']:
        return '未启用：请在 settings.OPS_LLM_CONFIG 里把 ENABLED 设为 True（或设环境变量 VMP_OPS_LLM_ENABLED=true）'
    if not c['BASE_URL'].startswith(('http://', 'https://')):
        return '未配置模型接口地址：settings.OPS_LLM_CONFIG["BASE_URL"]'
    if not c['MODEL']:
        return '未配置模型名：settings.OPS_LLM_CONFIG["MODEL"]'
    return ''


# ------------------------------------------------------------------ 脱敏

_KV_SECRET = re.compile(
    # 允许可选前缀（ansible_password / vault_password 之类）：只匹配裸 password
    # 会漏掉 ansible 最常用的 ansible_password=xxx。前缀必须以 _ 或 - 结尾，
    # 故 xxpassword 这种"更长标识符的一部分"不会误命中。
    # 与 sysmanage/services/redact.py 的同名正则必须保持一致（test_llm.py 有比对断言）。
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


def _redact_inline(text):
    """脱敏的内联副本，仅在 sysmanage 不可导入时兜底。

    两份实现靠 test_llm.py 的"逐样本比对两份输出一致"这条断言防止漂移——
    改了一边忘了另一边，回归会当场红。
    """
    if not text:
        return ''
    s = str(text)
    s = _BEARER.sub(lambda m: '%s ***' % m.group(1), s)
    s = _JWT.sub('***', s)
    s = _KV_SECRET.sub(lambda m: '%s%s***' % (m.group(1), m.group(2)), s)
    s = _URL_USERINFO.sub(lambda m: '%s***:***@' % m.group(1), s)
    s = _LONG_B64.sub('***', s)
    return s


def redact(text):
    """把证据文本里可能出现的凭据打码。日志行里混进 token/密码很常见，
    模型侧不应拿到，故在"进入提示词之前"统一处理，而不是靠采集端自觉。

    唯一实现在 sysmanage.services.redact（执行留痕/系统日志/提示词三条路径共用），
    这里只做委托；本模块会被独立 harness 在 Django app 未注册的环境下加载，
    故导入失败时退回 _redact_inline，绝不因为脱敏函数让整个模块 import 失败。
    """
    try:
        from sysmanage.services.redact import redact_text
        return redact_text(text)
    except Exception:
        return _redact_inline(text)


# ------------------------------------------------------------------ HTTP 客户端

def chat(messages, max_tokens=None, timeout=None):
    """调用内网 OpenAI 兼容 /chat/completions。只用标准库 urllib，不引新依赖。

    max_tokens=None 时按配置决定；配置为 0（默认）则请求体里不带这个字段——
    思考型模型给了上限容易把预算全花在思维链上、正式回答返回空串。

    返回 {'ok','text','error','model','latency_ms','finish_reason','usage',
    'reasoning_chars'}；失败时另带 'reasoning_preview' 帮助定位。
    任何失败都返回 ok=False + 可读 error，绝不抛异常给调用方（页面上要能降级显示）。
    """
    cfg = config()
    url = cfg['BASE_URL']
    if not url.startswith(('http://', 'https://')):
        return {'ok': False, 'text': '', 'error': '模型接口地址未配置或非法',
                'model': cfg['MODEL'], 'latency_ms': 0}

    payload = {
        'model': cfg['MODEL'],
        'messages': messages,
        'temperature': cfg['TEMPERATURE'],
    }
    # 默认不带 max_tokens/stream，与厂内验证过的成功调用体逐字一致。
    # 只有显式配了正数才发 max_tokens：思考型模型会把预算先花在 reasoning_content 上，
    # 预算在思考阶段耗尽时 content 是空串、HTTP 仍 200，看着就像"模型坏了"。
    mt = int(max_tokens if max_tokens is not None else cfg['MAX_TOKENS'])
    if mt > 0:
        payload['max_tokens'] = mt
    if cfg['DISABLE_THINKING']:
        payload['chat_template_kwargs'] = {'enable_thinking': False}
    body = json.dumps(payload, ensure_ascii=False).encode('utf-8')
    req = urllib.request.Request(url, data=body, method='POST')
    req.add_header('Content-Type', 'application/json; charset=utf-8')
    req.add_header('Accept', 'application/json')
    if cfg['API_KEY']:
        req.add_header('Authorization', 'Bearer %s' % cfg['API_KEY'])

    t0 = time.time()
    try:
        with urllib.request.urlopen(req, timeout=int(timeout or cfg['TIMEOUT'])) as resp:
            raw = resp.read().decode('utf-8', 'replace')
            status = getattr(resp, 'status', 200)
    except urllib.error.HTTPError as e:
        detail = ''
        try:
            detail = e.read().decode('utf-8', 'replace')[:300]
        except Exception:
            pass
        return {'ok': False, 'text': '', 'model': cfg['MODEL'],
                'latency_ms': int((time.time() - t0) * 1000),
                'error': 'HTTP %s %s%s' % (e.code, e.reason, ('：' + detail) if detail else '')}
    except socket.timeout:
        return {'ok': False, 'text': '', 'model': cfg['MODEL'],
                'latency_ms': int((time.time() - t0) * 1000),
                'error': '请求超时（%ss）：模型服务无响应或负载过高' % (timeout or cfg['TIMEOUT'])}
    except urllib.error.URLError as e:
        return {'ok': False, 'text': '', 'model': cfg['MODEL'],
                'latency_ms': int((time.time() - t0) * 1000),
                'error': '无法连接模型服务 %s：%s' % (url, e.reason)}
    except Exception as e:  # 兜底：任何异常都降级成"模型不可用"
        logger.exception('llm.chat 异常 url=%s', url)
        return {'ok': False, 'text': '', 'model': cfg['MODEL'],
                'latency_ms': int((time.time() - t0) * 1000),
                'error': '%s: %s' % (type(e).__name__, e)}

    latency = int((time.time() - t0) * 1000)
    try:
        obj = json.loads(raw)
    except ValueError:
        return {'ok': False, 'text': '', 'model': cfg['MODEL'], 'latency_ms': latency,
                'error': 'HTTP %s 返回非 JSON（前 200 字符）：%s' % (status, raw[:200])}

    choices = obj.get('choices') or []
    text = ''
    reasoning = ''
    finish = ''
    if choices and isinstance(choices[0], dict):
        msg = choices[0].get('message') or {}
        text = (msg.get('content') or '').strip()
        # Qwen3 系思考模型把思维链放在 reasoning_content，正式回答才在 content。
        reasoning = (msg.get('reasoning_content') or '').strip()
        finish = choices[0].get('finish_reason') or ''
    if not text:
        # 有的实现把内容放在 obj['message'] / obj['content']，兜底再取一次
        text = str(obj.get('content') or (obj.get('message') or {}).get('content') or '').strip()
    if not text:
        model = obj.get('model') or cfg['MODEL']
        if reasoning:
            # 思考写出来了、正式回答一个字没有：绝大多数是输出上限被思考阶段耗尽。
            # 思考过程不当作答案返回（那是思维链不是结论），但必须把线索报出来，
            # 否则运维只能对着"模型返回空内容"猜。
            hint = '模型只返回了思考过程（reasoning_content %d 字），正式回答 content 为空' % len(reasoning)
            if finish == 'length':
                hint += ('；finish_reason=length，说明输出上限在思考阶段就用完了。'
                         '请把 OPS_LLM_CONFIG 的 MAX_TOKENS / BATCH_MAX_TOKENS / MERGE_MAX_TOKENS '
                         '保持 0（不发 max_tokens，当前默认），或改开 DISABLE_THINKING=true')
            return {'ok': False, 'text': '', 'model': model, 'latency_ms': latency,
                    'finish_reason': finish, 'error': hint,
                    'reasoning_chars': len(reasoning),
                    'reasoning_preview': reasoning[:300]}
        return {'ok': False, 'text': '', 'model': model, 'latency_ms': latency,
                'finish_reason': finish,
                'error': '模型返回空内容（HTTP %s%s；响应前 200 字符：%s）' % (
                    status, ('，finish_reason=%s' % finish) if finish else '',
                    raw[:200].replace('\n', ' '))}
    return {'ok': True, 'text': text, 'error': '',
            'model': obj.get('model') or cfg['MODEL'], 'latency_ms': latency,
            'finish_reason': finish, 'usage': obj.get('usage') or {},
            'reasoning_chars': len(reasoning)}


def ping(timeout=60):
    """连通性测试：发一句极短提示，验证地址/模型名/网络是否可用。

    不带 max_tokens（曾为 16）：思考型模型光是思维链就远超 16 token，
    必然回空 content，把"服务其实是通的"误报成"不可用"。
    超时也要放宽——35B 模型不带输出上限时首答可能就是十几秒。
    """
    if not enabled():
        return {'ok': False, 'error': disabled_reason() or '未启用', 'model': '', 'latency_ms': 0}
    r = chat([{'role': 'user', 'content': '连通性测试，请只回复两个字：正常'}],
             max_tokens=0, timeout=timeout)
    if not r.get('ok') and r.get('reasoning_chars'):
        # HTTP 200 + 有思维链 = 地址通、模型名对、服务在算。连通性这一问已经答完了，
        # 不能因为"正式回答为空"就说不可用，否则运维会去查一个根本没坏的网络。
        r['ok'] = True
        r['error'] = ('连通正常（服务已响应并输出 %d 字思考过程），但该模型未给出正式回答：%s'
                      % (r['reasoning_chars'], r.get('error') or ''))
    r['enabled'] = True
    r['base_url'] = config()['BASE_URL']
    return r


# ------------------------------------------------------------------ 证据打包

def _lines(seq, cap=None, fmt=None):
    """把列表转成文本行；fmt 为 None 时直接 str()。"""
    out = []
    for x in (seq or []):
        try:
            s = fmt(x) if fmt else str(x)
        except Exception:
            continue
        s = (s or '').strip()
        if s:
            out.append(s)
    if cap and len(out) > cap:
        n = len(out)
        out = out[:cap]
        out.append('（本项共 %d 条，因篇幅只保留前 %d 条）' % (n, cap))
    return out


def _norm_lines(lines):
    """规整成"可整行搬运"的证据行：去空、压掉换行、单行超长按 LINE_CAP 截尾。

    单行截尾而不是整段裁剪，是为了让分批装填时永远以"整行"为单位搬运——
    一条日志被从中间截断再喂给模型，比不给更容易造成误读。
    """
    out = []
    for l in (lines or []):
        l = ' '.join(str(l or '').split())
        if not l:
            continue
        if len(l) > LINE_CAP:
            l = l[:LINE_CAP] + '…'
        out.append(l)
    return out


def _os_event_line(e, host=''):
    """把一条操作系统事件渲染成单行证据，行首带元数据、行尾放正文。

    兼容两种真实存在的形态（不是防御式编程，两处采集路径的落库结构就是不同）：
      - 影响分析：oslogs.summarize()['highlights'] 里的装饰字典
        （ts_text/kind_label/level/log/source/id/message）；
      - 故障排查：analysis['signals']['os_events'] 里的 [ip, kind, ts, msg] 数组
        （tuple 存进 JSONField 后变成数组）。
    元数据（主机/时间/分类/级别/日志源/组件/事件ID/相关依据）一律排在正文之前：
    单行超长时是从行尾截断的（见 _norm_lines），这样即便被截，模型仍知道这条日志
    来自哪台机、哪个时刻、哪个组件——否则关联分析无从下手。缺失的字段直接省略，
    不写"未知"占位（占位既费预算又可能被模型当成一条真实信息）。
    """
    d = e
    if isinstance(e, (list, tuple)):
        seq = list(e) + [''] * 4
        d = {'kind': seq[1], 'ts': seq[2], 'message': seq[3]}
        host = str(seq[0] or '').strip() or host
    if not isinstance(d, dict):
        return ''

    ts = str(d.get('ts_text') or d.get('ts') or d.get('ts_raw') or '')[:19].replace('T', ' ')
    kind_raw = str(d.get('kind') or '')
    kind = str(d.get('kind_label') or (oslogs.label(kind_raw) if kind_raw else ''))
    msg = ' '.join(str(d.get('message') or '').split())
    if not (ts or kind or msg):
        return ''

    meta = []
    for label_txt, val in (('主机', str(host or d.get('ip') or '').strip()),
                           ('时间', ts), ('分类', kind),
                           ('级别', str(d.get('level') or '')),
                           ('日志源', str(d.get('log') or '')),
                           ('组件', str(d.get('source') or '')),
                           ('事件ID', str(d.get('id') or '') if d.get('id') else ''),
                           ('相关依据', str(d.get('matched') or ''))):
        if val:
            meta.append('%s=%s' % (label_txt, val))
    return '- %s%s%s' % (' '.join(meta), '｜' if msg else '', msg)


def _os_event_items(a):
    """把排查证据里的 OS 事件统一成 (重要度, 时间, 主机, dict) 列表并按重要度排序。

    优先取 analysis['servers'][i]['os_events']——那是 oslogs.select() 的装饰结果，
    带级别/日志源/组件/命中依据；老任务或降级数据里只有 signals.os_events 的
    四元组，也照样认。

    排序是为了让"预算/条数上限"咬住时先保住整机级异常（日志清除/OOM/崩溃/重启/
    内核错误），而不是被第一台机器的 cron/auth 噪声把名额占满——装填与截断都是
    保留靠前的行，不排序就等于随机丢证据。
    """
    items = []
    for s in (a.get('servers') or []):
        if not isinstance(s, dict):
            continue
        ip = str(s.get('ip') or '')
        for e in (s.get('os_events') or []):
            if isinstance(e, dict):
                items.append((ip, e))
    if not items:
        for t in ((a.get('signals') or {}).get('os_events') or []):
            if isinstance(t, (list, tuple)) and len(t) >= 4:
                items.append((str(t[0] or ''),
                              {'kind': t[1], 'ts': t[2], 'message': t[3]}))
    items.sort(key=lambda p: str(p[1].get('ts') or ''), reverse=True)
    items.sort(key=lambda p: oslogs.KIND_PRIORITY.get(str(p[1].get('kind') or ''), 50))
    return items


def _tl_line(e):
    if not isinstance(e, dict):
        return ''
    ts = str(e.get('ts') or '')[:19].replace('T', ' ')
    return '- %s %s｜%s｜%s' % (ts or '(无时刻)', e.get('source') or '',
                               e.get('event_type') or '', e.get('summary') or '')


def _sections_troubleshoot(a):
    """故障排查证据分段：(优先级, 标题, 行列表)。数字越小越重要，预算不够时先丢大的。"""
    a = a if isinstance(a, dict) else {}
    svc = a.get('service') or {}
    sig = a.get('signals') or {}
    secs = []

    base = ['- 应用统一名：%s' % (svc.get('canonical_name') or '(未登记)')]
    if svc.get('domains'):
        base.append('- 对外域名：%s' % '、'.join(str(x) for x in svc['domains'][:10]))
    if svc.get('server_ips'):
        base.append('- 部署服务器：%s' % '、'.join(str(x) for x in svc['server_ips'][:10]))
    if svc.get('port'):
        base.append('- 服务端口：%s' % svc['port'])
    if svc.get('supervisor_program'):
        base.append('- supervisor 程序名：%s' % svc['supervisor_program'])
    if svc.get('jenkins_job'):
        base.append('- Jenkins job：%s' % svc['jenkins_job'])
    if svc.get('app_log_path'):
        base.append('- 应用日志路径：%s' % svc['app_log_path'])
    base.append('- 排查窗口：近 %s 分钟' % (a.get('window_min') or '?'))
    hl = a.get('headline') or {}
    if hl:
        base.append('- 系统自动结论概览（%s）：%s' % (hl.get('level') or '', hl.get('text') or ''))
    secs.append((1, '服务基本信息与系统概览', base))

    errs = _lines(a.get('errors'), cap=20)
    blind = []
    if sig.get('any_unreachable'):
        blind.append('- 有部署机采集失败/不可达：%s' % '、'.join(str(x) for x in sig['any_unreachable'][:10]))
    if sig.get('port_unknown'):
        blind.append('- 端口状态未知（采集缺失，非"未监听"）：%s' % '、'.join(str(x) for x in sig['port_unknown'][:10]))
    if sig.get('app_log_missing'):
        blind.append('- 应用日志未读到：%s' % '、'.join(str(x) for x in sig['app_log_missing'][:10]))
    if sig.get('os_missing'):
        blind.append('- 操作系统日志未采到（采集受限，非"无异常"）：%s' % '、'.join(str(x) for x in sig['os_missing'][:10]))
    secs.append((2, '采集告警与盲区（重要：这些是"不知道"，不是"没问题"）', blind + errs))

    secs.append((3, '已确认事实（系统只读采集直接观测到）',
                 _lines(a.get('facts'), cap=40, fmt=_tl_line)))
    secs.append((4, '时间关联（仅时间接近，系统已声明非因果）',
                 _lines(a.get('correlations'), cap=15, fmt=_tl_line)))

    srv = []
    for s in (a.get('servers') or []):
        if not isinstance(s, dict):
            continue
        ip = str(s.get('ip') or '')
        srv.append('- 主机=%s(%s) 可达=%s 端口%s=%s supervisor=%s 运行时长=%s CPU=%s%% 内存=%s%% 监听端口=%s' % (
            ip, s.get('os_type') or '?', s.get('reachable'),
            svc.get('port') or '?', s.get('port_listening'),
            s.get('supervisor_status') or '(未知)',
            s.get('uptime_seconds'), s.get('cpu_percent'), s.get('mem_percent'),
            ','.join(str(p) for p in (s.get('listen_ports') or [])[:20]) or '(未采到)'))
        # 每条子行都重复"主机="：这些行会被按预算逐行裁剪，缩进层级一旦被裁掉，
        # 模型就无法把日志末行关联回具体机器。
        al = s.get('app_log') or {}
        if isinstance(al, dict) and (al.get('tail_lines') or al.get('tail')):
            tail = al.get('tail_lines') or al.get('tail') or []
            if isinstance(tail, str):
                tail = [tail]
            srv.append('    主机=%s｜组件=应用日志(%s)｜末行：%s' % (
                ip, al.get('path') or '?', ' ⏎ '.join(str(x) for x in tail[-3:])[:LINE_CAP]))
        lt = s.get('logtail') or {}
        if isinstance(lt, dict) and lt.get('lines'):
            srv.append('    主机=%s｜组件=supervisor logtail(%s)｜末行：%s' % (
                ip, svc.get('supervisor_program') or '?',
                ' ⏎ '.join(str(x) for x in lt['lines'][-3:])[:LINE_CAP]))
        ol = s.get('os_logs') or {}
        if isinstance(ol, dict) and ol.get('notes'):
            srv.append('    主机=%s｜OS 日志概况：%s' % (
                ip, ' '.join(str(x) for x in ol['notes'][:8])))
    secs.append((5, '各部署机状态', srv))

    os_ev = [_os_event_line(d, host=ip) for ip, d in _os_event_items(a)]
    os_dropped = 0
    for s in (a.get('servers') or []):
        if isinstance(s, dict):
            try:
                os_dropped += int(s.get('os_events_dropped') or 0)
            except (TypeError, ValueError):
                pass
    if os_dropped:
        os_ev.append('- 另有 %d 条与本服务相关的 OS 事件未逐条展开（系统按重要度取了前若干条，'
                     '不代表其余事件无异常；全部种类见下一段聚合视图）' % os_dropped)
    secs.append((6, '近一日操作系统事件逐条明细（与本服务最相关的前若干条）',
                 _lines(os_ev, cap=80)))

    # 全量告警的聚合视图：采集侧已改为"近一日全部 Warning 及以上"，一天几百上千条，
    # 逐条送不进模型也不该送；但"条数上限"绝不能变成"信息丢失"，
    # 所以这里用 os_logs.groups 把全部错误种类（含次数与首末时间）补齐。
    os_g = []
    for s in (a.get('servers') or []):
        if not isinstance(s, dict):
            continue
        ip = str(s.get('ip') or '')
        ol = s.get('os_logs') or {}
        if not isinstance(ol, dict):
            continue
        if ol.get('level_filter'):
            os_g.append('- 主机=%s｜采集范围：%s' % (ip, ol['level_filter']))
        for g in (ol.get('groups') or []):
            os_g.append(_group_line(g, host=ip))
        if _num(ol.get('groups_dropped')):
            os_g.append('- 主机=%s｜另有 %d 类错误未列出（不代表无异常）'
                        % (ip, _num(ol.get('groups_dropped'))))
        for er in (ol.get('errors') or [])[:5]:
            os_g.append('- 主机=%s｜采集受限（盲区，非"无异常"）：%s' % (ip, er))
    secs.append((7, '近一日操作系统全部警告/错误（按错误类型聚合，次数为窗口内总次数）',
                 _lines(os_g, cap=120)))

    ngx = []
    nl = a.get('nginx_logs') or {}
    nhost = str(a.get('nginx_host') or '') or '未登记反代机'
    if isinstance(nl, dict):
        for k in ('access_logs', 'error_logs'):
            for e in (nl.get(k) or []):
                if not isinstance(e, dict):
                    continue
                if k == 'access_logs':
                    ngx.append('- 主机=%s｜access %s：窗口内 %s 条(正常 %s)，状态码 %s，最近正常访问 %s%s' % (
                        nhost, e.get('path'), e.get('total_in_window'), e.get('ok_in_window') or 0,
                        e.get('status_counts'), e.get('last_ok_ts') or '(尾部未见)',
                        ('｜异常：%s' % e['error']) if e.get('error') else ''))
                else:
                    ngx.append('- 主机=%s｜error %s：本服务归属 %s 行(全局 %s 行)，签名 %s，跨度 %s ~ %s%s' % (
                        nhost, e.get('path'), e.get('total_in_window'), e.get('total_all_services') or '?',
                        e.get('signatures') or '(无)', e.get('first_ts') or '-', e.get('last_ts') or '-',
                        ('｜异常：%s' % e['error']) if e.get('error') else ''))
    secs.append((8, 'Nginx 日志窗口统计（反代机上读取）', ngx))

    secs.append((9, '系统给出的推测（措辞已限定为推测）',
                 _lines(a.get('inferences'), cap=15, fmt=_tl_line)))
    secs.append((10, '系统给出的建议（均为只读排查动作）',
                 _lines(a.get('suggestions'), cap=15, fmt=_tl_line)))

    dns = []
    for d in (a.get('dns') or []):
        if not isinstance(d, dict):
            continue
        srvs = '、'.join('[%s→%s]' % (s.get('server'), ','.join(s.get('addresses') or []) or s.get('error'))
                         for s in (d.get('servers') or []) if isinstance(s, dict))
        dns.append('- %s：%s｜ping %s' % (d.get('domain'), srvs, (d.get('ping') or {}).get('ip') or '不通'))
    jk = a.get('jenkins') or {}
    lb = (jk.get('last_build') if isinstance(jk, dict) else None) or {}
    if lb:
        dns.append('- Jenkins 最近构建：%s 结果=%s 时间=%s' % (
            lb.get('number') or lb.get('id') or '?', lb.get('result') or '?', lb.get('timestamp') or '?'))
    secs.append((11, 'DNS 解析与 Jenkins 构建', dns))

    flags = []
    for k in ('nginx_5xx', 'nginx_upstream_errors', 'supervisor_bad', 'recent_reboot',
              'dns_fail', 'dns_mismatch', 'app_log_recent', 'port_missing', 'port_ok'):
        v = sig.get(k)
        if v:
            flags.append('- %s = %s' % (k, json.dumps(v, ensure_ascii=False)[:LINE_CAP]))
    secs.append((12, '系统提取的信号量（原始标记）', flags))
    return secs


def _risk_line(r):
    if not isinstance(r, dict):
        return ''
    return '- [%s] %s' % (r.get('level') or '?', r.get('text') or '')


def _svc_line(s):
    if not isinstance(s, dict):
        return ''
    return '- %s（端口 %s，状态 %s，域名 %s）' % (
        s.get('name') or '?', s.get('port') or '?', s.get('status') or '?',
        '、'.join(str(x) for x in (s.get('domains') or [])) or '无')


def _num(v, default=0):
    try:
        return int(v)
    except (TypeError, ValueError):
        return default


def _svc_name_chunks(svcs, limit=None, mark_related=False, width=340):
    """把服务名单折成若干段，每段不超过 width 字符。

    必须折行：_norm_lines 会把单行按 LINE_CAP 截尾，几百个服务名挤成一行
    就等于只送出前几十个——那正是"U8 服务采集不到"这个 bug 的另一种形态。
    逐行展开又太浪费（模型要的是名单，不是每个服务一段描述），折行是两者的平衡。
    """
    names = []
    for s in (svcs or []):
        if not isinstance(s, dict):
            continue
        nm = str(s.get('name') or s.get('display_name') or '').strip()
        if not nm:
            continue
        if mark_related and s.get('related'):
            nm = '%s★' % nm
        names.append(nm)
    omitted = 0
    if limit is not None and len(names) > limit:
        omitted = len(names) - limit
        names = names[:limit]
    chunks, cur = [], ''
    for nm in names:
        piece = ('、' + nm) if cur else nm
        if cur and len(cur) + len(piece) > width:
            chunks.append(cur)
            cur = nm
        else:
            cur += piece
    if cur:
        chunks.append(cur)
    return chunks, omitted


def _svc_inventory_lines(title, svcs, total, dropped, **kw):
    """一种服务状态 → 首行(带总数) + 若干续行 + 截断声明。"""
    chunks, omitted = _svc_name_chunks(svcs, **kw)
    out = ['- %s %d 个（名单 %d 行%s）：%s' % (
        title, total, len(chunks) or 1,
        '，★=与本机已登记应用相关' if kw.get('mark_related') and
        any(isinstance(s, dict) and s.get('related') for s in (svcs or [])) else '',
        chunks[0] if chunks else '(无)')]
    out += ['- %s（续）：%s' % (title, c) for c in chunks[1:]]
    if omitted:
        out.append('- %s：另有 %d 个未列出（名单过长，不代表不存在）' % (title, omitted))
    if dropped:
        out.append('- %s：采集端/展示端截断，另有 %d 个未列出（不代表不存在）' % (title, dropped))
    return out


def _group_line(g, host=''):
    """聚合后的一类 OS 事件 → 一行。次数与首末时间必须带上：
    "同一条错误刷了 500 次"和"只出现过 1 次"是完全不同的严重度信号。
    正文取 sample（首条原文）而不是 signature：提示词要求模型引用"原文摘录"，
    把数字抹成 # 的签名没法当原文用。
    每行都重复"主机="：这些行会被按预算逐行裁剪，主机只写在段尾就等于没写。"""
    if not isinstance(g, dict):
        return ''
    ts1 = str(g.get('first_ts') or '')[:19].replace('T', ' ')
    ts2 = str(g.get('last_ts') or '')[:19].replace('T', ' ')
    span = ts2 if ts1 == ts2 else '%s ~ %s' % (ts1 or '-', ts2 or '-')
    head = '%s｜%s｜日志源=%s｜事件ID=%s｜次数=%s｜时间=%s' % (
        g.get('level') or '?', oslogs.label(str(g.get('kind') or '')),
        g.get('source') or '?', g.get('id') or '?', g.get('count') or '?', span)
    if host:
        head = '主机=%s %s' % (host, head)
    raw = ' '.join(str(g.get('sample') or g.get('signature') or '').split())
    return '- %s%s%s' % (head, '｜原文：' if raw else '', raw[:LINE_CAP])


def _sections_impact(a):
    a = a if isinstance(a, dict) else {}
    b = a.get('basic') or {}
    ti = a.get('technical_impact') or {}
    bi = a.get('business_impact') or {}
    ol = a.get('os_logs') or {}
    secs = []

    secs.append((1, '目标与模拟操作', [
        '- 目标 IP：%s' % (a.get('target_ip') or '?'),
        '- 模拟操作：%s（仅分析，系统未执行任何动作）' % (a.get('op_label') or a.get('op_type') or '?'),
        '- 主机名：%s｜操作系统：%s' % (b.get('hostname') or '?', b.get('os') or '?'),
        '- 运行时长：%s 秒｜开机时间：%s' % (b.get('uptime_seconds'), b.get('boot_time') or '?'),
        '- CPU %s%%｜内存 %s%%（总 %s MB）' % (b.get('cpu_percent'), b.get('mem_percent'),
                                             b.get('mem_total_mb')),
    ]))

    conns = ti.get('active_connections') or {}
    sess = ti.get('active_sessions') or {}
    run_svcs = ti.get('running_services') or []
    stop_svcs = ti.get('stopped_services') or []
    # 有 *_total 就必须用 total，只有老快照才退回列表长度。
    # 以前这里直接 len(给出的清单)，而清单是被截断过的——"运行 60 个服务"这个
    # 被截断的数字因此被当成了机器上的事实，字母序靠后的 U8/UFIDA 系服务凭空消失。
    run_total = _num(ti.get('running_services_total'), len(run_svcs))
    run_dropped = _num(ti.get('running_services_dropped'), 0)
    stop_total = _num(ti.get('stopped_services_total'), len(stop_svcs))
    stop_dropped = _num(ti.get('stopped_services_dropped'), 0)
    truncated = run_dropped or stop_dropped
    secs.append((2, '当前连接与会话', [
        '- 监听端口 %d 个：%s' % (len(ti.get('listen_ports') or []),
                                 ','.join(str(p) for p in (ti.get('listen_ports') or [])[:40])),
        '- 服务：运行中 %d 个，非运行（停止/暂停等）%d 个；下面第 6 段给出完整名单%s' % (
            run_total, stop_total,
            '（名单有截断，未列出的不代表不存在）' if truncated else '（无截断）'),
        '- 检测到应用进程 %d 个；本机进程总数 %s%s' % (
            len(ti.get('related_apps') or []),
            _num(ti.get('processes_total')) or '(采集端未回报)',
            '（采集端按上限截断，非全量）' if ti.get('processes_truncated') else ''),
        '- TCP 总计 %s，其中 ESTABLISHED %s%s，状态分布 %s' % (
            conns.get('total_tcp'), conns.get('established_count'),
            '（明细样本已截断，计数为全量）' if conns.get('established_sample_truncated') else '',
            json.dumps(conns.get('by_state') or {}, ensure_ascii=False)[:200]),
        '- 活动连接来源 IP TOP：%s' % ('、'.join(
            '%s(%s)' % (r.get('ip'), r.get('count'))
            for r in (conns.get('remote_ip_top') or [])[:15]) or '(无)'),
        '- 活跃会话 %s 个（RDP %s）；当前登录用户：%s' % (
            sess.get('session_count'), sess.get('rdp_active'),
            '、'.join(str(x) for x in (sess.get('logged_on') or [])[:10]) or '(无)'),
    ]))

    secs.append((3, '直接影响（系统按采集数据列出）',
                 _lines(ti.get('direct'), cap=20, fmt=lambda x: '- %s' % x)))
    secs.append((4, '间接影响（承载的对外应用/域名）',
                 _lines(ti.get('indirect'), cap=20, fmt=lambda x: '- %s' % x)))
    secs.append((5, '风险提示', _lines(a.get('risks'), cap=25, fmt=_risk_line)))

    # 服务全名单：这是"重启/关机会影响什么"的直接依据，以前只给了个数字，
    # 模型根本无从判断 U8 之类未在平台登记的业务服务在不在机上。
    inv = _svc_inventory_lines('运行中服务', run_svcs, run_total, run_dropped,
                               mark_related=True)
    auto_stopped = [s for s in stop_svcs if isinstance(s, dict)
                    and str(s.get('start_mode') or '').lower().startswith('auto')]
    inv += _svc_inventory_lines('非运行状态服务（停止/暂停）', stop_svcs, stop_total,
                                stop_dropped, limit=150)
    if auto_stopped:
        inv += _svc_inventory_lines('其中"设为自动启动却处于停止"的服务'
                                    '（这类往往就是故障本身）',
                                    auto_stopped, len(auto_stopped), 0, limit=80)
    secs.append((6, '本机服务清单（只读采集）', inv))

    disk = ['- %s 使用率 %s%%（剩余 %s / %s GB）' % (
        d.get('device'), d.get('percent'), d.get('free_gb'), d.get('size_gb'))
        for d in (b.get('disks') or []) if isinstance(d, dict)]
    secs.append((7, '磁盘使用', disk))

    osl = []
    if ol.get('level_filter'):
        osl.append('- 采集范围：%s' % ol['level_filter'])
    if ol.get('logs_scanned'):
        osl.append('- 已扫描日志：%s' % '、'.join(str(x) for x in ol['logs_scanned'][:6]))
    if ol.get('notes'):
        osl += ['- %s' % x for x in ol['notes'][:10]]
    if ol.get('count_labels'):
        osl.append('- 分类计数：%s' % '、'.join(
            '%s=%s' % (c.get('label'), c.get('count')) for c in ol['count_labels'][:12]))
    if _num(ol.get('dropped')):
        osl.append('- 与本服务相关性筛选丢弃 %s 条（全量计数见上，明细未逐条展开）'
                   % ol.get('dropped'))
    if ol.get('errors'):
        osl.append('- 采集受限（盲区，不等于"无异常"）：%s' % '；'.join(str(x) for x in ol['errors'][:5]))
    if not ol.get('available'):
        osl.append('- 未采集到操作系统事件日志（%s；不能据此判断该机无异常）'
                   % ('采集受限，见上' if ol.get('errors')
                      else '可能是采集范围/级别内确实没有事件，也可能是采集受限，两者无法区分'))
    secs.append((8, '近一日操作系统事件概况', osl))

    ip0 = str(a.get('target_ip') or '')
    groups = [g for g in (ol.get('groups') or []) if isinstance(g, dict)]
    if groups:
        # 用聚合视图而不是 highlights：全量按级别采集后事件可能上千条，
        # 逐条列 25 行既漏又不 representative；一行 = 一种错误 + 次数 + 首末时间，
        # 同样的字符预算能覆盖全部种类，且保住了"刷 500 次 vs 只出 1 次"的严重度差异。
        det = _lines(groups, cap=60, fmt=lambda x: _group_line(x, host=ip0))
        gdropped = _num(ol.get('groups_dropped'))
        if gdropped:
            det.append('- 主机=%s｜另有 %d 类错误未列出（按严重度与次数取前 %d 类，'
                       '不代表其余无异常）' % (ip0 or '?', gdropped, len(groups)))
        det.append('- 主机=%s｜聚合口径说明：以上按"日志源+事件ID+错误签名"聚合，每行是一类错误，'
                   '"次数"为该类在采集窗口内出现的总次数，"原文"取该类首条；'
                   '同类其余各条未逐条送出，但不代表无异常。采集范围见上一段。' % (ip0 or '?'))
    else:
        det = _lines(ol.get('highlights'), cap=25,
                     fmt=lambda x: _os_event_line(x, host=ip0))
    secs.append((9, '近一日操作系统事件明细（按错误类型聚合，含级别/日志源/组件/次数）', det))

    secs.append((10, '业务用户影响可评估性', [
        '- 可评估：%s' % ('是' if bi.get('assessable') else '否'),
        '- 系统声明：%s' % (bi.get('note') or ''),
        '- 受影响对外域名：%s' % ('、'.join(str(x) for x in (bi.get('affected_domains') or [])[:15]) or '(未登记)'),
    ]))
    secs.append((11, '本机承载的已登记应用',
                 _lines(ti.get('related_services'), cap=15, fmt=_svc_line)))
    return secs


def _sections(scope, analysis):
    secs = (_sections_impact(analysis) if scope == 'impact'
            else _sections_troubleshoot(analysis))
    return sorted([s for s in secs if s], key=lambda s: s[0])


def plan_batches(scope, analysis, budget=None, max_batches=None):
    """把证据按优先级装进若干个"不超过单次预算"的批次，供分批问模型。

    为什么分批而不是一次性截断：模型上下文有限，一次塞不下时旧做法是"丢段落"，
    被丢的那段可能正好是关键证据。改成按段落优先级整行搬运到下一批，
    直到批数用尽（MAX_BATCHES）；用尽后仍未送出的段落标题记进 overflow，
    并如实写进提示词与页面——绝不把"没给到"说成"没有"。

    返回 {'batches': [{'index','text','chars','sections','prompt_chars'}],
          'overflow': [标题...], 'batch_count', 'total_chars', 'budget', 'max_batches'}
    """
    cfg = config()
    budget = max(MIN_ROOM + 64, int(budget or cfg['MAX_CHARS']))
    max_batches = max(1, int(max_batches or cfg['MAX_BATCHES']))

    batches, overflow = [], []
    created = 1                       # 已经开出来的批次数（含正在装的 cur）
    cur = {'parts': [], 'sections': [], 'chars': 0}

    def _add(batch, title, lines):
        body = '\n'.join(lines)
        block = '## %s\n%s\n' % (title, body)
        batch['parts'].append(block)
        batch['sections'].append({'title': title, 'chars': len(body), 'lines': len(lines)})
        # +2 是 '\n'.join 的分隔符开销，预留掉才能保证成品不超预算
        batch['chars'] += len(block) + (2 if len(batch['parts']) > 1 else 0)

    for _pri, title, raw in _sections(scope, analysis):
        lines = _norm_lines(raw)
        if not lines:
            continue
        cont = False
        while lines:
            head = ('%s（续）' % title) if cont else title
            room = budget - cur['chars'] - len('## %s\n\n' % head) - (2 if cur['parts'] else 0)
            if room < MIN_ROOM:
                # 连空批次都放不下这段标题：只能如实记为"未送出"，不能无限开新批
                if created >= max_batches or not cur['parts']:
                    overflow.append(head)
                    break
                batches.append(cur)
                cur = {'parts': [], 'sections': [], 'chars': 0}
                created += 1
                continue
            take, used = [], 0
            for l in lines:
                if used + len(l) + 1 > room:
                    break
                take.append(l)
                used += len(l) + 1
            if not take:
                # 本批剩余空间装不下这一行：空批次装得下就另起一批——就地截断会把
                # 证据正文砍掉（只剩主机/时间），那正是最不该丢的部分
                if (cur['parts'] and created < max_batches
                        and len(lines[0]) + 1 <= budget - len('## %s\n\n' % head)):
                    batches.append(cur)
                    cur = {'parts': [], 'sections': [], 'chars': 0}
                    created += 1
                    continue
                take = [lines[0][:max(80, room)] + '…（本行过长已截断）']
            _add(cur, head, take)
            lines = lines[len(take):]
            cont = bool(lines)

    if cur['parts']:
        batches.append(cur)

    out = []
    total = 0
    for i, b in enumerate(batches, 1):
        text = redact('\n'.join(b['parts'])).strip()
        out.append({'index': i, 'text': text, 'chars': len(text),
                    'sections': b['sections'], 'prompt_chars': 0})
        total += len(text)
    return {'batches': out, 'overflow': overflow, 'batch_count': len(out),
            'total_chars': total, 'budget': budget, 'max_batches': max_batches}


def build_evidence(scope, analysis, budget=None):
    """单批模式的证据打包（保留给只想看"这次会送什么给模型"的调用方/测试用）。

    等价于 plan_batches(max_batches=1) 的第一批；送不下的段落进 dropped。
    """
    plan = plan_batches(scope, analysis, budget=budget, max_batches=1)
    b = plan['batches'][0] if plan['batches'] else {
        'text': '', 'chars': 0, 'sections': []}
    return {'text': b['text'], 'chars': b['chars'], 'used': b['sections'],
            'dropped': plan['overflow'], 'budget': plan['budget']}


# ------------------------------------------------------------------ 提示词

_COMMON_RULES = """硬性要求（务必逐条遵守）：
1. 只能依据"证据材料"里出现的内容作答，禁止编造任何未在材料中出现的主机、端口、进程、日志行、时间点。
2. 每一条结论都必须以【已确认事实】、【推测】、【待验证】三者之一开头：
   【已确认事实】= 材料中由系统只读采集直接观测到、且你能指出对应证据行的内容；
   【推测】= 你基于证据做出的原因/因果判断，一律属于推测，不是结论；
   【待验证】= 需要人工核对或补充采集后才能定性的内容。
3. "可能的故障原因""高风险点"两节只允许出现【推测】或【待验证】，严禁把推测写成确定的故障根因；
   证据不足时必须直说"现有证据不足以定位根因"，并说明还缺哪一类证据。
4. 材料未提供、或标注为"采集受限/盲区/未知/未采到/未展开/被省略"的部分，必须明确说"该处证据不足，无法判断"，
   绝不允许推断为"正常"或"无异常"。
5. 严格区分"时间上先后/同时"与"因果"：不得仅因两件事时间接近就断言因果关系，需用"可能""推测""需确认"等措辞。
6. 材料中已有的分类（已确认事实/时间关联/推测/建议）是系统按只读采集给出的，你不得把"时间关联"或"推测"升级为"事实"。
7. 引用日志证据时必须带上材料里给出的主机、时间戳、日志源/组件，写成
   "主机 X｜时间 T｜日志源/组件 Y｜原文摘录"，便于人工回查；不得改写、翻译或臆造原文。
8. 你没有任何执行权限，输出的排查动作只能是只读命令或人工核对步骤；不得建议直接重启、停服务、改配置、部署、清理或清除日志。
   若确实需要此类操作，只能写成"需人工评估并授权后执行"，并说明前置确认项与风险。
9. 材料中不得出现也不得追问任何账号密码、密钥、令牌；如发现疑似凭据请只说"存在敏感信息，已脱敏"。
10. 操作系统事件明细是"按错误类型聚合"的：一行代表一类错误，其中"次数=N"是该类错误在采集窗口内出现的总次数，
    "时间=A ~ B"是该类错误首次与最后一次出现的时刻。判断严重度时必须把 N 计入（刷几百次的告警与只出现一次的不是一回事），
    但不得因为看到的是聚合行就断言"只发生了一次"。
11. 用中文作答，严格按要求的 Markdown 小标题顺序分段，标题一字不改；某节确实无内容时写"（本项无）"，不得省略标题。
    总长度控制在 1000 字以内，不要输出与运维无关的寒暄。"""

_TROUBLESHOOT_HEADINGS = """### 一、异常现象
### 二、关键日志证据
### 三、可能的故障原因（按可能性排序）
### 四、原因判断依据
### 五、建议的排查步骤（只读）
### 六、尚未确认的问题
### 七、建议补充采集的数据"""

_IMPACT_HEADINGS = """### 一、影响现象概述（技术影响 / 业务影响分开写）
### 二、关键证据
### 三、高风险点（按严重度排序）
### 四、风险判断依据
### 五、执行前的只读核对步骤
### 六、尚未确认的问题
### 七、建议补充采集的数据"""

_TROUBLESHOOT_TASK = """你是一名企业信息化运维工程师。下面是"服务故障辅助排查"系统只读采集并结构化后的证据材料
（含各部署机状态、应用日志末行、supervisor logtail、近一日操作系统事件、Nginx 窗口统计、DNS 与 Jenkins 构建）。
系统全程只读，未对任何服务器做过变更。

请严格按以下 7 个小标题顺序输出：
%s

各节写法要求：
- 一、异常现象：只写材料能支撑的现象，每条注明出现在哪台主机、哪个时间点，并标【已确认事实】。
- 二、关键日志证据：逐条摘录最关键的原始日志或统计，格式"主机 X｜时间 T｜日志源/组件 Y｜原文"，最多 8 条，标【已确认事实】。
- 三、可能的故障原因：每条以【推测】开头，按可能性从高到低排序；若证据不足，第一条就写"【推测】现有证据不足以定位根因"。
- 四、原因判断依据：与第三节逐条对应，说明依据哪些证据（引用主机+时间）、为什么这样推、还缺什么才能证实或排除。
- 五、建议的排查步骤（只读）：可直接执行的只读命令或人工核对项，写明在哪台主机执行、期望看到什么、看到什么说明什么。
- 六、尚未确认的问题：每条以【待验证】开头，写清"待确认什么"和"由谁/用什么方式确认"。
- 七、建议补充采集的数据：说明还该采什么（哪台机、哪类日志、多长窗口、需要什么权限），以及采到后能验证第三节的哪条推测。

""" % _TROUBLESHOOT_HEADINGS

_IMPACT_TASK = """你是一名企业信息化运维工程师。下面是"服务器操作影响分析"系统只读采集后的证据材料，
用于评估【模拟操作】的影响。系统并未执行该操作，全程只读。
材料含本机服务全名单（运行中 / 非运行）、连接与会话、磁盘、以及近一日操作系统全部警告与错误事件（按错误类型聚合）。

请严格按以下 7 个小标题顺序输出：
%s

各节写法要求：
- 一、影响现象概述：技术影响（连接/会话/服务清单/进程/端口/磁盘）与业务影响（对外域名、承载应用、可评估性）分开写，标【已确认事实】。
  服务清单里凡属业务应用（如 U8/UFIDA/OA/ERP/数据库等），必须逐个点名，不得只写"运行中服务 N 个"。
- 二、关键证据：逐条摘录支撑上面结论的原始数据，格式"主机 X｜时间 T｜来源 Y｜数值/原文"，最多 8 条。
- 三、高风险点：每条以【推测】开头，按严重度从高到低排序，不得写成确定结论。
  必须逐条覆盖服务名单中识别出的业务应用（如 U8/UFIDA/OA/ERP/数据库/中间件），说明该操作会让它们中断到什么程度；
  名单里"设为自动启动却处于停止"的服务要单独点出，这类往往已经是既有故障。
- 四、风险判断依据：与第三节逐条对应，说明依据哪些采集数据、为什么这样推、还缺什么才能确认。
- 五、执行前的只读核对步骤：只读命令或人工核对项（写明主机与期望结果）；任何变更类动作只能写"需人工评估并授权后执行"。
- 六、尚未确认的问题：每条以【待验证】开头。
- 七、建议补充采集的数据：说明还该采什么、采到后能确认哪条风险。

""" % _IMPACT_HEADINGS

_BATCH_NOTE = """注意：因证据总量超过单次请求容量，系统把证据按重要度分成了 %d 批，本材料是第 %d 批，
只包含上面列出的这些段落。其它批次的证据你完全看不到，因此：
- 只依据本批材料作答，绝不猜测未给出的批次里有什么；
- 本批材料未覆盖的维度，一律写"本批未提供，无法判断"，并放进"尚未确认的问题"或"建议补充采集的数据"；
- 不要因为本批只看到局部就下全局结论（例如本批没有错误日志，不等于"服务无异常"）；
- 本批只写与本批材料直接相关的内容，篇幅控制在 600 字以内（之后会另有一次调用把各批合并成最终意见）；
  不要为了凑满 7 个小标题而编造内容，本批确实没有的就写"（本项无）"。"""

_MERGE_TASK = """你是一名企业信息化运维工程师。因证据量超过单次请求容量，系统已把证据分成 %d 批分别请你分析过，
下面是各批的分析结果。请把它们合并成一份最终意见，严格按以下 7 个小标题顺序输出：
%s

合并规则（务必遵守）：
1. 只做归并、去重、排序，不得新增任何各批结果里没有出现过的主机、时间点、日志或结论。
2. 保留每条结论原有的【已确认事实】/【推测】/【待验证】标签；严禁在合并时把【推测】或【待验证】升级为【已确认事实】。
3. 各批结论互相矛盾时，两条都保留，标【待验证】并写明"第 X 批与第 Y 批结论不一致，需人工核对"，不得自行取舍。
4. 各批写到的"本批未提供/无法判断"必须汇总进"尚未确认的问题"或"建议补充采集的数据"，不得因为合并而丢失。
5. 同一原因被多批提到时合并为一条，并按可能性重新排序；引用证据时保留主机、时间戳、日志源/组件。
6. 若所有批次都表示证据不足，最终结论第一条必须写"【推测】现有证据不足以定位根因"。

"""

# 提示词版本号：落库时一起存，便于日后对比"换了提示词后模型结论有无变化"
# v3：影响分析证据加入服务全名单（运行中/非运行 + 截断如实披露）、
#     OS 事件改为按错误类型聚合（次数/首末时间），并新增聚合口径说明规则。
PROMPT_VERSION = 'v3-svc-inventory-oslog-groups'


def _task_prompt(scope):
    return _IMPACT_TASK if scope == 'impact' else _TROUBLESHOOT_TASK


def _headings(scope):
    return _IMPACT_HEADINGS if scope == 'impact' else _TROUBLESHOOT_HEADINGS


def _scope_headline(scope, analysis):
    a = analysis if isinstance(analysis, dict) else {}
    if scope == 'impact':
        return '目标：%s｜模拟操作：%s（未执行）' % (
            a.get('target_ip') or '?', a.get('op_label') or a.get('op_type') or '?')
    svc = a.get('service') or {}
    return '应用：%s｜域名：%s｜部署机：%s｜排查窗口：近 %s 分钟' % (
        svc.get('canonical_name') or '?',
        '、'.join(str(x) for x in (svc.get('domains') or [])) or '无',
        '、'.join(str(x) for x in (svc.get('server_ips') or [])) or '无',
        a.get('window_min') or '?')


def build_messages(scope, analysis, evidence, batch=None, batch_total=0):
    """组装单批（或不分批）分析的 system + user 两条消息。

    规则与输出格式放在 user 消息最前面、证据放最后：证据可能被裁，
    但"怎么答、不许怎么答"绝不能被裁掉。
    evidence 形如 {'text':..., 'dropped':[标题...]}；batch/batch_total 用于分批场景。
    """
    dropped = (evidence or {}).get('dropped') or []
    head = ['# 证据材料（系统只读采集，未做任何变更）',
            _scope_headline(scope, analysis)]
    if batch and batch_total > 1:
        head.append(_BATCH_NOTE % (batch_total, batch))
    head.append('采集时间：%s' % now_text())
    if dropped:
        head.append('注意：以下段落因超出本次分析容量被整体省略，其内容你完全不知道，'
                    '不得据此认为"没有异常"——%s。' % '、'.join(dropped))

    user = '%s\n\n%s\n\n%s\n## 证据正文\n%s' % (
        _task_prompt(scope).strip(), _COMMON_RULES, '\n'.join(head),
        (evidence or {}).get('text') or '(无可用证据)')
    return [
        {'role': 'system', 'content': '你是内网运维平台的辅助分析模型，只输出分析意见供人工核实，'
                                      '不具备任何执行权限，也不得输出可被自动执行的操作指令。'},
        {'role': 'user', 'content': user},
    ]


def build_merge_messages(scope, analysis, batch_results, overflow=None):
    """组装"汇总各批结果"的消息。只把各批的模型输出送回去，不再重发原始证据
    （否则等于没分批）；汇总稿必须沿用同一套 7 段结构与标签红线。"""
    parts = [(_MERGE_TASK % (len(batch_results), _headings(scope))).strip(),
             _COMMON_RULES,
             '# 背景',
             _scope_headline(scope, analysis),
             '汇总时间：%s' % now_text()]
    if overflow:
        parts.append('注意：以下证据段落始终未能送入任何一批，你与前面各批都不知道其内容，'
                     '必须在"尚未确认的问题"中列出——%s。' % '、'.join(overflow))
    for b in (batch_results or []):
        parts.append('\n## 第 %s 批分析结果（覆盖段落：%s）%s\n%s' % (
            b.get('index'), '、'.join(b.get('section_titles') or []) or '未知',
            '［该批调用失败，无结果］' if b.get('error') else '',
            b.get('text') or '(无输出)'))
    return [
        {'role': 'system', 'content': '你是内网运维平台的辅助分析模型，只输出分析意见供人工核实，'
                                      '不具备任何执行权限，也不得输出可被自动执行的操作指令。'},
        {'role': 'user', 'content': '\n'.join(parts)},
    ]


def now_text():
    try:
        return timezone.localtime(timezone.now()).strftime('%Y-%m-%d %H:%M:%S')
    except Exception:
        return timezone.now().strftime('%Y-%m-%d %H:%M:%S')


# ------------------------------------------------------------------ 对外入口

def analyze(scope, analysis, requested_by=''):
    """跑一次模型辅助分析，证据超过单次预算时自动分批作答 + 汇总。

    返回 JSON 安全的大字典：最终意见 text、各批明细 batches、证据全文 evidence_text。
    调用方（Celery 任务）负责把它落 LlmAnalysisRecord，再把 slim_for_storage() 的
    精简结果写进 analysis['llm']——原始 snapshot/analysis 的采集数据一律不动。
    """
    scope = scope if scope in SCOPES else 'troubleshoot'
    base = {
        'status': 'failed', 'scope': scope, 'text': '', 'error': '',
        'model': '', 'temperature': None, 'latency_ms': 0,
        'prompt_chars': 0, 'evidence_chars': 0, 'evidence_sections': [],
        'evidence_dropped': [], 'evidence_text': '', 'batches': [], 'merge': {},
        'batch_count': 0, 'prompt_version': PROMPT_VERSION,
        'requested_by': requested_by or '',
        'requested_at': now_text(), 'finished_at': '', 'base_url': '',
        'record_id': None,
    }
    if not enabled():
        base['status'] = 'disabled'
        base['error'] = disabled_reason() or '未启用大模型辅助分析'
        base['finished_at'] = now_text()
        return base

    cfg = config()
    base['model'] = cfg['MODEL']
    base['temperature'] = cfg['TEMPERATURE']
    base['base_url'] = cfg['BASE_URL']

    # 分析结果为空时不要拿"骨架占位符"去问模型——那样只会得到一堆凭空猜测
    if not isinstance(analysis, dict) or not analysis:
        base['error'] = '没有可用的采集证据（分析结果为空），无法请模型辅助判断'
        base['finished_at'] = now_text()
        return base

    plan = plan_batches(scope, analysis)
    base['evidence_chars'] = plan['total_chars']
    base['evidence_dropped'] = plan['overflow']
    base['batch_count'] = plan['batch_count']
    base['evidence_sections'] = ['%s（第%d批，%d字）' % (s['title'], b['index'], s['chars'])
                                 for b in plan['batches'] for s in b['sections']]
    base['evidence_text'] = '\n\n'.join(
        '===== 第 %d/%d 批证据 =====\n%s' % (b['index'], plan['batch_count'], b['text'])
        for b in plan['batches'])

    if not plan['batches'] or not plan['batches'][0]['text']:
        base['error'] = '没有可用的采集证据（分析结果为空），无法请模型辅助判断'
        base['finished_at'] = now_text()
        return base

    single = plan['batch_count'] == 1
    failures = []
    for b in plan['batches']:
        msgs = build_messages(scope, analysis,
                              {'text': b['text'], 'dropped': plan['overflow']},
                              batch=b['index'], batch_total=plan['batch_count'])
        prompt_chars = sum(len(m.get('content') or '') for m in msgs)
        r = chat(msgs, max_tokens=(cfg['MAX_TOKENS'] if single else cfg['BATCH_MAX_TOKENS']))
        entry = {
            'index': b['index'], 'status': 'success' if r.get('ok') else 'failed',
            'chars': b['chars'], 'prompt_chars': prompt_chars,
            'section_titles': [s['title'] for s in b['sections']],
            'text': r.get('text') or '', 'error': r.get('error') or '',
            'warning': ('输出在 finish_reason=length 处被截断（达到输出上限），内容可能不完整'
                        if r.get('finish_reason') == 'length' else ''),
            'latency_ms': r.get('latency_ms') or 0,
            'model': r.get('model') or cfg['MODEL'],
        }
        base['batches'].append(entry)
        base['prompt_chars'] += prompt_chars
        base['latency_ms'] += entry['latency_ms']
        base['model'] = entry['model']
        if entry['status'] != 'success':
            failures.append('第%d批：%s' % (b['index'], entry['error']))
        logger.info('ops LLM 分批分析 scope=%s 批次=%d/%d status=%s 证据=%d字 耗时=%dms',
                    scope, b['index'], plan['batch_count'], entry['status'],
                    entry['chars'], entry['latency_ms'])

    if single:
        one = base['batches'][0]
        base['status'] = one['status']
        base['text'] = one['text']
        base['error'] = one['warning'] if one['status'] == 'success' else one['error']
        base['finished_at'] = now_text()
        return base

    good = [b for b in base['batches'] if b['status'] == 'success']
    if not good:
        base['error'] = '分批调用全部失败：%s' % '；'.join(failures)[:500]
        base['finished_at'] = now_text()
        return base

    msgs = build_merge_messages(scope, analysis, base['batches'], plan['overflow'])
    prompt_chars = sum(len(m.get('content') or '') for m in msgs)
    r = chat(msgs, max_tokens=cfg['MERGE_MAX_TOKENS'])
    base['prompt_chars'] += prompt_chars
    base['latency_ms'] += r.get('latency_ms') or 0
    base['merge'] = {'status': 'success' if r.get('ok') else 'failed',
                     'prompt_chars': prompt_chars, 'latency_ms': r.get('latency_ms') or 0,
                     'error': r.get('error') or ''}
    partial = ('注意：有 %d 批证据未能分析（%s），本意见仅基于其余批次，可能不完整'
               % (len(failures), '；'.join(failures)[:300])) if failures else ''
    if r.get('ok'):
        base['status'] = 'success'
        base['text'] = r['text']
        warn = '；'.join(x for x in (partial,
                                     '汇总输出在 finish_reason=length 处被截断，内容可能不完整'
                                     if r.get('finish_reason') == 'length' else '') if x)
        base['error'] = warn
    else:
        # 汇总失败但各批已有结果：如实降级成"各批原文拼接"，绝不假装汇总成功
        base['status'] = 'success'
        base['text'] = '\n\n'.join(
            '## 第 %d 批分析结果（汇总调用失败，以下为各批原文，未去重、可能相互矛盾）\n%s'
            % (b['index'], b['text']) for b in good)
        base['merge']['note'] = '已降级为各批原文拼接'
        base['error'] = '；'.join(x for x in (
            '各批分析完成，但汇总调用失败：%s' % (r.get('error') or '未知错误'), partial) if x)
    base['finished_at'] = now_text()
    logger.info('ops LLM 辅助分析完成 scope=%s status=%s 批次=%d 证据=%d字 提示=%d字 耗时=%dms',
                scope, base['status'], plan['batch_count'], base['evidence_chars'],
                base['prompt_chars'], base['latency_ms'])
    return base


# 落 analysis['llm'] 时要裁掉的重字段（完整内容留在 LlmAnalysisRecord）
_HEAVY_KEYS = ('evidence_text', 'batches', 'merge')


def slim_for_storage(out, record_id=None):
    """裁掉证据全文与各批原文，只留结果页/轮询接口需要的部分。

    analysis 是 JSONField，会随结果页 3 秒轮询一起返回；把上万字证据塞在里面
    既拖慢页面，也容易让人误以为那是采集数据。完整留痕在 LlmAnalysisRecord，
    这里只留 record_id 指过去。
    """
    out = out if isinstance(out, dict) else {}
    slim = {k: v for k, v in out.items() if k not in _HEAVY_KEYS}
    slim['batches'] = [{
        'index': b.get('index'), 'status': b.get('status'), 'chars': b.get('chars'),
        'prompt_chars': b.get('prompt_chars'), 'latency_ms': b.get('latency_ms'),
        'error': b.get('error') or '', 'warning': b.get('warning') or '',
        'section_titles': b.get('section_titles') or [],
    } for b in (out.get('batches') or []) if isinstance(b, dict)]
    m = out.get('merge') or {}
    if m:
        slim['merge'] = {'status': m.get('status'), 'latency_ms': m.get('latency_ms'),
                         'prompt_chars': m.get('prompt_chars'),
                         'error': m.get('error') or '', 'note': m.get('note') or ''}
    slim['record_id'] = record_id if record_id is not None else out.get('record_id')
    return slim
