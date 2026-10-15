"""前端可编辑配置：库里的值覆盖 settings，settings 作默认值与兜底。

为什么用"写回 settings"而不是让各调用点改成 cfg.get()：
平台里有几十处 `settings.OPS_LLM_CONFIG[...]` / `settings.ANSIBLE_CONFIG[...]`
的直接读取，逐个改成走封装函数既容易漏又会产生一大堆 diff。改为在
AppConfig.ready() 与每次保存后把库里的覆盖值原地写回 settings 对象
（dict 就地 update、flat 键 setattr），所有既有读取点立刻生效，零改动。

代价：值是"进程内快照"。故有三条刷新路径——
  1) 保存/重置配置后立即 apply（当前 web 进程马上生效）；
  2) beat 定时任务周期 apply（Celery worker 是长驻进程，靠它收敛）；
  3) 进程重启时 ready() apply。

红线：is_secret=True 的键只写不读——页面只显示掩码（连首尾字符都不露），
接口不返回明文，审计只记长度。隔离内网允许服务端持有明文凭据，
但不允许它经前端界面外泄。
"""
import logging

from django.conf import settings

logger = logging.getLogger(__name__)

_MISSING = object()

# 可编辑键白名单：(settings路径, 分组, 值类型, 是否凭据, 说明, settings缺省时的默认值)
#
# 只有登记在这里的键才能从前端改。这是刻意的：settings 里还有 SECRET_KEY、
# DATABASES、SSO_APP_SECRET、MIDDLEWARE 这些一旦改错就整站起不来的键，
# 绝不能出现在一个网页表单里。要加新的可编辑项，就在这里加一行。
#
# 刻意不登记 MAX_TOKENS / BATCH_MAX_TOKENS / MERGE_MAX_TOKENS：
# 内网模型是思考型（先写 reasoning_content 再写 content），这三个值一旦为正数，
# 输出预算会被思维链吃光，content 返回空串而 HTTP 仍是 200 —— 这个坑已经踩过一次
# （页面报"模型返回空内容"）。配置界面不该把一个已经造成过故障的foot-gun 递到运维手里。
EDITABLE = [
    # ---- 大模型 ----
    ('OPS_LLM_CONFIG.ENABLED', 'llm', 'bool', False,
     '启用大模型辅助分析；关闭后结果页按钮会说明原因，不影响采集与规则分析', None),
    ('OPS_LLM_CONFIG.BASE_URL', 'llm', 'str', False,
     '模型接口地址（OpenAI 兼容 /v1/chat/completions）', None),
    ('OPS_LLM_CONFIG.MODEL', 'llm', 'str', False, '模型名', None),
    ('OPS_LLM_CONFIG.API_KEY', 'llm', 'str', True,
     '模型鉴权 key；内网自建服务一般留空', None),
    ('OPS_LLM_CONFIG.TEMPERATURE', 'llm', 'float', False,
     '采样温度，越低越稳定（故障分析建议 0.1~0.3）', None),
    ('OPS_LLM_CONFIG.TIMEOUT', 'llm', 'int', False,
     '单次调用超时（秒）。大模型首字较慢，别调太小', None),
    ('OPS_LLM_CONFIG.MAX_CHARS', 'llm', 'int', False,
     '单批送进模型的证据字数上限；超出会自动分批并声明', None),
    ('OPS_LLM_CONFIG.MAX_BATCHES', 'llm', 'int', False,
     '最多分批数。Celery -P solo 下单 worker 会被独占 (批数+1)×超时 秒，不宜调大', None),
    ('OPS_LLM_CONFIG.DISABLE_THINKING', 'llm', 'bool', False,
     '跳过思考直接作答（更快）。服务端不认这个字段会返回 400，报错就改回关闭', None),

    # ---- 运维分析 / 自动发现 ----
    ('OPS_DISCOVERY_CONFIG.REMOTE_BASE', 'ops', 'str', False,
     '控制机上 ops playbook/脚本的存放根目录（程序自动 SFTP 同步）', None),
    ('OPS_DISCOVERY_CONFIG.NGINX_HOST', 'ops', 'str', False, 'Nginx 反代服务器 IP', None),
    ('OPS_DISCOVERY_CONFIG.NGINX_CONF', 'ops', 'str', False, 'Nginx 主配置文件路径', None),
    ('OPS_DISCOVERY_CONFIG.JENKINS_HOST', 'ops', 'str', False,
     'Jenkins 服务器 IP；留空则跳过 Jenkins 发现源', None),
    ('OPS_DISCOVERY_CONFIG.JENKINS_JOBS_DIR', 'ops', 'str', False, 'Jenkins jobs 目录', None),
    ('OPS_DISCOVERY_CONFIG.PROBE_HOST', 'ops', 'str', False,
     'DNS 探测机；留空则回退用 NGINX_HOST', None),
    ('OPS_DISCOVERY_CONFIG.DNS_SERVERS', 'ops', 'str', False,
     '内网 DNS 服务器（逗号分隔），排查时逐台解析核对', None),
    ('OPS_DISCOVERY_CONFIG.INVENTORY', 'ops', 'str', False,
     'Linux 目标所在 inventory 文件名', None),
    ('OPS_DISCOVERY_CONFIG.WINDOWS_INVENTORY', 'ops', 'str', False,
     'Windows 目标所在 inventory 文件名（winrm，必须与 Linux 分开）', None),
    ('OPS_DISCOVERY_CONFIG.SUPERVISOR_HOSTS', 'ops', 'list', False,
     '要扫描 supervisor 的应用机 IP；留空=自动取 nginx/jenkins 发现的部署 IP', []),
    ('OPS_DISCOVERY_CONFIG.SUPERVISOR_WEB_PORT', 'ops', 'int', False,
     'supervisor Web 面板端口（每台应用机本机）', None),
    ('OPS_DISCOVERY_CONFIG.SUPERVISOR_WEB_USER', 'ops', 'str', True,
     'supervisor 面板账号（服务端抓取 logtail 用）', None),
    ('OPS_DISCOVERY_CONFIG.SUPERVISOR_WEB_PASS', 'ops', 'str', True,
     'supervisor 面板密码', None),
    ('OPS_DISCOVERY_CONFIG.OS_LOG_DAYS', 'ops', 'int', False,
     '影响分析/故障排查顺带采集近 N 日操作系统日志（只读）', None),

    # ---- Ansible 控制机 ----
    ('ANSIBLE_CONFIG.HOST', 'ansible', 'str', False, 'Ansible 控制机地址', None),
    ('ANSIBLE_CONFIG.WORKDIR', 'ansible', 'str', False, '控制机上的工作目录', None),
    ('ANSIBLE_CONFIG.PLAYBOOK_BIN', 'ansible', 'str', False,
     'ansible-playbook 可执行文件路径', '/usr/bin/ansible-playbook'),
    ('ANSIBLE_CONFIG.PYTHONPATH', 'ansible', 'str', False,
     '控制机 venv 的 site-packages（系统 ansible 靠它加载 pywinrm；留空则不 export）',
     '/opt/venv/lib/python3.12/site-packages'),
    ('ANSIBLE_CONFIG.INVENTORY', 'ansible', 'str', False, '默认 inventory 文件名', None),
    ('ANSIBLE_CONFIG.USERNAME', 'ansible', 'str', True, '控制机 SSH 账号', None),
    ('ANSIBLE_CONFIG.PASSWORD', 'ansible', 'str', True, '控制机 SSH 密码', None),

    # ---- 防火墙 ----
    ('FW_INTERNAL_CIDRS', 'fw', 'list', False,
     '内网网段前缀（用于外部 IP 判定），按企业实际补充', None),
    ('FW_INVENTORY_PATH', 'fw', 'str', False,
     '防火墙主机同步读取的 inventory 路径；留空用 /etc/ansible/hosts', ''),

    # ---- 病毒检测 ----
    ('AV_QUARANTINE_ROOT', 'av', 'str', False,
     '隔离留存根目录（处置动作全部留痕，绝不直接删业务文件）', ''),
    ('AV_COLLECT_HOST_IPS', 'av', 'list', False,
     '参与 Defender 事件采集的主机 IP；留空=按 AvCollectState 表', []),
    ('AV_EVENT_IDS', 'av', 'intlist', False,
     '采集的 Defender 事件 ID（1116 发现/1117 处置/1118 未处置/1119 已清理）', None),

    # ---- 平台 ----
    ('SYS_EXECLOG_KEEP_DAYS', 'system', 'int', False,
     '执行留痕保留天数（playbook/ansible/shell/sync）', 90),
    ('SYS_EXECLOG_PROBE_KEEP_DAYS', 'system', 'int', False,
     '探活类留痕保留天数（ping 量大、事后价值低，单独短保留）', 7),
    ('SYS_PROBE_INTERVAL_MIN', 'system', 'int', False,
     '首页拓扑探活周期（分钟）', 5),
]

_SPEC_BY_KEY = {row[0]: row for row in EDITABLE}

GROUP_LABELS = {
    'llm': '大模型',
    'ops': '运维分析',
    'ansible': 'Ansible 控制机',
    'av': '病毒检测',
    'fw': '防火墙',
    'report': '报表',
    'system': '平台',
}


def spec(path):
    """取某键的白名单条目；不在白名单里返回 None（即不可从前端编辑）。"""
    return _SPEC_BY_KEY.get(path)


def is_editable(path):
    return path in _SPEC_BY_KEY


def _split(path):
    parts = path.split('.', 1)
    return parts[0], (parts[1] if len(parts) > 1 else '')


def from_settings(path):
    """从 settings 读当前值。支持 'DICT.KEY' 两段式；读不到返回 _MISSING。"""
    root, leaf = _split(path)
    obj = getattr(settings, root, _MISSING)
    if obj is _MISSING:
        return _MISSING
    if not leaf:
        return obj
    if isinstance(obj, dict):
        return obj.get(leaf, _MISSING)
    return _MISSING


def default_of(path):
    """该键的出厂默认值：settings 快照优先，快照里没有则用白名单登记的兜底默认。

    必须读快照而不是读 settings：apply_to_settings 是就地改写 settings 的，
    改过之后 settings 里躺着的已经是覆盖值了。直接读它会让"恢复默认"无处可恢复、
    配置页的"默认值"列跟着显示成当前值——两个都是错的。
    """
    _snapshot_baseline()
    if path in _BASELINE and _BASELINE[path] is not None:
        return _BASELINE[path]
    v = from_settings(path)
    if v is not _MISSING:
        return v
    row = _SPEC_BY_KEY.get(path)
    return row[5] if row else None


def effective(path):
    """该键的生效值：库里的覆盖优先，其次 settings。"""
    try:
        from sysmanage.models import SysConfig
        row = SysConfig.objects.filter(key=path).first()
        if row is not None and row.value is not None:
            return row.value
    except Exception:
        # 表还没 migrate / DB 抖动：退回 settings，绝不能因为配置层挂掉而影响业务
        logger.warning('读取配置 %s 失败，回退 settings 默认值', path, exc_info=True)
    v = from_settings(path)
    return None if v is _MISSING else v


# settings 出厂值快照，首次 apply/default_of 时采集一次（见 _snapshot_baseline）
_BASELINE = {}


def _snapshot_baseline():
    """把 settings 里的出厂值按白名单逐键快照下来（只采一次）。

    时机上一定早于任何写回：apply_to_settings 与 default_of 都会先调它，
    而这两者都在第一次改写 settings 之前执行，所以快照必然是纯净的出厂值。
    """
    if _BASELINE:
        return
    for row in EDITABLE:
        path = row[0]
        v = from_settings(path)
        _BASELINE[path] = None if v is _MISSING else v


def _write_back(path, value):
    """把一个值写回 settings。dict 类键就地 update（保持对象身份，
    避免别处已经拿到旧引用），flat 键 setattr。返回是否写入成功。"""
    root, leaf = _split(path)
    try:
        cur = getattr(settings, root, _MISSING)
        if leaf:
            if cur is _MISSING:
                setattr(settings, root, {leaf: value})
            elif isinstance(cur, dict):
                cur[leaf] = value
            else:
                logger.warning('配置 %s 跳过：%s 不是字典', path, root)
                return False
        else:
            setattr(settings, root, value)
        return True
    except Exception:
        logger.warning('配置 %s 写回 settings 失败', path, exc_info=True)
        return False


def parse_value(raw, value_type):
    """把表单提交的字符串转成目标类型。转不了就抛 ValueError（带中文原因）。

    宁可报错也不静默降级：把 "abc" 悄悄存成 0，等它生效时排查成本更高。
    """
    s = '' if raw is None else str(raw).strip()
    if value_type == 'bool':
        if s.lower() in ('1', 'true', 'yes', 'on', '是', '开', 'enabled'):
            return True
        if s.lower() in ('0', 'false', 'no', 'off', '否', '关', 'disabled', ''):
            return False
        raise ValueError('开关只接受 是/否、true/false、1/0')
    if value_type == 'int':
        if s == '':
            raise ValueError('整数不能为空（要清空请用"恢复默认"）')
        try:
            return int(s)
        except ValueError:
            raise ValueError('"%s" 不是整数' % s)
    if value_type == 'float':
        if s == '':
            raise ValueError('小数不能为空（要清空请用"恢复默认"）')
        try:
            return float(s)
        except ValueError:
            raise ValueError('"%s" 不是小数' % s)
    if value_type in ('list', 'intlist'):
        if s == '':
            return []
        parts = [p.strip() for p in s.replace('\r', '\n').replace(',', '\n').split('\n')]
        parts = [p for p in parts if p]
        if value_type == 'intlist':
            out = []
            for p in parts:
                try:
                    out.append(int(p))
                except ValueError:
                    raise ValueError('"%s" 不是整数' % p)
            return out
        return parts
    return s


def apply_to_settings():
    """让 settings 与数据库覆盖对齐，返回本次写成"覆盖值"的键列表。

    两步：先把白名单里所有键恢复到出厂快照，再套用库里的覆盖。
    必须两步——只做第二步的话，删掉某条覆盖后 settings 里仍留着上一次的旧值，
    "恢复默认"就失效了（这是实现过程中真实踩到的 bug，回归里盯着）。

    不在白名单里的键一律不写回：防止有人绕过界面直接往表里塞 SECRET_KEY /
    DATABASES 之类的键把整站搞挂。
    """
    _snapshot_baseline()
    try:
        from sysmanage.models import SysConfig
        rows = list(SysConfig.objects.all())
    except Exception:
        logger.warning('配置覆盖未生效（读库失败，沿用 settings 默认值）', exc_info=True)
        return []
    overrides = {}
    for row in rows:
        if row.value is not None and is_editable(row.key):
            overrides[row.key] = row.value
    applied = []
    for row in EDITABLE:
        path = row[0]
        if path in overrides:
            if _write_back(path, overrides[path]):
                applied.append(path)
        else:
            base = _BASELINE.get(path)
            if base is not None:
                _write_back(path, base)
    if applied:
        logger.info('已从数据库应用 %d 项配置覆盖：%s', len(applied), ', '.join(applied))
    return applied


def _audit(username, key, action, old_display, new_display, result='success', detail=''):
    try:
        from sysmanage.models import ConfigAuditLog
        ConfigAuditLog.objects.create(
            username=(username or 'unknown')[:100], key=key[:128], action=action,
            old_display=(old_display or '')[:255], new_display=(new_display or '')[:255],
            result=result, detail=detail or '')
    except Exception:
        logger.warning('配置审计写入失败（忽略）', exc_info=True)


def _display(path, value):
    """值的展示形态。凭据类只露长度，一个字符都不露。"""
    from sysmanage.services.redact import mask_secret, mask_value
    row = _SPEC_BY_KEY.get(path)
    if row and row[3]:
        return mask_secret(value)
    return mask_value(value)


def set_value(path, raw, username):
    """校验 → 入库 → 写审计 → 立即生效。返回 (ok, message)。

    凭据类字段有个特殊约定：提交空串表示"不改"，因为页面从不回显明文，
    运维看到的输入框是空的，直接存空会把已有凭据抹掉。
    """
    row = _SPEC_BY_KEY.get(path)
    if row is None:
        # 被拒绝的越权写入也要留审计：谁试图改 SECRET_KEY / DATABASES 正是最该记下来的一条。
        # 但绝不把提交上来的值写进审计——它可能就是那个不该落库的机密。
        _audit(username, path, 'update', '', '', result='failed',
               detail='不在可编辑白名单内，已拒绝（提交的值不记录）')
        return False, '该配置项不在可编辑白名单内（%s）' % path
    _key, group, vtype, secret, desc, _dft = row
    if secret and (raw is None or str(raw).strip() == ''):
        return True, '凭据未提交新值，保持原值不变'
    try:
        value = parse_value(raw, vtype)
    except ValueError as exc:
        _audit(username, path, 'update', '', '', result='failed', detail=str(exc))
        return False, str(exc)

    from sysmanage.models import SysConfig
    old_display = _display(path, effective(path))
    obj, created = SysConfig.objects.update_or_create(
        key=path,
        defaults={'value': value, 'group': group, 'desc': desc,
                  'value_type': vtype, 'is_secret': secret,
                  'updated_by': (username or '')[:100]},
    )
    new_display = _display(path, value)
    _audit(username, path, 'create' if created else 'update',
           old_display, new_display,
           detail='（%s）' % desc[:120])
    apply_to_settings()
    return True, '已保存并生效：%s = %s' % (path, new_display)


def reset_value(path, username):
    """删除库里的覆盖，恢复用 settings 默认值。返回 (ok, message)。"""
    if not is_editable(path):
        # 与 set_value 同一口径：被拒绝的越权动作也要留痕
        _audit(username, path, 'reset', '', '', result='failed',
               detail='不在可编辑白名单内，已拒绝')
        return False, '该配置项不在可编辑白名单内（%s）' % path
    from sysmanage.models import SysConfig
    old_display = _display(path, effective(path))
    n, _ = SysConfig.objects.filter(key=path).delete()
    if n:
        _audit(username, path, 'reset', old_display,
               _display(path, default_of(path)), detail='删除数据库覆盖，恢复 settings 默认值')
    apply_to_settings()
    return True, ('已恢复默认：%s = %s' % (path, _display(path, default_of(path)))
                  if n else '该项本来就没有覆盖，当前即默认值')


def items_for_page():
    """配置页数据：按分组组织，每项带"当前生效值/是否已覆盖/默认值"。

    凭据类只给掩码；has_override 让运维一眼看出"哪些是改过的、哪些还是出厂默认"。
    """
    from sysmanage.models import SysConfig
    rows = {r.key: r for r in SysConfig.objects.all()}
    groups = {}
    for path, group, vtype, secret, desc, _dft in EDITABLE:
        row = rows.get(path)
        cur = effective(path)
        dft = default_of(path)
        groups.setdefault(group, []).append({
            'key': path,
            'group': group,
            'group_label': GROUP_LABELS.get(group, group),
            'value_type': vtype,
            'is_secret': secret,
            'desc': desc,
            'display': _display(path, cur),
            'default_display': _display(path, dft),
            'has_override': row is not None and row.value is not None,
            'updated_by': (row.updated_by if row else '') or '',
            'updated_at': (row.updated_at if row else None),
            # 表单初值：凭据类留空（永不回显明文），其它给当前值的文本形态
            'form_value': '' if secret else _to_form(cur, vtype),
        })
    return [(GROUP_LABELS.get(g, g), g, items) for g, items in groups.items()]


def _to_form(value, vtype):
    if value is None:
        return ''
    if isinstance(value, bool):
        return 'true' if value else 'false'
    if vtype in ('list', 'intlist') and isinstance(value, (list, tuple)):
        return ', '.join(str(x) for x in value)
    return str(value)
