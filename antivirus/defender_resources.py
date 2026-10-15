"""Windows Defender 事件资源串（%%NNN）→ 可读文本。

Defender 的 Operational 日志里，Action Name / Severity Name / Category Name 等字段
存的是"消息资源引用"（形如 ``%%809``），需由 provider 的消息 DLL(MpEvMsg.dll) 渲染
成文本。直接读 EventData 拿到的就是未渲染的 ``%%809``，界面上会原样显示，用户看不懂。

本模块内置一份权威映射（Microsoft-Windows-Windows Defender 消息表 800~860 段），
在入库/展示时把 ``%%NNN`` 就地替换成对应文本。红线：只做"忠实还原"，
未收录的编号保持原样（绝不臆测），不篡改任何处置留痕语义。
"""
import re

# Microsoft-Windows-Windows Defender 消息资源表（800~860），键为去掉 %% 的编号。
RESOURCE_MAP = {
    '800': 'AntiVirus',
    '801': 'AntiSpyware',
    '802': 'Antimalware',
    '803': 'Full',
    '804': 'Delta',
    '805': 'Full Scan',
    '806': 'Quick Scan',
    '807': 'Custom Scan',
    '808': 'Remove',
    '809': 'Quarantine',
    '810': 'Clean',
    '811': 'Allow',
    '812': 'Unknown',
    '813': 'Suspended',
    '814': 'Allowed',
    '815': 'User',
    '816': 'Scheduled',
    '817': 'Signature Update Folder',
    '818': 'Real-Time Protection',
    '819': 'Downloads and attachments',
    '820': 'System',
    '821': 'Heuristics',
    '822': 'Concrete',
    '823': 'Generic',
    '824': 'Current',
    '825': 'Backup',
    '826': 'Default',
    '827': 'Windows Defender Antivirus',
    '828': 'Microsoft Forefront Endpoint Protection',
    '829': 'Microsoft Standalone System Sweeper',
    '830': 'Crash',
    '831': 'Hang',
    '832': 'Not Applicable',
    '833': 'IE Downloads and Outlook Express Attachments',
    '834': 'On Access',
    '835': 'Behavior Monitoring',
    '843': 'Suspicious',
    '844': 'Unknown',
    '845': 'Local machine',
    '846': 'Network share',
    '847': 'Internet',
    '848': 'Executing',
    '849': 'Internal Definition Update Server',
    '850': 'File Share',
    '851': 'Microsoft Malware Protection Center',
    '852': 'Search',
    '853': 'Download',
    '854': 'Install',
    '855': 'Low',
    '856': 'Medium',
    '857': 'High',
    '859': 'Microsoft Update Server',
    '860': 'Microsoft Antimalware',
}

_RES_RE = re.compile(r'%%(\d+)')


def resolve_resource(text):
    """把字符串里的 ``%%NNN`` 资源引用替换成可读文本；未收录的编号原样保留。

    兼容带后缀的写法，如 ``%%809 (Failed)`` → ``Quarantine (Failed)``。
    非字符串/空值原样返回。
    """
    if not text:
        return text
    s = str(text)
    if '%%' not in s:
        return s
    return _RES_RE.sub(lambda m: RESOURCE_MAP.get(m.group(1), m.group(0)), s)
