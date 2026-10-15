"""运维分析 Celery 任务包。

autodiscover_tasks() 只会 `import opsanalysis.tasks`，故必须在此显式导入各子模块，
让 @shared_task 在 worker 启动时完成注册（与 firewall/antivirus 的 tasks 包一致）。
"""
from .analysis import run_impact_task, run_troubleshoot_task  # noqa: F401
from .discovery import run_discover_task  # noqa: F401
from .llm import run_llm_analysis  # noqa: F401

__all__ = ['run_impact_task', 'run_troubleshoot_task', 'run_discover_task',
           'run_llm_analysis']
