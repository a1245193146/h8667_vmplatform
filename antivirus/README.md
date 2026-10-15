# 病毒检测与隔离模块 — 部署配置使用说明

Windows Defender 病毒检测与隔离管理模块。基于 Windows Server 2016+ 内置 Defender 做文件病毒检测/隔离，
本系统只读取 Defender 检测事件与结果，形成统一病毒事件记录，并把需留存的文件安全转存到 UNC 隔离目录，
保证 Defender 清理后仍可追溯。

红线：不自研扫描引擎；不直接删除业务文件；不触碰 Defender 内部隔离目录；所有隔离/恢复/清理操作全部留痕。

---

## 0. 架构与数据流

```
Windows Server 2016 (Defender)
   └─ Defender 检出/隔离 → 写事件日志(1116/1117/1118/1119)
Django (Celery Beat 每30分钟)
   └─ collect_all_hosts_task → 逐台 run_playbook('av_collect_detections.yml')
Ansible 控制机 (SSH, /etc/ansible)
   └─ ansible-playbook -i hosts firewall/ansible/av_*.yml  → WinRM → 目标机
        └─ win_copy 推送 Av-*.ps1 + 执行 → 回传单行 JSON
Django 解析入库 (去重: unique(host, event_hash))
   └─ 页面查库展示；留存/恢复/清理异步派发到 UNC 隔离目录
```

模块复用防火墙（firewall）执行层：主机清单 `FirewallHost`、`run_playbook`、`parse_host_json`、`AnsibleTaskRecord`。
PowerShell 脚本与 Ansible playbook 因此放在 `firewall/powershell/` 与 `firewall/ansible/` 目录下，与防火墙资产同级。

---

## 1. 代码位置

Django 应用 `antivirus/`：

| 文件 | 作用 |
|---|---|
| `models.py` | `AvDetection`（病毒事件）、`AvCollectState`（断点续采水位）、`AvAuditLog`（操作留痕） |
| `migrations/0001_initial.py` | 建表迁移（依赖 `firewall.0001`） |
| `views.py` / `urls.py` | 看板、事件列表/详情、留存/复核/恢复/清理、审计、任务（URL 名以 `av_` 前缀） |
| `serializers.py` | 看板聚合（DB 聚合，不实时调 Ansible） |
| `services/collectors.py` | 采集（断点续采）+ 留存 |
| `services/ingest.py` | 事件归一化 + 去重入库 |
| `services/actions.py` | 复核 / 恢复 / 清理 |
| `services/audit.py` | 操作留痕 |
| `tasks/collection.py` / `tasks/actions.py` | Celery 异步任务 |
| `utils/rbac.py` | `av_admin_required` 管理员鉴权 |
| `templates/antivirus/` | 页面模板 |

执行层（随代码发布，需同步到 Ansible 控制机）：

- `firewall/ansible/`：`av_collect_detections.yml`、`av_preserve_file.yml`、`av_restore_file.yml`、`av_cleanup_file.yml`
- `firewall/powershell/`：`Av-CollectDetections.ps1`、`Av-PreserveFile.ps1`、`Av-RestoreFile.ps1`、`Av-CleanupFile.ps1`

---

## 2. Ansible 控制机（执行机）准备

1. 控制机上需存在仓库的 `firewall/ansible/` 与 `firewall/powershell/` 两个目录，且位于 `ANSIBLE_CONFIG['WORKDIR']`
   （默认 `/etc/ansible`）下——因为 playbook 用 `playbook_dir/../powershell` 定位脚本，命令又固定
   `firewall/ansible/<playbook>`。发布时把上述 8 个 av 文件同步到控制机对应目录即可。
2. `INVENTORY`（默认 `hosts`）中要有 `[windows]` 组，且组内主机地址与 `FirewallHost.ip` 一致
   （AV 用 `host.ip` 作为 `target_host`）。主机清单由防火墙模块的 `fw-sync-inventory` 任务同步，无需单独维护。
3. 目标 Windows 机需配好 WinRM（`ansible.windows`），与防火墙模块要求一致，无新增。

---

## 3. Django 侧配置（`h8667_vmplatform/settings.py`）

已内置（无需再改）：

- `INSTALLED_APPS` 已加 `'antivirus'`
- `h8667_vmplatform/urls.py` 已挂载 `path('antivirus/', include('antivirus.urls'))`
- `resize/templates/resize/base.html` 导航已加"病毒检测与隔离"下拉
- `CELERY_BEAT_SCHEDULE` 已加 `av-collect-all-hosts`（每 30 分钟）

需按环境配置：

| 配置项 | 说明 |
|---|---|
| `ANSIBLE_CONFIG` | 复用防火墙的 SSH 控制机配置（HOST/USERNAME/PASSWORD/WORKDIR/INVENTORY）。生产用环境变量 `VMP_ANSIBLE_USERNAME`、`VMP_ANSIBLE_PASSWORD` 覆盖 |
| `AV_QUARANTINE_ROOT` | **必填**。UNC 隔离根目录，默认空。为空则留存动作按设计失败（不静默写本地）。用同名环境变量覆盖 |
| `AV_EVENT_LOG_NAME` / `AV_EVENT_IDS` | 仅文档参照，采集脚本内已内置同等默认值，一般不用改 |

环境变量示例：

```bash
export AV_QUARANTINE_ROOT='\\文件服务器\AV-Quarantine'
export VMP_ANSIBLE_USERNAME='ansible_svc'
export VMP_ANSIBLE_PASSWORD='******'
```

---

## 4. UNC 隔离目录与权限（关键安全项）

以 `\\文件服务器\AV-Quarantine` 为例：

1. 在文件服务器建共享 `AV-Quarantine`。
2. **共享权限**：仅 `Administrators` 与执行 Ansible 的服务账号可读写；移除 `Everyone`。
   （脚本无法设置共享级权限，必须在基础设施侧手动配。）
3. **NTFS 权限**：脚本留存时会对 `{ROOT}\YYYY\MM\DD\{事件ID}` 子目录执行
   `icacls /inheritance:r /grant:r Administrators:F SYSTEM:F`（去继承，仅管理员 + SYSTEM）。
   根目录建议同样收紧，普通用户无访问权。
4. 目录按 `{ROOT}\YYYY\MM\DD\{事件ID}` 自动创建，无需预建。

---

## 5. 数据库迁移

```bash
cd h8667_vmplatform
python manage.py migrate antivirus
```

迁移 `0001_initial` 依赖 `firewall.0001`，请确保 firewall 已迁移。
建表：`antivirus_avdetection`、`antivirus_avcollectstate`、`antivirus_avauditlog`。

---

## 6. 启动 Celery（worker + beat）

采集与留存/恢复/清理都走 Celery 异步任务：

```bash
celery -A h8667_vmplatform worker -l info   # 执行 av 任务
celery -A h8667_vmplatform beat   -l info   # 定时调度 av-collect-all-hosts（每30分钟）
```

若与防火墙模块共用同一 worker/beat 即可，无需单独进程。

---

## 7. Windows 目标机前置条件

- Windows Server 2016+，Windows Defender 已启用（默认）。
- 事件日志 `Microsoft-Windows-Windows Defender/Operational` 已启用（Server 2016 默认开启）。
  采集脚本读取事件 ID **1116（检出）/ 1117（已处置）/ 1118、1119（处置失败）**。
- 采集为**断点续采**：每台主机在 `AvCollectState.last_record_id` 记录已消费的 Event Log RecordId 水位，
  只采更大的记录，重启/重跑不重不漏。首次采集 `since_record_id=0`（拉取现存事件，最多 1000 条/次）。

---

## 8. 使用流程

1. **看板** `/antivirus/` — 检测总数 / 待复核 / 确认恶意 / 误报、隔离留存数、采集健康度、
   近 14 天趋势、按服务器 / 威胁类型分布、TOP 威胁名称；60 秒自动刷新。右上角"立即采集"可手动触发全量采集。
2. **检测事件** `/antivirus/detections/` — 支持关键字（文件名/路径/威胁名/SHA256/主机）、当前状态、
   隔离留存状态、日期区间筛选。
3. **事件详情** `/antivirus/detections/<id>/` — 完整字段 + SHA256 + Defender 处置 + 隔离路径 + 操作日志。
   **管理员**可执行：
   - 留存隔离文件到 UNC（未留存 / 原文件不可得时）
   - 确认恶意 / 标记误报（纯 DB，同步）
   - 恢复文件（须填原因，异步；仅已留存时可用）
   - 最终清理（须填原因，异步，不可撤销）
   - 重新采集该主机
4. **审计日志** `/antivirus/audit/` — 所有留存 / 复核 / 恢复 / 清理 / 采集留痕，可按操作人 / 动作筛选。
5. **Ansible 任务** `/antivirus/tasks/` — 本模块触发的 `av_*` 任务执行记录与输出。

> 留存 / 恢复 / 清理为**异步**：提交后提示"任务已提交"，稍候刷新详情页看结果
> （`quarantine_status` 与操作日志会更新）。

状态字段说明：

- 当前状态 `status`：待复核 / 确认恶意 / 误报 / 已恢复 / 已清理
- 隔离留存 `quarantine_status`：未留存 / 已留存 / 原文件不可得 / 已恢复 / 已清理

---

## 9. 排查要点

| 现象 | 排查 |
|---|---|
| 采集 0 条 | 目标机 Defender Operational 日志是否有 1116/1117；`since_record_id` 水位是否已超过现存事件；`FirewallHost.enabled` 是否为真 |
| 留存失败 / 目标非法 | `AV_QUARANTINE_ROOT` 是否配置且为合法 UNC；控制机服务账号对 UNC 是否有写权限 |
| 任务一直 running / timeout | 控制机 SSH（`ANSIBLE_CONFIG`）连通性；WinRM；到 `/antivirus/tasks/` 看 `output` |
| PowerShell 中文乱码 / 解析错误 | 4 个 `Av-*.ps1` 必须带 UTF-8 BOM，同步到控制机时勿被转成 GBK / 去 BOM |
| 事件重复 | 去重键为 `unique(host, event_hash)`，event_hash 基于 Defender Detection ID；正常不会重复 |

---

## 10. 文件操作脚本的输入约定

留存 / 恢复 / 清理脚本一律通过 `-ParamsFile`（由 Ansible `win_copy` 写入的 JSON）接收路径参数，
**不经命令行拼接**，杜绝路径中空格 / 引号导致的注入与参数截断。JSON 键：

- `Av-PreserveFile.ps1`：`SourcePath`、`DestDir`、`FileName`
- `Av-RestoreFile.ps1`：`SourcePath`（UNC 留存副本）、`DestPath`（原始路径）
- `Av-CleanupFile.ps1`：`Path`（UNC 留存副本）

对应 playbook 的 `extra_vars`（由 Django 服务层传入）：

- `av_collect_detections.yml`：`target_host`、`since_record_id`
- `av_preserve_file.yml`：`target_host`、`source_path`、`dest_dir`、`file_name`
- `av_restore_file.yml`：`target_host`、`source_path`、`dest_path`
- `av_cleanup_file.yml`：`target_host`、`path`
