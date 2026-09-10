# h8667_vmplatform — 内网虚拟化运维平台

## 项目简介

面向内网环境的虚拟化运维自助平台。用户通过 Web 界面提交虚拟机磁盘扩容、
域名配置、Windows 服务器授权登录、IE/Edge 受信任站点设置等运维申请，
平台对接 vCenter / Ansible / AD / WinRM 自动完成执行，并内置 SSO 单点登录
与管理员审批流程。耗时操作通过 Celery 异步执行，前端轮询任务状态。

## 功能模块

1. **磁盘扩容（resize）**：输入虚拟机 IP → 查询磁盘列表（含 datastore 剩余空间）→
   选择磁盘并填写扩容容量与原因 → 按规则自动审批或转人工审批 →
   Celery 异步执行 vCenter 磁盘扩容 + Ansible 文件系统扩容。
2. **域名配置（domain）**：申请 `*.4307.com` 域名解析与 nginx 反向代理、
   负载均衡、SSL 证书配置，管理员审批后异步执行。
3. **服务器授权登录（server_auth）**：将域账号授权登录指定服务器
   （写入 AD userWorkstations 并加入本地管理员组），提交即自动执行。
4. **受信任站点设置（trust_site）**：通过 WinRM 在域控上更新组策略，
   将域名加入用户 IE/Edge 受信任站点，提交即自动执行。

## 技术栈

- 后端：Python 3.12 + Django 6.0
- 异步任务：Celery 5 + Redis（broker / result backend）
- 数据库：MySQL（hpjx 私有引擎）
- 虚拟化：pyVmomi（vCenter API）
- 自动化：Ansible（SSH 远程调用 ansible-playbook）
- 域控/系统：ldap3、pywinrm、paramiko
- 认证：hpjx 内网 SSO（`hpjx.hpjx_sso`）
- 前端：Django 模板 + 本地 Bootstrap 5（无外部 CDN，内网离线可用）

## 部署说明

依赖：

- MySQL 5.7+（库名默认 `h8667_vm_resize`）
- Redis（Celery broker / result backend）
- 可达的 vCenter、Ansible 控制机、AD 域控
- Python 3.12+

```bash
# 1. 安装依赖
pip install -r requirements.txt

# 2. 数据库迁移
python manage.py migrate

# 3. 启动 Web 服务
python manage.py runserver 0.0.0.0:8000

# 4. 启动 Celery worker（异步执行扩容等任务）
celery -A h8667_vmplatform worker -l info
```

## 需求实现对照

| # | 需求 | 实现说明 |
|---|------|----------|
| 1 | 前端界面美化 | 模板统一重构：浅色玻璃拟态导航、功能卡片、状态徽章、分页导航、任务状态轮询 |
| 2 | 审批流程 | 对接内网 SSO，管理员（`兼职信息化管理员`角色）在审批中心批准/驳回 |
| 3 | 后台异步执行 | 申请落库为任务，Celery worker 异步执行，前端轮询 `api/task/<id>/status/` 获取进度 |
| 4 | 扩容前存储空间判断 | 提交时实时查询 datastore 剩余空间并记录到任务；执行前再次预检（含 100GB 安全预留） |
| 5 | 按申请容量自动审批 | 申请扩容量 < 200GB 且存储充足 → 自动批准并立即执行；否则转人工审批 |
| 6 | 同大小磁盘区分 | 使用 vCenter 磁盘唯一标识 `disk_key`（`scsi{controllerKey}:{unitNumber}`）精确定位，提交时后端重查覆盖防篡改 |
| 7 | 关机虚拟机扩容 | vCenter 磁盘扩容后检测电源状态，关机则跳过文件系统扩容并提示"请开机后手动扩容文件系统" |
| 8 | 快照检测 | 提交时拦截存在快照的虚拟机（不落库）；执行层保留兜底检查，发现快照即失败并提示 |

## 环境变量清单

以下配置项均可通过环境变量覆盖（默认值仅供内网开发环境使用）：

| 环境变量 | 对应配置 | 默认值 |
|----------|----------|--------|
| `VMP_SECRET_KEY` | Django `SECRET_KEY` | 内置开发密钥 |
| `VMP_DEBUG` | Django `DEBUG`（`true`/`false`） | `true` |
| `VMP_CELERY_BROKER_URL` | `CELERY_BROKER_URL` | `redis://@x.x.20.143:6379/0` |
| `VMP_CELERY_RESULT_BACKEND` | `CELERY_RESULT_BACKEND` | `redis://@x.x.20.143:6379/1` |
| `VMP_VCENTER_USERNAME` | `VCENTER_CONFIG['USERNAME']` | `administrator@vsphere.local` |
| `VMP_VCENTER_PASSWORD` | `VCENTER_CONFIG['PASSWORD']` | 内网默认密码 |
| `VMP_ANSIBLE_USERNAME` | `ANSIBLE_CONFIG['USERNAME']` | 内网默认账号 |
| `VMP_ANSIBLE_PASSWORD` | `ANSIBLE_CONFIG['PASSWORD']` | 内网默认密码 |
| `VMP_AD_PASSWORD` | `AD_CONFIG['PASSWORD']` | 内网默认密码 |
| `VMP_TRUST_SITE_PASSWORD` | `TRUST_SITE_CONFIG['PASSWORD']` | 内网默认密码 |
| `VMP_DB_PASSWORD` | `DATABASES['default']['PASSWORD']` | 内网默认密码 |
| `VMP_SSO_APP_SECRET` | `SSO_APP_SECRET` | 内网默认密钥 |
| `VMP_DEV_SSO_APP_SECRET` | `DEV_SSO_APP_SECRET` | 内网默认密钥 |
