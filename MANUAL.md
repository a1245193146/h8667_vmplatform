# 虚拟机磁盘扩容平台 v2.0 部署与使用手册

## 1. 项目简介
虚拟机磁盘扩容平台 v2.0 是一个面向企业内网环境的自动化运维工具，旨在简化 vCenter 虚拟机的磁盘扩容流程。

### 功能概述
本版本实现了以下 8 项核心功能：
- UI 美化：基于 Bootstrap 5.3.0 打造简洁直观的用户界面。
- 审批流程：完善的申请、审批机制，确保操作可追溯。
- Celery 异步：通过异步任务处理耗时的扩容操作，避免页面卡死。
- 存储空间预检：执行扩容前自动检查物理存储剩余空间。
- 自动审批：对于小于 200GB 且资源充足的申请，系统自动批准执行。
- 磁盘区分：通过 SCSI 地址精确匹配磁盘，解决同大小磁盘的识别难题。
- 关机处理：支持关机状态下的磁盘扩容，并提供后续操作提示。
- 快照检测：自动检测虚拟机快照，存在快照时拒绝操作以保证数据安全。

## 2. 系统架构
平台基于 Django 6.0 框架开发，结合 Celery 实现异步任务调度，使用 Redis 作为消息中间件。
- 核心组件：Django 6.0 + Celery + Redis + MySQL + pyVmomi + Paramiko。
- 数据流向：用户提交申请 → 管理员/系统自动审批 → Celery 异步任务接管 → 通过 pyVmomi 调用 vCenter API 扩容虚拟磁盘 → 通过 Paramiko 远程连接 Ansible 控制节点执行文件系统扩容。

## 3. 环境要求
- 操作系统：推荐 Linux（Ubuntu/CentOS），支持 Windows 部署。
- Python：3.12+。
- 数据库：MySQL 5.7+ 或 8.0+。
- 缓存/消息队列：Redis 6.0+。
- 基础设施：vCenter 6.7+ 环境。
- 自动化工具：Ansible 控制节点（Ubuntu 推荐）。
- 认证系统：内网 SSO 系统（依赖 hpjx 包）。

## 4. 离线部署步骤
本指南重点介绍内网环境下的离线安装流程。

### 步骤 1：拷贝项目文件
将完整的项目文件夹拷贝到内网目标服务器中。

### 步骤 2：安装 Python 依赖
进入项目根目录，通过本地安装包安装依赖。
```bash
pip install --no-index --find-links=packages/ -r requirements.txt
```
注意：当前 packages/ 目录下的 whl 文件适用于 Windows x64 和 Python 3.12 环境。如果内网服务器为 Linux，需在联网的 Linux 机器上预先下载对应版本的安装包：
```bash
pip download -d packages/ -r requirements.txt --platform manylinux2014_x86_64 --python-version 312 --only-binary=:all:
```
在 Linux 上安装 mysqlclient 之前，需确保已安装以下系统级依赖：
- CentOS/RHEL：yum install mysql-devel python3-devel gcc
- Ubuntu/Debian：apt install libmysqlclient-dev python3-dev build-essential

### 步骤 3：安装 hpjx 包
hpjx 是公司内部 SSO 认证包，请从内网私有仓库获取并安装。

### 步骤 4：配置 settings.py
编辑 h8667_vmplatform/settings.py 文件，按实际情况填写配置：
- 数据库：DATABASES 配置中的 HOST、USER、PASSWORD、NAME。
- vCenter：VCENTER_CONFIG 中的 HOST、USERNAME、PASSWORD。
- Ansible：ANSIBLE_CONFIG 中的 HOST、USERNAME、PASSWORD、WORKDIR、PLAYBOOK 路径。
- Redis：设置 CELERY_BROKER_URL 和 CELERY_RESULT_BACKEND。
- SSO：填入 SSO_APP_ID、SSO_APP_SECRET 等。
- 安全性：生产环境下必须更改 SECRET_KEY，并将 DEBUG 设为 False，配置 ALLOWED_HOSTS。

### 步骤 5：初始化数据库
```bash
python manage.py makemigrations resize
python manage.py migrate
python manage.py createsuperuser  # 按提示创建管理员账号
```

### 步骤 6：收集静态文件
```bash
python manage.py collectstatic
```
项目已内置 Bootstrap 相关资源，无需联网即可加载样式。

### 步骤 7：启动 Redis
确保 Redis 服务已启动并监听配置的端口。
```bash
redis-server
```

### 步骤 8：启动 Celery Worker
开启一个新的终端窗口，启动异步任务处理器：
```bash
celery -A h8667_vmplatform worker -l info
```

### 步骤 9：启动 Django
- 开发/测试环境：
```bash
python manage.py runserver 0.0.0.0:8000
```
- 生产环境（推荐使用 gunicorn）：
```bash
pip install gunicorn
gunicorn h8667_vmplatform.wsgi:application -b 0.0.0.0:8000 -w 4
```

## 5. 功能使用说明

### 5.1 用户登录
- 系统集成内网 SSO 统一认证（hpjx 中间件）。
- 用户通过 SSO 登录后，系统自动获取用户信息（`request.SsoUserInfo`）。
- 管理员判定规则：SSO 角色（`roles_name`）中包含「兼职信息化管理员」的用户自动拥有审批权限，无需手动配置。

### 5.2 提交扩容申请
1. 访问「提交申请」页面。
2. 输入待扩容虚拟机的 IP 地址，点击「查询磁盘」。
3. 系统将调用 vCenter API 实时获取该虚拟机的磁盘状态。
4. 页面将展示所有磁盘的标签、SCSI 地址、当前容量、所属存储卷及该存储卷的剩余空间。
5. 风险预警：
   - 若检测到虚拟机存在快照，将显示红色警告，此时无法进行扩容。
   - 若虚拟机处于关机状态，将显示黄色提示，告知扩容后需手动执行文件系统调整。
6. 选择目标磁盘，输入扩容数值（限制 1-500GB）并填写原因。
7. 提交规则：
   - 申请容量 < 200GB 且物理存储空间充裕：系统自动审批通过，立即触发异步扩容。
   - 申请容量 ≥ 200GB：申请将进入人工审批队列。

### 5.3 查看历史记录
- 普通用户：仅能查看自己提交的申请记录及执行状态。
- 管理员：可查看全平台所有的申请记录。
- 功能：支持查看详细的执行日志和审批说明。

### 5.4 管理员审批
- 权限识别：管理员登录后，导航栏会显示「审批管理」菜单，并在醒目位置标注待处理任务数量。
- 操作流：
   - 批准：确认后触发后台异步任务。
   - 驳回：需填写理由，用户可在详情页查看驳回反馈。

### 5.5 任务执行流程（后台自动化）
1. Celery Worker 监听并领取任务。
2. vCenter 层面处理：
   - 校验快照状态及物理存储剩余容量。
   - 基于磁盘的 disk_key（SCSI 地址）进行精准定位，确保扩容目标准确无误。
3. 文件系统处理：
   - 若虚拟机为开机状态：自动连接 Ansible 控制节点，通过预设脚本完成系统分区扩容。
   - 若虚拟机为关机状态：仅完成 vCenter 磁盘扩容，任务标记成功并提示用户开机后处理。
4. 结果持久化：执行过程及最终结果均记录于数据库。

## 6. Django Admin 管理
- 路径：访问 /admin/。
- 功能：管理员可在此对扩容记录进行手动编辑、筛选或搜索。支持按 IP、申请人、磁盘标签进行检索，并提供状态过滤器。

## 7. 项目目录结构
```text
h8667_vmplatform/
├── manage.py                          # 项目管理脚本
├── requirements.txt                   # 依赖清单
├── packages/                          # 离线部署包
├── h8667_vmplatform/                  # 项目配置目录
│   ├── settings.py                    # 主配置文件
│   ├── urls.py                        # 全局路由
│   ├── celery.py                      # Celery 配置
│   └── wsgi.py                        # 服务入口
└── resize/                            # 业务应用目录
    ├── models.py                      # 数据模型（Task, DiskInfo等）
    ├── views.py                       # 业务逻辑视图
    ├── tasks.py                       # Celery 异步任务定义
    ├── forms.py                       # 数据校验表单
    ├── urls.py                        # 应用路由
    ├── admin.py                       # 后台管理配置
    ├── context_processors.py          # 模板上下文
    ├── services/                      # 核心服务层
    │   ├── vc_service.py              # vCenter 交互逻辑
    │   └── ansible_service.py         # Ansible 远程调用
    ├── static/resize/                 # 静态资源
    │   ├── css/bootstrap.min.css
    │   └── js/bootstrap.bundle.min.js
    └── templates/resize/              # 模板文件
        ├── base.html                  # 基础框架
        ├── index.html                 # 首页
        ├── submit.html                # 申请页面
        ├── history.html               # 历史记录
        ├── detail.html                # 详情展示
        └── admin_pending.html         # 审批管理
```

## 8. 常见问题 (FAQ)
- Q: Celery Worker 启动后任务不执行？
  - A: 请检查 Redis 服务状态，并确认 settings.py 中的 CELERY_BROKER_URL 是否指向正确的 Redis 地址。
- Q: 任务状态长时间处于「执行中」？
  - A: 检查 Celery Worker 是否崩溃。如 Worker 正常，请查看 Worker 终端日志确认是否由于网络超时导致的任务挂起。
- Q: vCenter 连接失败？
  - A: 校验 VCENTER_CONFIG 配置。确认服务器到 vCenter 管理 IP 的 443 端口网络畅通。
- Q: 页面没有样式，排版混乱？
  - A: 请确保执行了 python manage.py collectstatic 命令。检查 Nginx 或 Gunicorn 的静态文件代理配置。
- Q: 如何将普通用户设为管理员？
  - A: 管理员权限由 SSO 角色自动判定。用户的 roles_name 中包含「兼职信息化管理员」即自动拥有审批权限，无需手动配置。如需调整，请在 SSO 系统中修改用户角色。
- Q: 环境不匹配（如 Linux 运行 Windows 包）？
  - A: 请在具有相同架构的联网 Linux 环境中重新运行 pip download 命令准备离线包。
