运维分析模块 Ansible / 脚本目录

一、无需人工拷贝——运行前自动同步
    程序在每次执行 ops playbook 前，由 opsanalysis/services/sync.py 用 SFTP
    把本仓库三类文件自动推送到 Ansible 控制机（settings.ANSIBLE_CONFIG['HOST']，
    即 10.2.20.226），按内容指纹增量上传（未变化整批跳过）：

        本地(应用服务器)                      远端(控制机 REMOTE_BASE)
        opsanalysis/ansible/*.yml      →   /etc/ansible/playbooks/opsanalysis/*.yml
        opsanalysis/scripts/*.py       →   /etc/ansible/playbooks/opsanalysis/scripts/*.py
        opsanalysis/powershell/*.ps1   →   /etc/ansible/playbooks/opsanalysis/powershell/*.ps1

    REMOTE_BASE 默认 /etc/ansible/playbooks/opsanalysis，可用环境变量
    VMP_OPS_REMOTE_BASE 覆盖。运行时程序会把
        -e script_dir={REMOTE_BASE}/scripts
        -e ps_dir={REMOTE_BASE}/powershell
    显式传给 playbook，故不依赖 playbook 内 `playbook_dir/../scripts` 的默认相对路径。

    前置条件：
      1) 应用服务器能 SSH 到控制机（复用 firewall 模块同一套 ANSIBLE_CONFIG 账号/密码）；
      2) 该账号对 {REMOTE_BASE} 有写权限（能 mkdir/写文件）；
      3) 目标机 IP（nginx/jenkins/各应用机/Windows 机）必须登记在控制机 inventory
         （默认 /etc/ansible/hosts）里，并配好 ansible_user / 密码或私钥，
         否则 `hosts: "{{ target_host }}"` 匹配不到主机。

二、playbook 用途（全部只读采集/探测，绝不执行关机/重启/停服务/改配置）
    ops_impact_windows.yml       Windows 影响分析快照（win_copy Collect-OpsImpact.ps1 → win_shell）
    ops_impact_linux.yml         Linux 影响分析快照（copy collect_ops_impact.py → 探测 python 执行 → 清理）
    ops_discover_nginx.yml       只读解析 nginx.conf（upstream/server/access_log/proxy_pass）
    ops_discover_jenkins.yml     只读解析 jobs/*/config.xml（部署IP/git/supervisor程序/端口）
    ops_discover_supervisor.yml  只读发现 supervisor program（ini + supervisorctl status）
    ops_probe_dns.yml            只读 DNS 解析核对（nslookup/getent/ping）
    ops_probe_nginx_logs.yml     只读 nginx access/error 日志窗口统计（5xx / upstream 错误签名）
    ops_probe_jenkins_builds.yml 只读 Jenkins 最近构建（build.xml/changelog.xml）

    所有目标端脚本输出单行 JSON {"ok":true,"data":{...}}，
    由 firewall.services.ansible_executor.parse_host_json 解析。

三、手动验证（在控制机上；先确保目标 IP 在 inventory 内）
    cd /etc/ansible
    # 目标机连通性
    ansible <目标IP> -i hosts -m ping                 # Linux
    ansible <目标IP> -i hosts -m win_ping             # Windows
    # 直接跑一个只读发现（脚本目录已由自动同步建好）
    ansible-playbook -i hosts playbooks/opsanalysis/ops_discover_nginx.yml \
        -e target_host=192.168.2.250 \
        -e script_dir=/etc/ansible/playbooks/opsanalysis/scripts \
        -e nginx_conf=/usr/lib/nginx/conf/nginx.conf

四、可选覆盖（-e）
    -e script_dir=/path/to/scripts     指定 Linux 脚本目录（默认自动同步目录）
    -e ps_dir=/path/to/powershell      指定 Windows 脚本目录（默认自动同步目录）
    -e nginx_conf=...  -e jenkins_jobs_dir=...  -e domain=...  -e dns_servers=...
    -e access_logs=...  -e error_logs=...  -e window_min=30  -e jenkins_job=...
