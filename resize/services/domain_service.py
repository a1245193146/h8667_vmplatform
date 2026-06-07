"""Domain configuration service."""

import logging
from pathlib import Path

import certifi
import OpenSSL.crypto
import requests
from certsrv import Certsrv
from pypsrp.client import Client


logger = logging.getLogger(__name__)


def set_nginx_1(domain, ip, port):
    res = {
        'status1': 'False',  # 反向代理是否成功
        'status2': 'False',  # 负载均衡是否成功
        'status3': 'False',  # DNS是否配置成功
        'status4': 'False',  # SSL证书是否配置成功
        'mess': []
    }
    path = r"\\filesync\share\files\ssl"
    dir_ssl = Path(path)
    ssl_res, ssl_err = gen_cert(domain=domain)
    try:
        if ssl_res:
            cert, key = ssl_res[0], ssl_res[1]  # 提取证书和私钥
            with open(dir_ssl.joinpath('{}.crt'.format(domain)), 'w') as f:
                f.write(cert)
            with open(dir_ssl.joinpath('{}.key'.format(domain)), 'w') as f:
                f.write(key)
            res['status4'] = 'True'
    except Exception as e:
        res['status4'] = 'False'
        res['mess'].append(e)
    _domain = domain.replace('.4307.com', '')
    dns_res, err = dns_create_a_record(domain=_domain, ip='192.168.2.250', zone='4307.com')

    if dns_res:
        res['status3'] = 'True'
    else:
        res['mess'].append('DNS已经存在！')

    if '4307' not in domain:
        res['mess'].append('不合法域名！')
        return res

    if ip is None or ip == '' or port is None or port == '':
        return res

    token_url = 'http://192.168.2.250:8080/token/getToken?name=root&pass=Admin123'
    headers = {
        'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46'
    }
    token = requests.request("GET", token_url, headers=headers, timeout=30).json().get("obj").get("token")

    # 查询是否已经存在反向代理
    search_url = f"""http://192.168.2.250:8080/api/server/getPage?keywords={domain}"""
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
        'token': f"{token}",
    }
    search_response = requests.get(url=search_url, headers=headers, timeout=30)


    if len(search_response.json()['obj']['records']) > 0:
        print('已经存在代理')
        res['mess'].append('已经存在代理')
    else:
        # 配置443端口和80端口的代理
        set_nginx_server(token=token, domain=domain, port=443)
        set_nginx_server(token=token, domain=domain, port=80,ssl=0)
        res['status1'] = 'True'

    search_stream_url = f"""http://192.168.2.250:8080/api/upstream/getPage?keywords={domain}"""

    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
        'token': f"{token}",
    }

    search_stream_res = requests.get(url=search_stream_url, headers=headers, timeout=30).json()
    stream_id = ''
    if len(search_stream_res['obj']['records']) > 0:
        print('已经存在负载均衡')
        res['mess'].append('已经存在负载均衡')
        stream_id = search_stream_res['obj']['records'][0]['id']
    else:
        #  创建负载均衡
        stream_url = f"""http://192.168.2.250:8080/api/upstream/insertOrUpdate?name={domain}"""
        stream_response = requests.get(url=stream_url, headers=headers, timeout=30).json()
        stream_id = stream_response['obj']['id']

        # 配置负载均衡
        stream_weight_url = f"""http://192.168.2.250:8080/api/upstream/insertOrUpdateServer?upstreamId={stream_id}&server={ip}&port={port}&weight=1&failTimeout=10&maxFails=1"""
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
            'token': f"{token}",
        }
        weight_response = requests.get(url=stream_weight_url, headers=headers, timeout=30)
        res['status2'] = 'True'
        resp = weight_response.json()

    check_url = 'http://192.168.2.250:8080/api/nginx/check'

    check_res = requests.get(url=check_url, headers=headers, timeout=30).json()
    if check_res['success'] is False:
        res['status5'] = 'False'
        return res
    replace_url = 'http://192.168.2.250:8080/api/nginx/replace'
    replace_res = requests.get(url=replace_url,headers=headers, timeout=30).json()
    if replace_res['success'] is False:
        res['status6'] = 'False'
        return res
    load_url = 'http://192.168.2.250:8080/api/nginx/reload'
    load_res = requests.get(url=load_url,headers=headers, timeout=30).json()
    if load_res['success'] is False:
        res['status7'] = 'False'
        return res
    return res


def set_nginx_server(token, domain, port,ssl=1):
    server_url = f"""http://192.168.2.250:8080/api/server/insertOrUpdate?serverName={domain}&listen={port}&key=/opt/sharefiles/files/ssl/{domain}.key&pem=/opt/sharefiles/files/ssl/{domain}.crt&ssl={ssl}"""
    headers = {
        'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
        'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
        'token': f"{token}",
    }
    server_response = requests.get(url=server_url, headers=headers, timeout=30).json()

    if server_response['success']:
        server_id = server_response['obj']['id']
        # 注意，这里能跑就不要动，会有莫名其妙的bug，日志的路径，最好去nginx那边复制过来！！！！！！
        param_url = f"""http://192.168.2.250:8080/api/param/insertOrUpdate?serverId={server_id}&name=access_log&value=/home/nginxWebUI/log/{domain}-access.log main"""
        param_url = param_url.encode('US-ASCII')
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
            'token': f"{token}",
        }
        param_response = requests.get(url=param_url, headers=headers, timeout=30)

        location_url = f"""http://192.168.2.250:8080/api/server/insertOrUpdateLocation?serverId={server_id}&path=/&headerHost=$host&value=http://{domain}"""
        headers = {
            'Content-Type': 'application/x-www-form-urlencoded;charset=utf-8',
            'Cookie': 'SOLONID=678aff7e8c2f405d8abdde048e602c46',
            'token': f"{token}",
        }
        location_response = requests.get(url=location_url, headers=headers, timeout=30)


# copy自陈沛容的hpjx-core-controlcenter
def dns_create_a_record(domain, zone, ip, ttl=3600):
    def get_err(self, code):
        err = self.DNS_ERR.get(code)
        if err:
            return err[1]
        else:
            raise Exception('这个错误代码【{}】没有解释'.format(code))
    """
    创建一个新的A主机

    # 一个域名可以有多个ip指向

    # 增加域名记录
    dnscmd /RecordAdd 4307.com abc 3600 A 192.168.188.93
    dnscmd /RecordAdd 4307.com abc 3600 A 192.168.188.55
    dnscmd /RecordAdd 4307.com abc 3600 A 192.168.2.193
    """
    err = None
    res = None

    _domain = domain
    _ip = ip
    _zone = zone

    with Client(server='Nettrix14.hp4307.com', port=5985, username='bakadmin', password='1qazxsw@',
                ssl=False) as client:
        # 获取所有的顶级域
        cmd = 'dnscmd /RecordAdd {} "{}" {} A {}'.format(_zone, _domain or '@', ttl, _ip)
        print(cmd)
        # cmd = 'dnscmd /RecordAdd 4307.com abc 3600 A 192.168.188.55'.format(_zone, ttl, _ip)
        stdout, stderr, cmd_err = client.execute_cmd(cmd, encoding='GBK')
        print(stdout, stderr, cmd_err)
        if cmd_err == 0:  # 没有错误
            # res = self.dnscmd_err_re.match(stdout)
            # if res:  # 如果解析出内容,表示有错误输出
            #     err = res.groupdict()
            #     return False, err
            # else:
            #     return True, err
            return True, err
        else:  # 如果有错误
            err = stdout
            return False, err


def gen_cert(domain):
    cert_server = Certsrv('http://Nettrix14.hp4307.com', 'bakadmin', '1qazxsw@', auth_method='ntlm',
            cafile=certifi.where())

    """生成指定域名的证书"""
    err = None
    res = None

    DN = domain

    # 生成私钥
    key = OpenSSL.crypto.PKey()
    key.generate_key(OpenSSL.crypto.TYPE_RSA, 2048)

    # 生成csr
    req = OpenSSL.crypto.X509Req()
    req.get_subject().CN = DN  # 域名
    san_str = f'DNS: {DN}'
    san = san_str.encode()
    san_extension = OpenSSL.crypto.X509Extension(b"subjectAltName", False, san)
    req.add_extensions([san_extension])

    req.set_pubkey(key)
    req.sign(key, "sha256")

    # 从adcs获取证书
    pem_req = OpenSSL.crypto.dump_certificate_request(OpenSSL.crypto.FILETYPE_PEM, req)
    pem_cert = cert_server.get_cert(pem_req, "WebServer")
    pem_key = OpenSSL.crypto.dump_privatekey(OpenSSL.crypto.FILETYPE_PEM, key)
    _cert = pem_cert.decode()
    _key = pem_key.decode()
    # print('Cert:\n{}'.format(pem_cert.decode()))
    # print('Key:\n{}'.format(pem_key.decode()))
    res = (_cert, _key)
    return res, err


def execute_domain_config(domain, ip, port):
    """Entry point for Celery task. Calls set_nginx_1 and returns result dict."""
    return set_nginx_1(domain=domain, ip=ip, port=port)
