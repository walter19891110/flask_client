import psutil
import hashlib
import time
import requests
from requests_toolbelt import SSLAdapter


# 打印多网卡 mac 和 ip 信息
def get_ip_mac():
    ip_mac = dict()
    dic = psutil.net_if_addrs()
    adapter = dic['en0']
    for snic in adapter:
        if snic.family.name in {'AF_LINK', 'AF_PACKET'}:
            ip_mac['mac'] = snic.address
        elif snic.family.name == 'AF_INET':
            ip_mac['ip'] = snic.address

    print(ip_mac)
    ip_mac['ip'] = '192.168.0.101'
    return ip_mac


def web_client():

    # 获取设备ID和设备识别码
    print('终端启动，进行终端入网验证!')
    ip_mac = get_ip_mac()
    dev_data = {'devID': ip_mac['mac'], 'devIC': ip_mac['ip']}
    print(dev_data)

    # 设置HTTPS
    adapter = SSLAdapter('TLSv1.2')  # 设置证书验证方式为TLSv1.2
    r = requests.Session()
    r.mount('https://', adapter)  # 设置HTTPS的SSL适配器
    ca_file = '../certs/chain-ca.pem'  # 设置根证书

    # 终端入网验证
    dev_verify_api = 'https://127.0.0.1:5000/api/dev/dev_verify'
    # r = requests.post(dev_verify_api, json=dev_data, cert=('../certs/client.crt.pem', '../certs/client.key.pem'))  # 指定根证书
    r = requests.post(dev_verify_api, json=dev_data, verify=ca_file)  # 指定根证书

    if r.status_code == 200:
        print(r.json())
        ret_code = r.json()['ret_code']
        if ret_code != 0:
            print('终端入网验证失败, 错误代码:', ret_code)
            return ret_code
    else:
        print('请求错误，错误码:', r.status_code)
        return r.status_code
    print('终端入网验证成功，接入人机网!')
    #time.sleep(1)

    # 终端入网成功，进行身份认证
    print('终端入网成功，进行身份认证!')
    id_verify_api = 'https://127.0.0.1:5000/api/auth/id_verify'
    data = {"username": "wangjing", "type": 1, "data": "wangjing"}
    r = requests.post(id_verify_api, json=data, verify=ca_file)
    if r.status_code == 200:
        print(r.json())
        ret_code = r.json()['ret_code']
        if ret_code != 0:
            print('身份认证失败, 错误代码:', ret_code)
            return ret_code
    else:
        print('请求错误，错误码:', r.status_code)
        return r.status_code

    #time.sleep(1)

    # 身份认证成功，进行人机验证
    print('身份认证成功，进行人机验证!')
    user_dev_verify_api = 'https://127.0.0.1:5000/api/dev/user_dev_verify'
    data = {"devID": ip_mac['mac'], "username": "wangjing"}
    r = requests.post(user_dev_verify_api, json=data, verify=ca_file)
    if r.status_code == 200:
        print(r.json())
        ret_code = r.json()['ret_code']
        if ret_code != 0:
            print('人机验证失败, 错误代码:', ret_code)
            return ret_code
    else:
        print('请求错误，错误码:', r.status_code)
        return r.status_code
    #time.sleep(1)

    # 进行权限查询
    print('人机验证通过，进行权限查询!')
    #time.sleep(1)

    # 登录成功，进入桌面
    print('登录成功，更新登录状态，获取身份令牌，进入桌面!')
    login_success_api = 'https://127.0.0.1:5000/api/auth/login_success'
    data = {"username": "wangjing"}
    r = requests.put(login_success_api, json=data, verify=ca_file)
    if r.status_code == 200:
        print(r.json())
        ret_code = r.json()['ret_code']
        if ret_code != 0:
            print('更新登录状态失败, 错误代码:', ret_code)
            return ret_code
    else:
        print('请求错误，错误码:', r.status_code)
        return r.status_code

    # 保存身份令牌
    print('收到身份令牌，请保存!')


def performance_test():

    ca_file = '../certs/chain-ca.pem'  # 设置根证书
    while True:
        i = 0
        time_start = time.time()
        while i < 10:
            user_dev_verify_api = 'https://127.0.0.1:5000/api/dev/user_dev_verify'
            data = {"devID": devID, "username": "wangjing"}
            r = requests.post(user_dev_verify_api, json=data, verify=ca_file)
            i = i+1
        time_end = time.time()
        print('use time', time_end - time_start)


def test_dev_verify():

    ca_file = '../certs/chain-ca.pem'  # 设置根证书
    while True:
        i = 0
        time_start = time.time()
        while i < 10000:
            dev_verify_api = 'https://127.0.0.1:5000/api/dev/dev_verify'
            data = {'devID': "93e50ecb50de1f04af1252075f829661", 'devIC': "a541dddab6cb3ad680053f55559ad394"}
            #r = requests.post(id_verify_api, json=data, verify=ca_file)
            r = requests.post(dev_verify_api, json=data, verify=ca_file)
            i = i+1
        time_end = time.time()
        print('use time', time_end - time_start)

def test_dev_verify_noredis():

    ca_file = '../certs/chain-ca.pem'  # 设置根证书
    while True:
        i = 0
        time_start = time.time()
        while i < 10000:
            dev_verify_api = 'https://127.0.0.1:5000/api/dev/dev_verify_noredis'
            data = {'devID': "93e50ecb50de1f04af1252075f829661", 'devIC': "a541dddab6cb3ad680053f55559ad394"}
            #r = requests.post(id_verify_api, json=data, verify=ca_file)
            r = requests.post(dev_verify_api, json=data, verify=ca_file)
            i = i+1
        time_end = time.time()
        print('use time', time_end - time_start)

def test():
    ca_file = '../certs/chain-ca.pem'  # 设置根证书
    while True:
        i = 0
        time_start = time.time()
        while i < 10000:
            test_api = 'https://127.0.0.1:5000/api/test'
            data = {"a": 1, "b": 2}
            #r = requests.post(test_api, json=data)
            r = requests.post(test_api, json=data, verify=ca_file)
            i = i+1
        time_end = time.time()
        print('use time', time_end - time_start)

if __name__ == "__main__":
    web_client()
    #performance_test()
    #test_dev_verify_noredis()
    #test_dev_verify()
