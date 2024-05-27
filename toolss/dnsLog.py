import requests
import random

headers = {
    'User-Agent':'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/102.0.0.0 Safari/537.36'
}

def dnslog_sessid():
    url = f"http://47.244.138.18/getdomain.php?t={random.random()}"
    res = requests.get(url=url, headers=headers, timeout=10)
    get_cookie = res.cookies.get_dict()
    for k,v in get_cookie.items():
        cookie = f"{k}={v}"
    info = {"domain": res.text, "cookie":cookie}
    return info

def get_dnslog_rs(info):
    dns = info["domain"]
    # domain = f"{id}.{dns}"
    cookie = info["cookie"]
    url = f'http://www.dnslog.cn/getrecords.php?t={random.random()}'
    headers.update({"Cookie":cookie})
    r = requests.get(url=url, headers=headers, timeout=10)
    print(r.text)
    if dns in r.text:
        return True, dns
    else:
        return False, ""