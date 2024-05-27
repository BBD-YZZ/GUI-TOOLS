import requests

def check_proxy_uses(proxy):
    testurl = "https://www.baidu.com/"
    headers = {"User-Agent": "Mozilla/5.0"}  # 响应头
    try:
        requests.packages.urllib3.disable_warnings()
        test = requests.get(testurl, headers=headers, timeout=5, verify=False, proxies=proxy)
        if test.status_code == 200:
            return f"get: www.baidu.com, code:{test.status_code}, 代理可用！", True            
    except Exception as e:
        return f"代理{proxy}不可用，请检查更换代理！", False