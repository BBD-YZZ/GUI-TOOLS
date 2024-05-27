import time
from urllib.parse import urlparse, urljoin
import string
import random
import os,sys

def current_time():
    current_time = time.strftime('%Y-%m-%d %H:%M:%S',time.localtime(time.time()))
    return current_time

def write_log(logstr):
    timestr = current_time()
    logmsg = f"[{str(timestr)}]: {str(logstr)}\n"
    return logmsg

def re_stander_url(target):
        if not target.startswith("http://") and not target.startswith("https://"):
            target = "http://" + target
        else:
            target = target

        s_url = urlparse(target)
        port = s_url.port    
        if port is None:
            return f"{s_url.scheme}://{s_url.netloc}"
        elif port == 80:
            return f"{s_url.scheme}://{s_url.netloc}"
        elif port == 443:
            return f"https://{s_url.netloc}"
        else:
            return f"{s_url.scheme}://{s_url.hostname}:{port}"

def read_file_slice(filename):
    ua = []
    with open(filename, "r") as f:
        for line in f:
            ua.append(line.strip())
    return ua

def get_random_string(length):
    letters = string.ascii_letters
    return ''.join(random.choice(letters) for _ in range(length))

def get_random_all(length):
    characters = string.ascii_letters + string.digits + string.punctuation
    return ''.join(random.choice(characters) for _ in range(length))

def currentt_path():
    return os.path.abspath(__file__)

def parent_dir():
    return os.path.dirname(currentt_path())

def root_path():
    return os.path.dirname(os.path.abspath(sys.argv[0]))

def current_directory():
    return os.getcwd()