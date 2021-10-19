#!/usr/bin/python

import requests
import urllib3
import json
import time
import datetime

PROTOCOL = 'https'
RVISION = '10.10.10.10' #ip
USERNAME = 'Alex Rootovski`'
PASSWORD = 'roottoor'

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

#Начало сессии
s = requests.Session()
login = s.post(
	PROTOCOL + '://' + RVISION + '/login', 
	data={
		'username': USERNAME,
		'password': PASSWORD
	},
	verify=False
)
loginResult = login.text
#print(loginResult)



#Получение csrf
unixtime = str(time.mktime(datetime.datetime.now().timetuple()))[:-2]
check_csrf = s.get(
	PROTOCOL + '://' + RVISION + '/csrfToken?'+ unixtime,
	verify=False
)
csrf = json.loads(check_csrf.text)["_csrf"]
#print(csrf)

incidentsFilter =[{
	"property":"from","operator":"in","value":["ksc"]}, #фильтр на источник 
	{"property":"status","operator":"in","value":["opened"] #фильтр на статус
}]


devicesParams = {
    'page': 1,  # Пагинация, номер страницы
    'start': 0,  # Пагинация, позиция элемента с которого начать поиск
    'limit': 1,  # 99999 - вывод всех строк
    'filters': json.dumps(incidentsFilter)
}


#Запрос на выгрузку
export = s.get(
	PROTOCOL + '://' + RVISION + '/api/v2/am/vulnerabilities/devices',
	params=devicesParams,
	verify=False
)
exportResult = export.json()

print(json.dumps(exportResult, indent=2, sort_keys=True, ensure_ascii=False))
#Для вывода в файл раскоментить строки снизу
#buff = json.dumps(exportResult, indent=2, sort_keys=True, ensure_ascii=False)
#with open('122.json', 'w') as f:
#	f.write(buff)
