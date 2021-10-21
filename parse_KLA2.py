#! /usr/bin/python

import requests
from bs4 import BeautifulSoup

def parse_kla(KLA): #Работает классно
	cve_id = []
	url = 'https://threats.kaspersky.com/ru/vulnerability/' + KLA
	response = requests.get(url)
	soup = BeautifulSoup(response.text, 'lxml')
	items = soup.find_all('a', class_='gtm_vulnerabilities_cve')
	for i in items:
		buff = i.get_text()
		cve_id.append(buff)
	return cve_id

def cve_replace(cve): #Допилить запросы по полям
	url = 'https://nvd.nist.gov/vuln/detail/' + cve
	response = requests.get(url)
	print(response.status_code)
		
if __name__ == "__main__":
	KLA = 'KLA11000' #Допилить чтение из файла export_RV_JSON.py
	buff = parse_kla(KLA)
	for i in buff:
		cve_replace(i)
