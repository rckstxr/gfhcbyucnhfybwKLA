#! /usr/bin/python

#Potom zasyny B requements.txt
#pip3 install json
#pip3 install googletrans

import requests
from bs4 import BeautifulSoup
import json
import urllib3
from googletrans import Translator

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning) 

def parse_kla(KLA): #Работает классно
	cve_id = []
	url = 'https://threats.kaspersky.com/ru/vulnerability/' + KLA
	response = requests.get(url, verify=False)
	soup = BeautifulSoup(response.text, 'lxml')
	items = soup.find_all('a', class_='gtm_vulnerabilities_cve')
	for i in items:
		buff = i.get_text()
		cve_id.append(buff)
	return cve_id

def cve_replace(cve):
	#Hyinya s proxy
	#translator = Translator() 
	url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve + API
	response = requests.get(url, verify=False)
	parse_text = response.json()
	desc = parse_text['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
	#Hyinya s proxy
	#description = translator.translate(desc, dest='ru') 
	solutions = parse_text['result']['CVE_Items'][0]['cve']['references']['reference_data'][0]['url']
	vector = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString']
	score = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
	print(f'\n\n{cve}')
	print(f'Описание:\n{desc}')
	print(f'Решение:\n{solutions}')
	print(f'CVSSv3 Score: {score}')
	print(f'CVSSv3 vector: {vector}')
		
if __name__ == "__main__":
	KLA = 'KLA11000' #Допилить чтение из файла export_RV_JSON.py
	buff = parse_kla(KLA)
	for cve in buff:
		cve_replace(cve)
