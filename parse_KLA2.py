#! /usr/bin/python

# Potom zasyny B requements.txt
# pip3 install json

import requests
from bs4 import BeautifulSoup
import json
import urllib3
import re

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def parse_kla(KLA):  #  Теперь точно работает классно
    cve_id = []
    url = 'https://threats.kaspersky.com/ru/vulnerability/' + KLA
    response = requests.get(url, verify=False)
    soup = BeautifulSoup(response.text, 'lxml')
    items = soup.find_all('a', class_='gtm_vulnerabilities_cve')
    for i in items:
        buff = i.get_text()
        regex = re.search(r'CVE-\d{4}-\d{4,6}', buff)
        if(regex != None):
            cve_id.append(buff)
    return cve_id

def cve_replace(cve): #Допилить if на CVSSv3 и CVSSv2, а так работает классно
    API = 'API'
    url = 'https://services.nvd.nist.gov/rest/json/cve/1.0/' + cve + API
    response = requests.get(url, verify=False)
    parse_text = response.json()
    description = parse_text['result']['CVE_Items'][0]['cve']['description']['description_data'][0]['value']
    sol = parse_text['result']['CVE_Items'][0]['cve']['references']['reference_data']
    for n, solutions in enumerate(sol, start = 0):
        try:
            if(sol[n]['tags'][n] == 'Patch'):
                solution = 'Официальный патч: ' + solutions['url']
        except:
            solution = 'Подробная информация: ' + solutions['url']
    vector = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['vectorString']
    score = parse_text['result']['CVE_Items'][0]['impact']['baseMetricV3']['cvssV3']['baseScore']
    print(f'\n\n{cve}')
    print(f'Описание:\n{description}')
    print(f'{solution}')
    print(f'CVSSv3 Score: {score}')
    print(f'CVSSv3 vector: {vector}')

def read2list(file):
    kla_line = []
    ip_line = []
    with open(file, 'r', encoding="utf-8") as file:
        for i in file:
            buff = i.strip()
            regex_kla = re.findall(r'KLA\d{4,7}', buff)
            regex_ip = re.findall(r'\d{1,3}[.]\d{1,3}[.]\d{1,3}[.]\d{1,3}', buff)
            #print(regex)
            if (regex_kla != None):
                kla_line.append(regex_kla)
            if (regex_ip != None):
                ip_line.append(regex_ip)
    return kla_line
    return ip_line


if __name__ == "__main__":

    KLA = 'KLA11002'  # Допилить чтение из файла export_RV_JSON.py
    buff = parse_kla(KLA)
    for cve in buff:
        cve_replace(cve)
    '''
    file = '1.txt'
    print(read2list(file))
    '''
