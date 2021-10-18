from selenium import webdriver
from selenium.webdriver.opera.options import Options
from bs4 import BeautifulSoup
import os
import re
import csv


class KLAParser:


    def read_kla_file(self, kla_list):
        kla_list = input("file CSV: ")
        with open(kla_list, 'r') as input_list:
            cve_list = csv.reader(input_list)
        return cve_list


    def scraping(self, kla):
        opera_options = Options()
        opera_options.add_argument("--headless")
        opera_options.add_argument("--no-sandbox")
        driver = webdriver.Opera(executable_path=os.path.abspath("C:\Program Files\Opera\launcher.exe"), opera_options=opera_options)
        url = "https://threats.kaspersky.com/ru/vulnerability/" + kla
        driver.get(url)
        html = driver.page_source
        driver.close()
        return BeautifulSoup(html, 'html.parser')

      
    def get_kla_from_kla_list(self, cve_list_file):
        kla_list = self.read_kla_file(cve_list_file)
        kla_pages = {"pages":[]}
        for kla in kla_list:
