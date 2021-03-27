from bs4 import BeautifulSoup
import requests, re, random, os, time
import asyncio
import json
from timeit import default_timer
from datetime import datetime
import os
import logging


class Proxies:
    def __init__(self, data_file='data/scraping.json',
                 pubproxy="http://pubproxy.com/api/proxy?port=8080,3128,3129,51200,8811,8089,33746,8880,32302,80,8118,8081",
                 proxyscrape="https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all&ssl=all&anonymity=elite",
                 free_proxy_list="https://free-proxy-list.net/",
                 sslproxies="https://www.sslproxies.org/"):
        self.file_name = data_file
        with open(os.path.abspath(self.file_name), 'r') as f:
            self.data = json.load(f)
        self.pp_url = pubproxy
        self.ps_url = proxyscrape
        self.fpl_url = free_proxy_list
        self.ssl_url = sslproxies

        # Logging info
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter('%(asctime)s : %(filename)s : %(funcName)s : %(levelname)s : %(message)s')
        self.file_handler = logging.FileHandler(os.path.abspath('log_data/proxies.log'))
        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.file_handler)

    def get_header(self):
        header = {
            "user-agent": random.choice(random.choice(self.data['user_agents'])),
            "referer": random.choice(self.data['referer']),
            "upgrade-Insecure-Requests": '0',
            "DNT": 1,
            "Connection": "keep-alive",
            "Accept": 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            "Accept-Encoding": 'gzip, deflate, br', 'Accept-Language': 'en-US,en;q=0.5'
        }
        return header

    def get_proxy(self):
        if len(self.data['working_proxies']) == 0:
            self.scrape_proxies()
        if len(self.data['working_proxies']) < 10:
            # TODO: test several proxies and determine if they should be deleted or moved into working_proxies
            i = 0
            while(len(self.data['working_proxies']) < 10 and i < len(self.data['proxies'])):
                proxy = self.data['proxies'][i]
                if not proxy:
                    i += 1
                    continue
                p = {'http': f"http://{proxy}", 'https': f"http://{proxy}"}
                try:
                    response = requests.get("https://httpbin.org/ip", proxies=p, timeout=5)
                    # print(response.content)
                    self.data['working_proxies'].append(proxy)
                except Exception as e:
                    pass
                i += 1
            if i >= len(self.data['proxies']):
                self.data['proxies'] = []
                self.scrape_proxies()
                return self.get_proxy()
        return random.choice(self.data['working_proxies'])

    def scrape_proxies(self):
        fpl_proxies = self.get_free_proxy_list()
        ssl_proxies = self.get_ssl_proxy_list()
        pubproxies = self.get_pubproxies()
        proxyscrape = self.get_proxy_scrape()
        self.data['proxies'] += (fpl_proxies + ssl_proxies + pubproxies + proxyscrape)

    def write_proxies(self):
        with open(self.file_name, 'w') as ofile:
            json.dump(self.data, ofile, indent=4)

    def get_pubproxies(self, limit=10):
        proxies = []
        for i in range(limit):
            try:
                response = requests.get(self.pp_url)
                proxies.append(response.json()['data'][0]['ipPort'])  # append ip:port for each proxy
            except Exception as e:
                self.logger.error(f"Error fetching proxy from {self.pp_url}")
        self.logger.info(f"Fetched {len(proxies)} from {self.pp_url}")
        return proxies

    def get_proxy_scrape(self):
        proxies = []
        try:
            response = requests.get(self.ps_url)
            if response.status_code == 200:
                proxies = response.text.split('\r\n')
                self.logger.info(f"Fetched {len(proxies)} from {self.ps_url}")
            else:
                self.logger.error(f"Status Code {response.status_code} from ProxyScrape .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from ProxyScape: {self.ps_url} {e}")
        return proxies

    def get_free_proxy_list(self):
        proxies = []
        try:
            response = requests.get(self.fpl_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "lxml")
                textarea = soup.find('textarea').text
                proxies = re.findall('\d+\.\d+\.\d+\.\d+\:\d+', textarea)
                self.logger.info(f"Fetched {len(proxies)} from {self.fpl_url}")
            else:
                self.logger.error(f"Status Code {response.status_code} from free-proxy-list .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from free-proxy-list: {self.fpl_url} {e}")
        return proxies

    def get_ssl_proxy_list(self):
        try:
            response = requests.get(self.ssl_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "lxml")
                textarea = soup.find('textarea').text
                proxies = re.findall('\d+\.\d+\.\d+\.\d+\:\d+', textarea)
                self.logger.info(f"Fetched {len(proxies)} from {self.ssl_url}")
                return proxies
            else:
                self.logger.error(f"Status Code {response.status_code} from free-proxy-list .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from free-proxy-list: {self.ssl_url} {e}")
        return []


class AsyncProxies(Proxies):
    def __init__(self, *args, **kwargs):
        super(AsyncProxies, self).__init__(*args, **kwargs)

    def get_proxy(self):
        if len(self.data['working_proxies']) == 0:
            self.scrape_proxies()
        if len(self.data['working_proxies']) < 10:
            i = 0
            while(len(self.data['working_proxies']) < 10 and i < len(self.data['proxies'])):
                proxy = self.data['proxies'][i]
                if not proxy:
                    i += 1
                    continue
                p = {'http': f"http://{proxy}", 'https': f"http://{proxy}"}
                try:
                    response = requests.get("https://httpbin.org/ip", proxies=p, timeout=5)
                    # print(response.content)
                    self.data['working_proxies'].append(proxy)
                except Exception as e:
                    pass
                i += 1
            if i >= len(self.data['proxies']):
                self.data['proxies'] = []
                self.scrape_proxies()
                return self.get_proxy()
        return random.choice(self.data['working_proxies'])

    def scrape_proxies(self):
        fpl_proxies = self.get_free_proxy_list()
        ssl_proxies = self.get_ssl_proxy_list()
        pubproxies = self.get_pubproxies()
        proxyscrape = self.get_proxy_scrape()
        self.data['proxies'] += (fpl_proxies + ssl_proxies + pubproxies + proxyscrape)

    def write_proxies(self):
        with open(self.file_name, 'w') as ofile:
            json.dump(self.data, ofile, indent=4)

    def get_pubproxies(self, limit=10):
        proxies = []
        for i in range(limit):
            try:
                response = requests.get(self.pp_url)
                proxies.append(response.json()['data'][0]['ipPort'])  # append ip:port for each proxy
            except Exception as e:
                self.logger.error(f"Error fetching proxy from {self.pp_url}")
        self.logger.info(f"Fetched {len(proxies)} from {self.pp_url}")
        return proxies

    def get_proxy_scrape(self):
        proxies = []
        try:
            response = requests.get(self.ps_url)
            if response.status_code == 200:
                proxies = response.text.split('\r\n')
                self.logger.info(f"Fetched {len(proxies)} from {self.ps_url}")
            else:
                self.logger.error(f"Status Code {response.status_code} from ProxyScrape .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from ProxyScape: {self.ps_url} {e}")
        return proxies

    def get_free_proxy_list(self):
        proxies = []
        try:
            response = requests.get(self.fpl_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "lxml")
                textarea = soup.find('textarea').text
                proxies = re.findall('\d+\.\d+\.\d+\.\d+\:\d+', textarea)
                self.logger.info(f"Fetched {len(proxies)} from {self.fpl_url}")
            else:
                self.logger.error(f"Status Code {response.status_code} from free-proxy-list .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from free-proxy-list: {self.fpl_url} {e}")
        return proxies

    def get_ssl_proxy_list(self):
        try:
            response = requests.get(self.ssl_url)
            if response.status_code == 200:
                soup = BeautifulSoup(response.content, "lxml")
                textarea = soup.find('textarea').text
                proxies = re.findall('\d+\.\d+\.\d+\.\d+\:\d+', textarea)
                self.logger.info(f"Fetched {len(proxies)} from {self.ssl_url}")
                return proxies
            else:
                self.logger.error(f"Status Code {response.status_code} from free-proxy-list .. ")
        except Exception as e:
            self.logger.error(f"Error fetching proxy from free-proxy-list: {self.ssl_url} {e}")
        return []

if __name__ == '__main__':
    prox = Proxies()
    print(prox.get_proxy())


if __name__ == '__main__':
    prox = Proxies()
    print(prox.get_proxy())

