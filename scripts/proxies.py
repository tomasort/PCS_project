from concurrent.futures.thread import ThreadPoolExecutor
from bs4 import BeautifulSoup
import requests, re, random, os, time
import asyncio
import json
from timeit import default_timer
from datetime import datetime
import os
import logging

MIN_WORKING_PROXIES = 20
MAX_WAIT_TIME = 7
CHECK_URLS = ['https://httpbin.org/ip', 'https://www.azlyrics.com/', 'https://httpbin.org/', 'https://httpbin.org/cookies', 'https://putsreq.com/0YX76rNsK3gkd7MKx750/inspect']


class Proxies:
    def __init__(self, data_file='data/scraping_headers.json',
                 pub_proxy="http://pubproxy.com/api/proxy?port=8080,3128,3129,51200,8811,8089,33746,8880,32302,80,8118,8081",
                 proxy_scrape="https://api.proxyscrape.com/?request=getproxies&proxytype=http&timeout=10000&country=all&ssl=all&anonymity=elite",
                 free_proxy_list="https://free-proxy-list.net/",
                 ssl_proxy_list="https://www.sslproxies.org/"):
        self.file_name = data_file
        with open(os.path.abspath(self.file_name), 'r') as f:
            self.data = json.load(f)
        if self.data:
            self.proxies = set(self.data['proxies'])
            self.working_proxies = set(self.data['working_proxies'])
        else:
            print("Missing input file for proxies and headers")
            raise(ValueError)
        self.pp_url = pub_proxy
        self.ps_url = proxy_scrape
        self.fpl_url = free_proxy_list
        self.ssl_url = ssl_proxy_list

        # Logging info
        self.logger = logging.getLogger(__name__)
        self.logger.setLevel(logging.DEBUG)
        self.formatter = logging.Formatter('%(asctime)s : %(filename)s : %(funcName)s : %(levelname)s : %(message)s')
        self.file_handler = logging.FileHandler(os.path.abspath('../log_data/proxies.log'))
        self.file_handler.setLevel(logging.DEBUG)
        self.file_handler.setFormatter(self.formatter)
        self.logger.addHandler(self.file_handler)

    def get_headers(self):
        headers = {
            "user-agent": random.choice(self.data['user_agents'][random.choice(list(self.data['user_agents'].keys()))]),
            "referer": random.choice(self.data['referrers']),
            "upgrade-Insecure-Requests": '0',
            "DNT": '1',
            "Connection": "keep-alive",
            "Accept": random.choice([
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3",
                "text/html", "text/html,application/xhtml+xml",
                "text/html,application/xhtml+xml,application/xml;q=0.9",
                "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng",
                "*/*",
                "text/plain; q=0.5, text/html, text/x-dvi; q=0.8, text/x-c",
                "text/*, text/plain, text/plain;format=flowed, */*",
                "text/*;q=0.3, text/html;q=0.7, text/html;level=1, text/html;level=2;q=0.4, */*;q=0.5"]),
            "Accept-Encoding": 'gzip, deflate, br',
            "Accept-Language": random.choice(["en-US,en;q=0.9,es;q=0.8", "en-US", "en-US,en;q=0.9", "*", "*;q=0.5", "en-US,en;q=0.5"])
        }
        return headers

    def get_proxy(self):
        while True:
            if len(self.working_proxies) < 5 or len(self.proxies) < MIN_WORKING_PROXIES * 2:
                asyncio.run(self.scrape_proxies())
            if len(self.working_proxies) < MIN_WORKING_PROXIES:
                while (len(self.working_proxies) < (MIN_WORKING_PROXIES + 10)):
                    try:
                        proxy = self.proxies.pop()
                        if not proxy:  # test for the empty string
                            continue
                        test_proxy = {'http': f"http://{proxy}", 'https': f"http://{proxy}"}
                        response = requests.get(random.choice(CHECK_URLS), proxies=test_proxy, timeout=MAX_WAIT_TIME)
                        self.working_proxies.add(proxy)
                    except KeyError as k:
                        print("There are no more proxies")
                        break
                    except Exception as e:
                        continue
            if self.working_proxies and self.proxies:
                break
        current_working_proxy = self.working_proxies.pop()
        self.proxies.add(current_working_proxy)
        return current_working_proxy

    async def scrape_proxies(self):
        with ThreadPoolExecutor(max_workers=4) as executor:
            loop = asyncio.get_event_loop()
            tasks = [self.get_free_proxy_list, self.get_ssl_proxy_list, self.get_pubproxies, self.get_proxy_scrape]
            group = asyncio.gather(*[loop.run_in_executor(executor, task) for task in tasks])
            fpl_proxies, ssl_proxies, pub_proxies, proxy_scrape = loop.run_until_complete(group)
            self.proxies.update(fpl_proxies, ssl_proxies, pub_proxies, proxy_scrape)

    def write_proxies(self):
        with open(self.file_name, 'w') as ofile:
            json.dump(self.data, ofile, indent=4)

    async def get_pubproxies(self, limit=10):
        proxies = []
        for i in range(limit):
            try:
                response = requests.get(self.pp_url)
                proxies.append(response.json()['data'][0]['ipPort'])  # append ip:port for each proxy
            except Exception as e:
                self.logger.error(f"Error fetching proxy from {self.pp_url}")
        self.logger.info(f"Fetched {len(proxies)} from {self.pp_url}")
        return proxies

    async def get_proxy_scrape(self):
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

    async def get_free_proxy_list(self):
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

    async def get_ssl_proxy_list(self):
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

    def check_proxies(self):
        pass

    def get_proxy(self):
        while True:
            if len(self.working_proxies) < 5 or len(self.proxies) < MIN_WORKING_PROXIES * 2:
                self.scrape_proxies()
            if len(self.working_proxies) < MIN_WORKING_PROXIES:
                while (len(self.working_proxies) < (MIN_WORKING_PROXIES + 10)):
                    try:
                        proxy = self.proxies.pop()
                        if not proxy:  # test for the empty string
                            continue
                        test_proxy = {'http': f"http://{proxy}", 'https': f"http://{proxy}"}
                        response = requests.get(random.choice(CHECK_URLS), proxies=test_proxy, timeout=MAX_WAIT_TIME)
                        self.working_proxies.add(proxy)
                    except KeyError as k:
                        print("There are no more proxies")
                        break
                    except Exception as e:
                        continue
            if self.working_proxies and self.proxies:
                break
        current_working_proxy = self.working_proxies.pop()
        self.proxies.add(current_working_proxy)
        return current_working_proxy


if __name__ == '__main__':
    prox = Proxies()
    print(prox.get_proxy())
    # prox.write_proxies()

