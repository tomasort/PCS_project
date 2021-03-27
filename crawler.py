import pandas as pd
import random
import requests
from bs4 import BeautifulSoup
import re
from collections import Counter
from website import Website

url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost...
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

class Crawler:

    # TODO: add concurrency
    def __init__(self, url, max_tries=2, levels=2):
        self.url = url
        self.urls = self.crawl(self.url, max_tries, levels)
        pass

    def crawl(self, url, max_tries=2, levels=2, num_links=10):
        if levels == 0:
            return []
        # Go through the website and find all the urls
        MISSING_SCHEMA = False
        tries = 0
        while True:
            try:
                response = requests.get(url, timeout=7)
                soup = BeautifulSoup(response.content, "lxml")
                if self.is_captcha(soup):
                    raise requests.exceptions.ConnectionError
                links = set()
                all_links = soup.findAll('a')
                if len(all_links)  > num_links:
                    random_urls = random.sample(soup.findAll('a'), num_links)
                else:
                    random_urls = all_links
                for link in random_urls:
                    cur_url = link.get('href')
                    print(cur_url)
                    if cur_url:
                        if re.match(url_regex, cur_url) is not None:
                            links.update(set(cur_url))
                            links.update(self.crawl(cur_url, levels=levels-1))
                            continue
                        if self.url[-1] == "/" and cur_url[0] == "/":
                            cur_url = f"{url}{cur_url[1:]}"
                        else:
                            cur_url = f"{url}{cur_url}"
                        if 'captcha' in cur_url:
                            continue
                        links.update(cur_url)

                if len(links) <= num_links:
                    return links
                else:
                    return random.sample(links, num_links)
            except requests.exceptions.MissingSchema as e:
                MISSING_SCHEMA = True
                url = f"https://{url}"
                continue
            except requests.exceptions.ConnectionError as e:
                # TODO: if we end up using proxies we need to change them here
                if tries <= 1 and MISSING_SCHEMA:
                    url = f"http://{self.url}"
                    MISSING_SCHEMA = False
                tries += 1
                if tries >= max_tries:
                    return []
                continue


    def get_urls(self):
        return self.urls

    def is_captcha(self, soup):
        # TODO: try more rules to test if a page is contains a captcha
        for html in soup.find_all("script"):
            if 'src' in html.attrs.keys() and "captcha" in html.attrs['src']:
                # return True
                pass
        return soup.find("input", id="recaptcha-token") is not None

