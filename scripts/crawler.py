from urllib.parse import urldefrag, urljoin, urlparse
import random
import requests
from bs4 import BeautifulSoup
import re
from scripts.proxies import Proxies


url_regex = re.compile(
        r'^(?:http|ftp)s?://' # http:// or https://
        r'(?:(?:[A-Z0-9](?:[A-Z0-9-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9-]{2,}\.?)|' #domain...
        r'localhost|' #localhost... probably not useful in this case
        r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})' # ...or ip
        r'(?::\d+)?' # optional port
        r'(?:/?|[/?]\S+)$', re.IGNORECASE)

# TODO: add concurrency
class Crawler:
    """Class for recursively crawl the pages in a specific URL provided by the user"""

    def __init__(self, url, max_tries=2, levels=2):
        self.url = url
        self.urls = self.crawl(self.url, max_tries, levels)
        pass

    def crawl(self, url, max_tries=2, levels=2, num_links=10):
        """This function goes through the contents of the Page specified by the URL and finds and the URL in it
        Then it recursively does the same thing on each URL"""
        print(f"Crawling {url}")
        if levels == 0:
            return []
        # Go through the website and find all the urls
        MISSING_SCHEMA = False
        tries = 0
        while True:
            try:
                p = Proxies()
                print(f"Trying to Fetch {url} num_of_times={tries}")
                headers = p.get_headers()
                response = requests.get(url, timeout=10, headers=headers, allow_redirects=True, verify=False)
                if response.status_code == 200:
                    print(f'Success! {url}')
                elif response.status_code == 404:
                    print('Page Not Found.')
                else:
                    print('Status code: ', response.status_code)
                soup = BeautifulSoup(response.text, "lxml")
                if self.is_captcha(soup):
                    print(f"Captcha Found in {url}")
                    raise requests.exceptions.ConnectionError
                links = set()
                all_links = soup.findAll('a')
                print(f"Found {len(all_links)} links")
                if len(all_links) > num_links+8:
                    random_urls = random.sample(all_links, num_links+8)
                else:
                    random_urls = all_links
                for link in random_urls:
                    cur_url = link.get('href')
                    # print(cur_url)
                    if cur_url:
                        if re.match(url_regex, cur_url) is not None and urlparse(url).netloc != urlparse(cur_url).netloc and urlparse(url).netloc != '':
                            links.update([cur_url])
                            links.update(self.crawl(cur_url, levels=levels-1))  # crawl cur_url
                            continue
                        else:  # cur_url must be a relative url
                            try:
                                if urlparse(url).netloc == '':
                                    print(f"it must be a relative {cur_url}")
                                    urljoin(urldefrag(url)[0], cur_url)
                            except Exception as e:
                                pass
                if len(links) <= num_links:
                    return links
                else:
                    return random.sample(links, num_links)
            except requests.exceptions.MissingSchema as e:
                print("No Scheme")
                MISSING_SCHEMA = True
                url = f"https://{url}"
                continue
            except requests.exceptions.ConnectionError as e:
                print("Connection error")
                # TODO: if we end up using proxies we need to change them here
                if tries <= 1 and MISSING_SCHEMA:
                    url = f"http://{self.url}"
                    MISSING_SCHEMA = False
                tries += 1
                if tries >= max_tries:
                    return []
                continue
            except Exception as e:
                print("some weird error")
                break


    def get_urls(self):
        return self.urls

    def is_captcha(self, soup):
        """This function tests if the page is a captcha page or not"""
        # TODO: try more rules to test if a page is contains a captcha
        for html in soup.find_all("script"):
            if 'src' in html.attrs.keys() and "captcha" in html.attrs['src']:
                # return True
                pass
        return soup.find("input", id="recaptcha-token") is not None

