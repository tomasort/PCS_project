from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import urlparse
import argparse
import requests
import sys
import re


# TODO: store the domain_spf (whatever that means)
# TODO: store the asn_ip
# TODO: determine if the url has been shortened


class Website:
    def __init__(self, url):
        # The structure of the parsed url is: scheme://netloc/path;parameters?query#fragment
        self.response_time = None
        page = self.fetch(url)
        parsed_url = urlparse(url)
        self.url = parsed_url.geturl()
        self.content = page.content
        self.headers = page.headers
        self.scheme = parsed_url.scheme
        self.netloc = parsed_url.netloc  # network location
        self.path = parsed_url.path
        self.params = parsed_url.params
        self.query = parsed_url.query
        self.fragments = rsed_url.fragments
        self.port = parsed_url.port
        count = Counter(self.url)
        self.num_att = count['@']
        self.num_plus = count['+']
        self.num_ast = count['*']
        self.num_pound = count['#']
        self.num_doll = count['$']
        self.num_perc = count['%']
        self.num_equ = count['=']
        self.num_quest = count['?']
        self.num_slash = count['/']
        self.num_dot = count['.']
        self.num_hiph = count['-']
        self.num_under = count['_']
        self.url_emails = get_email(self.url)


    def fetch(url):
        print("Fetching website")
        response = requests.get(url)
        if response.status_code == 200:
            print('Success!')
        elif response.status_code == 404:
            print('Not Found.')
            sys.exit(1)
        self.response_time = response.elapsed
        # TODO: figure out the number of redirects
        # TODO: check if the website has a tls/ssl certificate
        return BeautifulSoup(response.content, 'lxml')


    def get_email(url):
        pattern = re.compile("\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
        emails = pattern.findall(url)
        return emails

    # TODO: find if the site is in the google index
    # TODO: store the time_domain_activation
    # TODO: store the time domain expiration






if __name__ == '__main__':
    # extract the command line arguments
    parser = argparse.ArgumentParser(description='Process urls') 
    parser.add_argument('filename')
    args = parser.parse_args()
    print("Feature Extraction")
    url = args.filename
    # Fetch the website and extract the features
    w = Website(url)
