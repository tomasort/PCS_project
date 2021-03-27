from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import urlparse
from tld import get_tld
from nslookup import Nslookup
from ipaddress import ip_address
from contextlib import redirect_stdout
from whois import whois
import requests, argparse, sys, re, os, ipwhois, io


class Website:
    def __init__(self, url):
        parsed_url = urlparse(url)  # The structure of the parsed url is: scheme://netloc/path;parameters?query#fragment

        # Attributes based on the whole url
        self.url = parsed_url.geturl()
        count = Counter(self.url)
        self.url_num_dot = count['.']
        self.url_num_hiph = count['-']
        self.url_num_under = count['_']
        self.url_num_slash = count['/']
        self.url_num_quest = count['?']
        self.url_num_equ = count['=']
        self.url_num_att = count['@']
        self.url_num_amp = count['&']
        self.url_num_excl = count['!']
        self.url_num_spaces = count[' ']
        self.url_num_tilde = count['~']
        self.url_num_comma = count[',']
        self.url_num_plus = count['+']
        self.url_num_ast = count['*']
        self.url_num_pound = count['#']
        self.url_num_doll = count['$']
        self.url_num_perc = count['%']
        self.url_length = len(self.url)
        self.url_emails = self.get_email(self.url)
        try:
            self.tld = get_tld(self.url)
            self.tld_length = len(self.tld)
        except Exception as e:
            l = parsed_url.netloc.split(".")
            self.tld = l if l else None
            self.tld_length = len(self.tld) if self.tld else -1

        # Attributes based on the domain part of the url
        self.domain = parsed_url.netloc
        count = Counter(self.domain)
        self.dom_num_dot = count['.']
        self.dom_num_hiph = count['-']
        self.dom_num_under = count['_']
        self.dom_num_slash = count['/']
        self.dom_num_quest = count['?']
        self.dom_num_equ = count['=']
        self.dom_num_att = count['@']
        self.dom_num_amp = count['&']
        self.dom_num_excl = count['!']
        self.dom_num_spaces = count[' ']
        self.dom_num_tilde = count['~']
        self.dom_num_comma = count[',']
        self.dom_num_plus = count['+']
        self.dom_num_ast = count['*']
        self.dom_num_pound = count['#']
        self.dom_num_doll = count['$']
        self.dom_num_perc = count['%']
        self.dom_length = len(self.domain)
        self.dom_num_vowels = count['a'] + count['e'] + count['i'] + count['o'] + count['u']
        self.dom_is_ip = self.is_ipaddress(parsed_url.netloc)
        self.dom_server_or_client = True if "server" in self.domain.lower() or "client" in self.domain.lower() else False

        # Attributes based on the directory part of the url
        self.directory = self.get_directory(parsed_url.path)
        count = Counter(self.directory)
        self.dir_num_dot = count['.']
        self.dir_num_hiph = count['-']
        self.dir_num_under = count['_']
        self.dir_num_slash = count['/']
        self.dir_num_quest = count['?']
        self.dir_num_equ = count['=']
        self.dir_num_att = count['@']
        self.dir_num_amp = count['&']
        self.dir_num_excl = count['!']
        self.dir_num_spaces = count[' ']
        self.dir_num_tilde = count['~']
        self.dir_num_comma = count[',']
        self.dir_num_plus = count['+']
        self.dir_num_ast = count['*']
        self.dir_num_pound = count['#']
        self.dir_num_doll = count['$']
        self.dir_num_perc = count['%']
        self.dir_length = len(self.directory)

        # Attributes based on the file_name part of the url
        self.file_name = self.get_file_name(parsed_url.path)
        self.file_num_dot = count['.']
        self.file_num_hiph = count['-']
        self.file_num_under = count['_']
        self.file_num_slash = count['/']
        self.file_num_quest = count['?']
        self.file_num_equ = count['=']
        self.file_num_att = count['@']
        self.file_num_amp = count['&']
        self.file_num_excl = count['!']
        self.file_num_spaces = count[' ']
        self.file_num_tilde = count['~']
        self.file_num_comma = count[',']
        self.file_num_plus = count['+']
        self.file_num_ast = count['*']
        self.file_num_pound = count['#']
        self.file_num_doll = count['$']
        self.file_num_perc = count['%']
        self.file_length = len(self.file_name)

        # Attributes based on WHOIS

        dom = None
        # sys.stdout = open(os.devnull, 'w')
        f = io.StringIO()  # we are going to store stdout in f
        with redirect_stdout(f):
            dom = whois(parsed_url.netloc)
        out = f.getvalue()  # get the string from f into out
        error_pattern = re.compile(r'\bError.*')
        x = [i for i in out.split('\n') if error_pattern.match(i)]
        if len(x) > 0: print("There was an error in whois")
        self.dom_activation_date = dom.creation_date  # TODO: change this to days
        self.dom_expiration_date = dom.expiration_date  # TODO: change this to days
        self.dom_country = dom.country

        # Get info from IP address
        if self.dom_is_ip:  # the way we call whois depends on the format of the domain
            self.ip = parsed_url.netloc
        else:
            # If the domain is not in IP format find the IP address
            domain = "example.com"
            dns_query = Nslookup(dns_servers=["1.1.1.1"])
            ips_record = dns_query.dns_lookup(domain)
            if ips_record.answer:  # If the answer list is not empty
                self.ip = ips_record.answer[0]
            else:
                self.ip = None
        if self.ip:
            obj = ipwhois.IPWhois(self.ip)
            results = obj.lookup_rdap()
        # TODO: store the asn_ip
        # sys.stdout = sys.__stdout__
        page = self.fetch_page(self, url)
        self.content = page.content
        self.headers = page.headers

        self.scheme = parsed_url.scheme
        self.params = parsed_url.params
        self.fragments = parsed_url.fragments
        self.port = parsed_url.port

    def fetch_page(self, url):
        print("Fetching website")
        # TODO: check if the website has a tls/ssl certificate. get() raises an error if the site does not has SSL
        # The error is requests.exceptions.SSLError
        response = requests.get(url)
        if response.status_code == 200:
            print('Success!')
        elif response.status_code == 404:
            print('Not Found.')
            sys.exit(1)
        self.response_time = response.elapsed
        # TODO: figure out the number of redirects
        return BeautifulSoup(response.content, 'lxml')

    def get_email(self, url):
        pattern = re.compile("\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
        emails = pattern.findall(url)
        return emails

    def get_directory(self, path):
        return os.path.dirname(path)

    def get_file_name(self, path):
        return os.path.basename(path)

    def is_ipaddress(self, domain):
        try:
            ip_address(domain)
            return True
        except Exception as e:
            return False

    # TODO: find if the site is in the google index.
    # TODO: determine if the url has been shortened

    def features(self):
        # TODO: return a list of the features in the right order
        return




if __name__ == "__main__":
    w = Website("http://13.234.215.215/")
    u = Website("https://lojaonlinetimor.000webhostapp.com/")
    u = Website("http://vod.reliableiptv.com/images/spl_schedules/4cc73ad389754af37e7d3f4b079b981d/index.php?d16f368958a5dbdaaff735ef81ce40a5?dispatch=LDpjZWL1sxB96npRSaRn3Oq12JoBAY8lBxFBtqCVXd54BuVuEM")
