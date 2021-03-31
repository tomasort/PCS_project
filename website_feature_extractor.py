from bs4 import BeautifulSoup
import datetime
from collections import Counter
from urllib.parse import urlparse, parse_qs
from nslookup import Nslookup
from ipaddress import ip_address
from contextlib import redirect_stdout
from whois import whois
import requests, sys, re, os, ipwhois, io, tld
from sklearn.feature_extraction.text import CountVectorizer




class WebsiteFeatureExtractor:

    def __init__(self, url):
        parsed_url = urlparse(url)  # The structure of the parsed url is: scheme://netloc/path;parameters?query#fragment
        # Attributes based on the whole url
        self.url = parsed_url.geturl()
        count = Counter(self.url)
        self.url_num_dot = count['.']
        self.url_num_hyphen = count['-']
        self.url_num_underline = count['_']
        self.url_num_slash = count['/']
        self.url_num_quest = count['?']
        self.url_num_equ = count['=']
        self.url_num_at = count['@']
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
        url_email_addresses = self.get_email(self.url)
        self.url_emails = True if url_email_addresses else False
        # self.url_num_emails = len(url_email_addresses)

        # Attributes based on the domain part of the url
        self.domain = parsed_url.netloc
        count = Counter(self.domain)
        self.dom_num_dot = count['.']
        self.dom_num_hyphen = count['-']
        self.dom_num_underline = count['_']
        self.dom_num_slash = count['/']
        self.dom_num_quest = count['?']
        self.dom_num_equ = count['=']
        self.dom_num_at = count['@']
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
        self.dom_num_vowels = count['a'] + count['e'] + count['i'] + count['o'] + count['u']
        self.dom_length = len(self.domain)
        self.dom_is_ip = self.is_ipaddress(parsed_url.netloc)
        self.dom_contains_server_or_client = True if "server" in self.domain.lower() or "client" in self.domain.lower() else False
        self.dom_spf = None

        # Attributes based on the directory part of the url
        self.directory = self.get_directory(parsed_url.path)
        count = Counter(self.directory)
        self.dir_num_dot = count['.']
        self.dir_num_hyphen = count['-']
        self.dir_num_underline = count['_']
        self.dir_num_slash = count['/']
        self.dir_num_quest = count['?']
        self.dir_num_equ = count['=']
        self.dir_num_at = count['@']
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
        # we could also test for the file extension
        count = Counter(self.file_name)
        self.file_num_dot = count['.']
        self.file_num_hyphen = count['-']
        self.file_num_underline = count['_']
        self.file_num_slash = count['/']
        self.file_num_quest = count['?']
        self.file_num_equ = count['=']
        self.file_num_at = count['@']
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


        # Attributes based on the query part of the url
        self.param_string = parsed_url.query # there is a discrepancy with the data (from the paper) and the way urlparse parses the url
        self.params = parse_qs(self.param_string)
        count = Counter(self.param_string)
        self.params_num_dot = count['.']
        self.params_num_hyphen = count['-']
        self.params_num_underline = count['_']
        self.params_num_slash = count['/']
        self.params_num_quest = count['?']
        self.params_num_equ = count['=']
        self.params_num_at = count['@']
        self.params_num_amp = count['&']
        self.params_num_excl = count['!']
        self.params_num_spaces = count[' ']
        self.params_num_tilde = count['~']
        self.params_num_comma = count[',']
        self.params_num_plus = count['+']
        self.params_num_ast = count['*']
        self.params_num_pound = count['#']
        self.params_num_doll = count['$']
        self.params_num_perc = count['%']
        self.params_length = len(self.param_string)
        self.params_tld_present = self.get_tld(self.param_string);  # find out if there is a tld in the param_string variabe
        self.params_nums = len(self.params)

        # Attributes based on TLD (top level domain)
        try:
            self.tld = tld.get_tld(self.url)
            self.tld_length = len(self.tld)
        except Exception as e:
            l = parsed_url.netloc.split(".")
            self.tld = l if l else None
            self.tld_length = len(self.tld) if self.tld else -1


        # # Attributes based on WHOIS
        # For some reason the command whois prints the error to stdin so we need to catch that in case whois returns nothing
        f = io.StringIO()  # we are going to store stdout in the variable f
        with redirect_stdout(f):
            self.whois_record = whois(parsed_url.netloc)
        out = f.getvalue()  # get the string from f into out
        error_pattern = re.compile(r'\bError.*')
        x = [i for i in out.split('\n') if error_pattern.match(i)]
        if len(x) > 0: print("There was an error in whois")
        # WHOIS_FOUND = True if self.dom_record else False


        # Get IP address
        dns_query = Nslookup(dns_servers=["1.1.1.1"])
        ip_record = dns_query.dns_lookup(parsed_url.netloc)  #TODO: time this request
        self.time_response = None  #TODO: get the lookup time response (figure out if they want it in days, second, milliseconds or what)
        if self.dom_is_ip:
            self.ip = parsed_url.netloc
        else:
            # If the domain is not in IP format find the IP address
            self.ip = ip_record.answer[0] if ip_record.answer else None

        # Get info from IP address and WHOIS server stuff
        self.num_resolved_ips = len(ip_record.answer) if ip_record else None
        obj = ipwhois.IPWhois(self.ip) if self.ip else None
        # Store the info from the IPWhois object

        # rdap some times returns better  results than whois but most papers use whois data
        # self.dom_record = obj.lookup_rdap()
        self.dom_record = obj.lookup_whois()  if obj else None# The only downside (also with rdap) is that we don't get expiration date
        self.asn_ip = self.dom_record['asn'] if obj and ('asn' in self.dom_record.keys()) else None

        # TODO: calculate the time in days correctly
        # I think that by "Domain activation time" they mean the time that the domain has been active
        # So we need to get the current date and time and see the difference
        if self.dom_record:
            datetime_pattern = re.compile(r'(\d{1,2}/\d{1,2}/\d{4})|(\d{4}-\d{1,2}-\d{1,2})')
            self.dom_activation_date = self.get_activation_date(self.dom_record)  # this would have to change if we move from whois to rdap
            self.dom_activation_date = datetime.datetime.strptime(datetime_pattern.search(self.dom_activation_date).group(), '%Y-%m-%d')
            self.dom_activation_date = datetime.datetime.now() - self.dom_activation_date
            self.dom_activation_date = self.dom_activation_date.days
        else:
            self.dom_activation_date = None
        self.dom_expiration_date = self.whois_record.expiration_date if type(self.whois_record.expiration_date) != list else self.whois_record.expiration_date[0]
        if self.dom_expiration_date:
            self.dom_expiration_date = self.dom_expiration_date - datetime.datetime.now()
            self.dom_expiration_date = self.dom_expiration_date.days

        # self.dom_country = self.dom_record.country

        self.domain_dpf = None  # TODO: get mx_servers
        self.num_name_servers = None  # TODO: get nameservers
        self.num_mx_servers = None
        self.ttl = None  # TODO: get ttl_hostname
        self.tls_ssl_cert= False  # it gets updated in the fetch_page function
        self.num_redirects = 0  # TODO: find the number of redirects
        self.url_shortened = False  # TODO: determine if the url has been shortened

        # We don't really pan to use these features for the machine learning model
        # TODO: add a flag to know if we want to collect info from google or not (we don't want it all the time think about the crawler)
        self.url_google_indx = False
        self.dom_google_indx = False

        page = self.fetch_page(url)
        self.content = page.content
        self.headers = page.headers

        self.scheme = parsed_url.scheme
        self.params = parsed_url.params
        self.fragments = parsed_url.fragment
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

    def get_activation_date(self, dom_record):
        if 'nets' in dom_record.keys():
            net_obj = dom_record['nets'][0] if dom_record['nets'] else None
            if net_obj:
                return net_obj['created'] # TODO: change from string to datetime object (or days) before returning
        # TODO: do one for rdap where nets is network and the date is in a list called event
        return None


    def get_features(self):
        # return a list of the features in the right order
        feature_dict = self.__dict__
        # TODO: this is probably not the best way of declaring the order of the attributes. please update
        correct_order = ['url_num_dot', 'url_num_hyphen', 'url_num_underline', 'url_num_slash', 'url_num_quest', 'url_num_equ', 'url_num_at', 'url_num_amp', 'url_num_excl', 'url_num_spaces', 'url_num_tilde', 'url_num_comma', 'url_num_plus', 'url_num_ast', 'url_num_pound', 'url_num_doll', 'url_num_perc', 'url_length', 'url_emails',
                         'dom_num_dot', 'dom_num_hyphen', 'dom_num_underline', 'dom_num_slash', 'dom_num_quest', 'dom_num_equ', 'dom_num_at', 'dom_num_amp', 'dom_num_excl', 'dom_num_spaces', 'dom_num_tilde', 'dom_num_comma', 'dom_num_plus', 'dom_num_ast', 'dom_num_pound', 'dom_num_doll', 'dom_num_perc', 'dom_num_vowels', 'dom_length', 'dom_is_ip', 'dom_contains_server_or_client',
                         'dir_num_dot', 'dir_num_hyphen', 'dir_num_underline', 'dir_num_slash', 'dir_num_quest', 'dir_num_equ', 'dir_num_at', 'dir_num_amp', 'dir_num_excl', 'dir_num_spaces', 'dir_num_tilde', 'dir_num_comma', 'dir_num_plus', 'dir_num_ast', 'dir_num_pound', 'dir_num_doll', 'dir_num_perc', 'dir_length',
                         'file_num_dot', 'file_num_hyphen', 'file_num_underline', 'file_num_slash', 'file_num_quest', 'file_num_equ', 'file_num_at', 'file_num_amp', 'file_num_excl', 'file_num_spaces', 'file_num_tilde', 'file_num_comma', 'file_num_plus', 'file_num_ast', 'file_num_pound', 'file_num_doll', 'file_num_perc', 'file_length',
                         'params_num_dot', 'params_num_hyphen', 'params_num_underline', 'params_num_slash', 'params_num_quest', 'params_num_equ', 'params_num_at', 'params_num_amp', 'params_num_excl', 'params_num_spaces', 'params_num_tilde', 'params_num_comma', 'params_num_plus', 'params_num_ast', 'params_num_pound', 'params_num_doll', 'params_num_perc', 'params_length', 'params_tld_present', 'params_nums',
                         'time_response', 'dom_spf', 'asn_ip', 'dom_activation_date', 'dom_expiration_date', 'num_resolved_ips', 'num_name_servers', 'num_mx_servers', 'ttl', 'tls_ssl_cert', 'num_redirects', 'url_google_indx', 'dom_google_indx', 'url_shortened']
        result = []
        for feature in correct_order:
            current_value = self.__dict__[feature] if self.__dict__[feature] else -1
            result.append(int(current_value))
        return result

    def get_tld(self, str):
        # returns the number of tld strings in the str variable
        vectorizer = CountVectorizer(ngram_range=(1, 6), analyzer='char')
        analyzer = vectorizer.build_analyzer()
        for _token in analyzer(str):
            pass
        # if there are no tlds in the str return None
        return None




if __name__ == "__main__":
    # Fake websites:
    w = WebsiteFeatureExtractor("http://13.234.215.215/")
    w.get_features()
    u = WebsiteFeatureExtractor("https://lojaonlinetimor.000webhostapp.com/")
    u.get_features()
    x = WebsiteFeatureExtractor("http://vod.reliableiptv.com/images/spl_schedules/4cc73ad389754af37e7d3f4b079b981d/index.php?d16f368958a5dbdaaff735ef81ce40a5?dispatch=LDpjZWL1sxB96npRSaRn3Oq12JoBAY8lBxFBtqCVXd54BuVuEM")
    x.get_features()
    # Legit websites:
    w = WebsiteFeatureExtractor("http://www.eckert-ferkel.de/")
    w.get_features()
    u = WebsiteFeatureExtractor("http://www.akgupta.com/")
    u.get_features()
    x = WebsiteFeatureExtractor("http://www.eksplora.com/")
    x.get_features()
