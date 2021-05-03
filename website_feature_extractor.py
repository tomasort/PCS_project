from bs4 import BeautifulSoup
import signal
from dateutil import parser
from urllib import request
import datetime
from collections import Counter, OrderedDict
from urllib.parse import urlparse, parse_qs, quote, unquote
from nslookup import Nslookup
from ipaddress import ip_address
from contextlib import redirect_stdout
from whois import whois
import requests, re, os, ipwhois, io, tld, time
from sklearn.feature_extraction.text import CountVectorizer
from scripts.proxies import Proxies
import pandas as pd


class timeout():
    def __init__(self, seconds=1, error_message='Timeout'):
        self.seconds = seconds
        self.error_message = error_message

    def handle_timeout(self, signum, frame):
        raise TimeoutError(self.error_message)

    def __enter__(self):
        signal.signal(signal.SIGALRM, self.handle_timeout)
        signal.alarm(self.seconds)

    def __exit__(self, type, value, traceback):
        signal.alarm(0)


tld_df = pd.read_csv("tld/tld2/tlds.csv")


def get_email(url):
    pattern = re.compile("\"?([-a-zA-Z0-9.`?{}]+@\w+\.\w+)\"?")
    emails = pattern.findall(url)
    return emails


def get_directory(path):
    return os.path.dirname(path)


def get_file_name(path):
    file_name = os.path.basename(path),
    return file_name[0] if type(file_name) == tuple else file_name


def is_ipaddress(domain):
    try:
        ip_address(domain)
        return True
    except Exception as e:
        return False


def get_tld(str):
    # returns the number of tld strings in the str variable
    vectorizer = CountVectorizer(ngram_range=(1, 6), analyzer='char')
    analyzer = vectorizer.build_analyzer()
    for _token in analyzer(str):
        if not tld_df[tld_df['TLD'] == _token].empty:
            return tld_df[tld_df['TLD'] == _token]['TLD']
    # if there are no TLDs in the str return None
    return None


def is_shortened(url):
    parsed_url = urlparse(url)
    for test in ['tl.gd', 'trunc.it', 'tinyurl', 'bit.ly', 'tiny', 'is.gd', 'ow.ly', 'goo.gl', 'twurl.nl', 'fb.me',
                 't.co', 'su.pr', 'ht.ly', 'youtu.be', 'post.ly', 'amzn.to', 'icio.us', 'flic.kr', 'moby.tl', 'om.ly']:
        if test in parsed_url.netloc and len(url) < 20:
            return True
    return False


class WebsiteFeatureExtractor:
    """Class for extracting the features of an entire website to determine if it is a phishing attack or not"""

    def __init__(self, url, use_proxy=False):
        self.features = OrderedDict()
        self.use_proxy = use_proxy
        parsed_url = urlparse(url)  # The structure of the parsed url is: scheme://netloc/path;parameters?query#fragment
        if not parsed_url.scheme:
            parsed_url = urlparse("https://" + url)  # we might need to change it to http later if it is not secure

        # First we get the basic URL-based features. In this section we get attributes from the url such as the
        # number of dots, commas, hyphens and other special characters.

        self.features['url'] = f'"{quote(url)}"'
        # Attributes based on the whole url
        self.max_retries = 2
        self.timeout = 12
        self.url = unquote(parsed_url.geturl())
        count = Counter(self.url)  # this is a dictionary-like structure for maintaining the counts of each character
        self.features['url_dots'] = count['.']
        self.features['url_hyphens'] = count['-']
        self.features['url_underscores'] = count['_']
        self.features['url_slashes'] = count['/']
        self.features['url_double_slashes'] = self.url.count("//")
        self.features['url_questions'] = count['?']
        self.features['url_equals'] = count['=']
        self.features['url_ats'] = count['@']
        self.features['url_amps'] = count['&']
        self.features['url_exclamations'] = count['!']
        self.features['url_spaces'] = count[' ']
        self.features['url_tildes'] = count['~']
        self.features['url_commas'] = count[',']
        self.features['url_pluses'] = count['+']
        self.features['url_asts'] = count['*']
        self.features['url_pounds'] = count['#']
        self.features['url_dollars'] = count['$']
        self.features['url_percents'] = count['%']
        self.features['url_length'] = len(self.url)
        url_email_addresses = get_email(self.url)
        self.features['email_in_url'] = 1 if url_email_addresses else 0
        self.features['url_num_emails'] = len(url_email_addresses)

        # Attributes based on the domain part of the url
        self.domain = parsed_url.netloc
        self.url = unquote(parsed_url.geturl())
        count = Counter(unquote(self.domain))
        self.features['dom_dots'] = count['.']
        self.features['dom_hyphens'] = count['-']
        self.features['dom_underlines'] = count['_']
        self.features['dom_slashes'] = count['/']
        self.features['dom_double_slashes'] = self.domain.count("//")
        self.features['dom_questions'] = count['?']
        self.features['dom_equals'] = count['=']
        self.features['dom_ats'] = count['@']
        self.features['dom_amps'] = count['&']
        self.features['dom_exclamations'] = count['!']
        self.features['dom_spaces'] = count[' ']
        self.features['dom_tilde'] = count['~']
        self.features['dom_commas'] = count[',']
        self.features['dom_pluses'] = count['+']
        self.features['dom_asts'] = count['*']
        self.features['dom_pounds'] = count['#']
        self.features['dom_dollars'] = count['$']
        self.features['dom_percents'] = count['%']
        self.features['dom_vowels'] = count['a'] + count['e'] + count['i'] + count['o'] + count['u']
        self.features['dom_length'] = len(self.domain)
        self.features['dom_is_ip'] = 1 if is_ipaddress(parsed_url.netloc) else 0
        self.features[
            'dom_server_or_client'] = 1 if "server" in self.domain.lower() or "client" in self.domain.lower() else 0
        self.dom_spf = None  # We are currently not using this feature
        # TODO: digit_letter_ratio in path and domain.

        # Attributes based on the directory part of the url
        self.directory = get_directory(parsed_url.path)
        if self.directory == '':
            for f in ['dir_dots', 'dir_hyphens', 'dir_underlines', 'dir_slashes', 'dir_double_slashes', 'dir_questions', 'dir_equals', 'dir_ats', 'dir_amps', 'dir_amps', 'dir_exclamations',
                      'dir_spaces', 'dir_spaces', 'dir_tilde', 'dir_commas', 'dir_pluses', 'dir_asts', 'dir_pounds', 'dir_dollars', 'dir_percents', 'dir_length']:
                self.features[f] = -1
        else:
            count = Counter(unquote(self.directory))
            self.features['dir_dots'] = count['.']
            self.features['dir_hyphens'] = count['-']
            self.features['dir_underlines'] = count['_']
            self.features['dir_slashes'] = count['/']
            self.features['dir_double_slashes'] = self.directory.count('//')
            self.features['dir_questions'] = count['?']
            self.features['dir_equals'] = count['=']
            self.features['dir_ats'] = count['@']
            self.features['dir_amps'] = count['&']
            self.features['dir_exclamations'] = count['!']
            self.features['dir_spaces'] = count[' ']
            self.features['dir_tilde'] = count['~']
            self.features['dir_commas'] = count[',']
            self.features['dir_pluses'] = count['+']
            self.features['dir_asts'] = count['*']
            self.features['dir_pounds'] = count['#']
            self.features['dir_dollars'] = count['$']
            self.features['dir_percents'] = count['%']
            self.features['dir_length'] = len(self.directory)

        # Attributes based on the file_name part of the url
        self.file_name = get_file_name(parsed_url.path)
        if self.file_name == '':
            for f in ['file_dots', 'file_hyphens', 'file_underlines', 'file_slashes', 'file_double_slashes', 'file_questions', 'file_equals', 'file_ats', 'file_amps', 'file_amps', 'file_exclamations',
                      'file_spaces', 'file_spaces', 'file_tilde', 'file_commas', 'file_pluses', 'file_asts', 'file_pounds', 'file_dollars', 'file_percents', 'file_length']:
                self.features[f] = -1
            self.features['file_ext'] = ""
        else:
            count = Counter(unquote(self.file_name))
            self.features['file_dots'] = count['.']
            self.features['file_hyphens'] = count['-']
            self.features['file_underlines'] = count['_']
            self.features['file_slashes'] = count['/']
            self.features['file_double_slashes'] = self.file_name.count("//")
            self.features['file_questions'] = count['?']
            self.features['file_equals'] = count['=']
            self.features['file_ats'] = count['@']
            self.features['file_amps'] = count['&']
            self.features['file_exclamations'] = count['!']
            self.features['file_spaces'] = count[' ']
            self.features['file_tilde'] = count['~']
            self.features['file_commas'] = count[',']
            self.features['file_pluses'] = count['+']
            self.features['file_asts'] = count['*']
            self.features['file_pounds'] = count['#']
            self.features['file_dollars'] = count['$']
            self.features['file_percents'] = count['%']
            self.features['file_length'] = len(self.file_name)
            self.features['file_ext'] = "" if not '.' in self.file_name else quote(self.file_name.split('.')[-1])

        # Attributes based on the query part of the url
        self.param_string = parsed_url.query  # there is a discrepancy with the data (from the paper) and the way urlparse parses the url
        self.params = parse_qs(self.param_string)
        if self.param_string == '':
            for f in ['params_dots', 'params_hyphens', 'params_underlines', 'params_slashes', 'params_double_slashes', 'params_questions', 'params_equals', 'params_ats', 'params_amps', 'params_amps', 'params_exclamations',
                      'params_spaces', 'params_spaces', 'params_tilde', 'params_commas', 'params_pluses', 'params_asts', 'params_pounds', 'params_dollars', 'params_percents', 'params_length']:
                self.features[f] = -1
        else:
            count = Counter(unquote(self.param_string))
            self.features['params_dots'] = count['.']
            self.features['params_hyphens'] = count['-']
            self.features['params_underlines'] = count['_']
            self.features['params_slashes'] = count['/']
            self.features['params_double_slashes'] = self.param_string.count("//")
            self.features['params_questions'] = count['?']
            self.features['params_equals'] = count['=']
            self.features['params_ats'] = count['@']
            self.features['params_amps'] = count['&']
            self.features['params_exclamations'] = count['!']
            self.features['params_spaces'] = count[' ']
            self.features['params_tilde'] = count['~']
            self.features['params_commas'] = count[',']
            self.features['params_pluses'] = count['+']
            self.features['params_asts'] = count['*']
            self.features['params_pounds'] = count['#']
            self.features['params_dollars'] = count['$']
            self.features['params_percents'] = count['%']
            self.features['params_length'] = len(self.param_string)
        # find out if there is a tld in the param_string variabe
        param_tld = get_tld(self.param_string)
        self.features['tld_in_params'] = 1 if not param_tld is None and not param_tld.empty else 0
        self.features['params_nums'] = len(self.params) if self.param_string else -1

        print("Looking for TLD")
        # Attributes based on TLD (top level domain)
        try:
            self.tld = tld.get_tld(self.url)
            self.features['tld'] = self.tld
            self.features['tld_length'] = len(self.tld)
        except Exception as e:
            if self.features['dom_is_ip']:
                self.features['tld'] = ""
                self.features['tld_length'] = -1
            else:
                sections = parsed_url.netloc.split(".")
                tld_list = []
                for possible_tld in sections:
                    if len(tld_df[tld_df['TLD'] == possible_tld]) > 0:
                        tld_list.append(possible_tld)
                current_tld = ".".join(tld_list)
                self.tld = current_tld if tld_list else ""
                self.features['tld'] = self.tld
                self.features['tld_length'] = len(self.tld) if self.tld else -1


        print("Trying to reach the whois server")
        self.whois_record = None
        try:
            self.get_whois(parsed_url)
        except:
            print("Exception on getting whois")
            self.whois_record = None

        self.features['whois'] = 1 if self.whois_record else 0

        print("Getting DNS records")
        # Get IP address of the given url for better Who is data
        dns_query = Nslookup(dns_servers=["1.1.1.1", "1.0.0.1", "8.8.8.8", "8.8.4.4", "9.9.9.9"])
        start = time.time()
        dns_error = False
        try:
            ip_record = dns_query.dns_lookup(parsed_url.netloc)
        except:
            # The dns lookup returned an error
            dns_error = True
            ip_record = None
        roundtrip = time.time() - start
        self.features['dns_response_time'] = -1 if dns_error else roundtrip
        self.features['dns'] = 1 if ip_record else 0
        if self.features['dom_is_ip']:
            self.ip = parsed_url.netloc
        else:
            # If the domain is not in IP format find the IP address
            # Note: we take the first IP that the dns returned
            self.ip = ip_record.answer[0] if ip_record and ip_record.answer else None

        # Get info from IP address and WHOIS server stuff
        # This proxy can only be used from a specific ip address and will refuse connection otherwise

        print("Serching for other IPs")
        obj = None
        try:
            if self.use_proxy:
                handler = request.ProxyHandler(
                    {'http': 'http://108.59.14.203:13010', 'https': 'http://108.59.14.203:13010'})
                opener = request.build_opener(handler)
                self.num_resolved_ips = len(ip_record.answer) if ip_record else None
                try:
                    obj = ipwhois.IPWhois(self.ip, proxy_opener=opener) if self.ip else None
                except:
                    pass
            else:
                self.num_resolved_ips = len(ip_record.answer) if ip_record else None
                try:
                    obj = ipwhois.IPWhois(self.ip) if self.ip else None
                except:
                    pass
        except:
            pass

        # Store the info from the IPWhois object
        # rdap some times returns better  results than whois but most papers use whois data
        # self.dom_record = obj.lookup_rdap()
        try:
            self.dom_record = obj.lookup_whois()  # The only downside (also with rdap) is that we don't get expiration date
        except:
            self.dom_record = None
        self.features['asn_ip'] = self.dom_record['asn'] if obj and ('asn' in self.dom_record.keys()) else -1

        # Get activation date using data from IPWhois
        # we need to get the current date and time and see the difference
        if self.dom_record:
            # this would have to change if we move from whois to rdap:
            act = self.get_activation_date(self.dom_record)
            if act:
                activation_date = datetime.datetime.now() - act
                self.features['dom_activation_date'] = activation_date.days
            else:
                self.features['dom_activation_date'] = -1
        else:
            self.features['dom_activation_date'] = -1

        # Get expiration date using data from whois
        expiration_date = self.get_expiration_date(self.whois_record) if self.whois_record else None
        self.features['dom_expiration_date'] = -1
        if expiration_date:
            try:
                expiration_date = expiration_date - datetime.datetime.now()
                self.features['dom_expiration_date'] = expiration_date.days if expiration_date else -1
            except:
                pass
        self.features['resolved_ns'] = len(self.whois_record.values()) if self.whois_record and self.whois_record.values else 0
        # self.features['dnssec'] = str(set(self.whois_record['dnssec'])) if self.whois_record and self.whois_record['dnssec'] else ""
        self.features['resolved_ips'] = len(ip_record.answer) if ip_record and ip_record.answer else 0
        if self.dom_record and self.dom_record['nets']:
            self.features['dom_country'] = ", ".join([country for country in list(set([x['country'].strip() if 'country' in x.keys() and x['country'] else None for x in self.dom_record['nets']])) if country is not None])
            self.features['dom_country'] = f"\"{self.features['dom_country']}\""
        else:
            self.features['dom_country'] = ""

        self.url_shortened = is_shortened(self.url)

        print("Looking for page")
        self.features['cookies'] = 0  # is updated in the fetch function
        # in fetch_page we get the redirects and tls_ssl_cert features
        try:
            page = self.fetch_page(url)
        except Exception as e:
            if "Errno 24" in str(e) or "open files" in str(e):
                print("This is BAD")
                raise e
            page = None

        print("Processing Page")
        # TODO: check for secure forms
        # check for hidden elements
        self.features['hidden_elements'] = -1
        self.features['display_none_elements'] = -1
        if page:
            self.features['hidden_elements'] = len(page.select('[style~="visibility:hidden"]'))
            self.features['hidden_elements'] = self.features['hidden_elements'] + len(page.select('[visibility~=hidden]'))
            self.features['display_none_elements'] = len(page.select('[style~="display:none"]'))
            self.features['display_none_elements'] = self.features['display_none_elements'] + len(page.select('[display~=none]'))
        # get number of forms
        self.features['forms'] = -1
        if page:
            self.features['forms'] = len(page.find_all('form'))
        # ExtFormAction: check if the action attribute on forms is an external address.
        self.features['ext_form_actions'] = -1
        if page:
            self.features['ext_form_actions'] = 0
            for form in page.find_all('form'):
                href = form.attrs['href'] if 'href' in form.attrs.keys() else None
                if href and self.domain != urlparse(href).netloc and urlparse(href).netloc:
                    self.features['ext_form_actions'] = self.features['ext_form_actions'] + 1
        self.features['page_content_length'] = -1
        if page:
            self.features['page_content_length'] = len(page.get_text())
        # popup_windows: boolean value for identifying if the html source contains pup-ups
        # check disabling right click. (apparently this can be done from the url)
        self.features['popup_windows'] = -1
        self.features['disable_right_click'] = -1
        #  mail etc are present into the script because this information submitted by the victim on phishing link can be mailed to attacker.
        self.features['email_in_script'] = -1
        if page:
            self.features['popup_windows'] = 0
            self.features['disable_right_click'] = 0
            self.features['email_in_script'] = 0
            for script in page.find_all('script'):
                c = script.decode()
                if 'window.open' in c:
                    self.features['popup_windows'] = self.features['popup_windows'] + 1
                if 'preventDefault()' in c:
                    self.features['disable_right_click'] = 1
                self.features['email_in_script'] = 1 if get_email(c) else 0
        # check for favicon and check if the favicon is installed from a different hostname!
        self.features['favicon'] = -1
        self.features['ext_favicon'] = -1
        if page:
            self.features['favicon'] = 0
            self.features['ext_favicon'] = 0
            icon_link_element = page.find("link", rel="shortcut icon")
            if icon_link_element:
                self.features['favicon'] = 1
                if 'href' in icon_link_element.attrs.keys():
                    icon_href = icon_link_element['href']
                else:
                    icon_href = ""
                if urlparse(icon_href).netloc != self.domain and urlparse(icon_href).netloc:
                    self.features['ext_favicon'] = 1
        # get the number of images
        self.features['img'] = -1
        if page:
            self.features['img'] = len(page.find_all('img'))
        # check the number of null self redirect hyperlinks in the page and the percentage
        self.features['null_self_redirects'] = -1
        self.features['a_tags'] = -1
        # links that lead to an external page.
        self.features['ext_links'] = -1
        if page:
            self.features['null_self_redirects'] = 0
            self.features['a_tags'] = 0
            self.features['ext_links'] = 0
            for a_tag in page.find_all('a'):
                if 'href' in a_tag.attrs.keys() and (a_tag.attrs['href'] == "#" or a_tag.attrs['href'] == ""):
                    self.features['null_self_redirects'] = self.features['null_self_redirects'] + 1
                self.features['a_tags'] = self.features['a_tags'] + 1
                if 'href' in a_tag.attrs.keys() and urlparse(a_tag.attrs['href']).netloc != self.domain and urlparse(a_tag.attrs['href']).netloc:
                    self.features['ext_links'] = self.features['ext_links'] + 1
        # check iframes
        self.features['iframes'] = -1
        if page:
            self.features['iframes'] = len(page.find_all('iframes'))
        self.features['port'] = parsed_url.port
        self.scheme = parsed_url.scheme
        self.params = parsed_url.params
        self.fragments = parsed_url.fragment

    def fetch_page(self, url):
        print(f"Fetching website {url}")
        self.features['redirects'] = 0
        if urlparse(url).scheme == '':
            url = "https://" + url
        proxy = None
        retries = 0
        # if self.use_proxy:
        #     proxy = {'http': 'http://108.59.14.203:13010', 'https': 'http://108.59.14.203:13010'}
        self.features['tls_ssl_cert'] = 0
        self.features['status_code'] = -1
        self.features['live'] = 0
        while retries < self.max_retries:
            try:
                p = Proxies()
                response = requests.get(url, headers=p.get_headers(), timeout=self.timeout, proxies=proxy, allow_redirects=True)
                if response.status_code == 200:
                    print(f'Success! {url}')
                elif response.status_code == 404:
                    print('Page Not Found.')
                else:
                    print('Status code: ', response.status_code)
                self.features['tls_ssl_cert'] = 1
                self.features['status_code'] = response.status_code
                self.features['cookies'] = 1 if 'Cookie' in response.headers.keys() or 'Set-Cookie' in response.headers.keys() else 0

                for redirect in response.history:
                    if redirect.url != self.url:
                        self.features['redirects'] = self.features['redirects'] + 1
                self.features['live'] = 1
                return BeautifulSoup(response.text, 'lxml')
            except requests.exceptions.SSLError as e:
                print("Error3", e)
                print("Trying without verifying tls and ssl")
                self.features['tls_ssl_cert'] = 0
                try:
                    url = url.replace("https", "http")
                    response = requests.get(url, headers=p.get_headers(), verify=False, timeout=self.timeout, proxies=proxy,
                                            allow_redirects=True)
                    self.features['status_code'] = response.status_code
                    self.features['cookies'] = 1 if 'Cookie' in response.headers.keys() or response.cookies else 0
                    for redirect in response.history:
                        if redirect.url != self.url:
                            self.features['redirects'] = self.features['redirects'] + 1
                    self.features['live'] = 1
                    return BeautifulSoup(response.text, 'lxml')
                except Exception as e:
                    print("Error1", e)
                    return None
            except Exception as e:
                print("Error2", e)
                if "Errno 24" in str(e) or "open files" in str(e):
                    print("This is BAD")
                    raise(e)
                retries += 1
                break
        self.features['live'] = 0
        return None

    def get_activation_date(self, dom_record):
        datetime_pattern = re.compile(r'(\d{1,2}/\d{1,2}/\d{4})|(\d{4}-\d{1,2}-\d{1,2})')
        most_recent = None
        if 'nets' in dom_record.keys():
            for dom_rec in dom_record['nets']:
                if 'created' in dom_rec.keys() and dom_rec['created'] and datetime_pattern.search(dom_rec['created']) and datetime_pattern.search(dom_rec['created']).group():
                        created = datetime.datetime.strptime(datetime_pattern.search(dom_rec['created']).group(), '%Y-%m-%d')
                        if most_recent is None or most_recent < created:  # we keep the most recent one
                            most_recent = created
        return most_recent

    def get_whois(self, parsed_url):
        # # Attributes based on WHOIS.
        # For some reason the command whois prints the error to stdin so we need to catch
        # that in case whois returns nothing
        f = io.StringIO()  # we are going to store stdout in the variable f
        with redirect_stdout(f):
            # remember that the url is of the form scheme://netloc/path;parameters?query#fragment.
            try:
                self.whois_record = whois(self.parsed_url.netloc)  # the whois method takes the netloc part of the url.
            except:
                pass
        out = f.getvalue()  # get the string from f into out
        error_pattern = re.compile(r'\bError.*')
        x = [i for i in out.split('\n') if error_pattern.match(i)]
        if len(x) > 0:
            print("There was an error in whois")
            print(out)


    def get_expiration_date(self, whois_record):
        if type(whois_record.expiration_date) == list:
            most_recent = None
            for exp_date in whois_record.expiration_date:
                if type(exp_date) is str:
                    try:
                        exp_date = parser.parse(exp_date)
                    except:
                        continue
                if most_recent is None or most_recent > exp_date:  # we keep the most recent one
                    most_recent = exp_date
            return most_recent
        else:
            return whois_record.expiration_date

    def get_features(self):
        # return a list of the features in the right order
        return list(self.features.values())

    def get_features_names(self):
        return list(self.features.keys())


if __name__ == "__main__":
    # Test the feature extraction

    # Fake websites:
    w = WebsiteFeatureExtractor("http://13.234.215.215")
    w.get_features()
    r = WebsiteFeatureExtractor("https://lojaonlinetimor.000webhostapp.com/")
    # u.get_features()
    # This website is down (not surprising since it is a phishing site)
    # x = WebsiteFeatureExtractor("http://vod.reliableiptv.com/images/spl_schedules/4cc73ad389754af37e7d3f4b079b981d/index.php?d16f368958a5dbdaaff735ef81ce40a5?dispatch=LDpjZWL1sxB96npRSaRn3Oq12JoBAY8lBxFBtqCVXd54BuVuEM")
    # x.get_features()

    # Legit websites:
    w = WebsiteFeatureExtractor("http://www.eckert-ferkel.de/")
    w.get_features()
    u = WebsiteFeatureExtractor("https://stackoverflow.com/questions/38489386/python-requests-403-forbidden")
    u.get_features()
    x = WebsiteFeatureExtractor("http://www.eksplora.com/")
    x.get_features()
