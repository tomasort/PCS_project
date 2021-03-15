from bs4 import BeautifulSoup
import argparse
import requests
import sys

# TODO: get:
#   length of the url and the domain
#   # of dots in url, domain, directory and params
#   # of hyphens in url, domain, directory and params
#   # of underlines in url, domain, directory and params
#   # of slashes in url, domain, directory and params
#   # of question marks in url, domain, directory and params
#   # of equal signs in url, domain, directory and params
#   # of @ in url, domain, directory and params
#   # of + in url, domain, directory and params
#   # of * in url, domain, directory and params
#   # of # in url, domain, directory and params
#   # of $ in url, domain, directory and params
#   # of % in url, domain, directory and params

# TODO: determine if there is an email present in the url
# TODO: store the response time
# TODO: store the domain_spf (whatever that means)
# TODO: store the asn_ip
# TODO: store the time_domain_activation
# TODO: store the time domain expiration
# TODO: check if the website has a tls/ssl certificate
# TODO: figure out the number of redirects
# TODO: find if the site is in the google index
# TODO: determine if the url has been shortened
class Website:
    def __init__(self, url, content, headers):
        self.url = url
        self.content = content
        self.headers = headers


def get_website(url):
    print("Fetching website")
    response = requests.get(url)
    if response.status_code == 200:
        print('Success!')
    elif response.status_code == 404:
        print('Not Found.')
    return BeautifulSoup(response.content, 'lxml')


if __name__ == '__main__':
    # extract the command line arguments
    parser = argparse.ArgumentParser(description='Process urls') 
    parser.add_argument('filename')
    args = parser.parse_args()
    print("Feature Extraction")
    # fetch the website
    print(get_website(args.filename))
    # TODO: Extract the features from the website