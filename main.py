from bs4 import BeautifulSoup
from collections import Counter
from urllib.parse import urlparse
import pandas as pd
import argparse
import requests
import sys
import re
import whois
from website import Website
from crawler import Crawler

def fetch_data(file_name):
    df = pd.read_csv(file_name,)
    result = []
    for label, row in df.iterrows():
        url = row['0']
        c = Crawler(url)
        result.extend(c.get_urls())


if __name__ == '__main__':
    # extract the command line arguments
    # parser = argparse.ArgumentParser(description='Process urls')
    # parser.add_argument('filename')
    # args = parser.parse_args()
    # print("Feature Extraction")
    # url = args.filename
    # Fetch the website and extract the features
    # w = Website(url)
    fetch_data('data/legit_sample.csv')
