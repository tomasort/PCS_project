from bs4 import BeautifulSoup
import argparse
import requests
import sys

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