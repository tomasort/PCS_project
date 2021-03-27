import requests
import pandas as pd
import asyncio
import time
from bs4 import BeautifulSoup
import re
import random

phishing_df = pd.read_csv('data/phishing_urls.csv')  # all phishing urls
legit_df = pd.read_csv('')

# if __name__ == '__main__':
#     print(phishing_df.head())
