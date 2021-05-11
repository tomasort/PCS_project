import threading
import pandas as pd
import urllib3
from website_feature_extractor import WebsiteFeatureExtractor
from scripts.crawler import Crawler
from urllib.parse import unquote, urlparse


urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

already_scraped_df = pd.read_csv("legit_data_collected.csv", header=None)
already_scraped_df[0] = already_scraped_df[0].apply(lambda x : unquote(urlparse(unquote(x)).netloc + urlparse(unquote(x)).path))
url_df = pd.read_csv("data/legitimate_urls.csv")
url_df.drop(url_df[url_df['0'].apply(lambda x : unquote(urlparse(unquote(x)).netloc + urlparse(unquote(x)).path)).isin(already_scraped_df[0].unique())].index, inplace=True)
print(len(url_df))

def get_features_from_url(a, b, num):
    for i in range(a, b):
        if i < len(url_df):
            try:
                c = Crawler(url_df.iloc[i][0], max_tries=1, levels=2)
                websites = list(c.get_urls()) if c.get_urls() else []
                websites.append(url_df.iloc[i][0])
                for url in websites:
                    print(f"extracting features from {url}")
                    w = WebsiteFeatureExtractor(url)
                    with open(f"legit_data_collected.csv", 'a') as open_file:
                        open_file.write(",".join([str(x) for x in w.get_features()]) + "\n")
            except Exception as e:
                print("Error4", e)
                raise e


number_of_threads = 15
i = 0
while i < len(url_df):
    threads = []
    for x in range(number_of_threads):
        if i < len(url_df):
            try:
                print("creating thread")
                t = threading.Thread(target=get_features_from_url, args=(i, i+1, x))
                t.start()
                threads.append(t)
                i += 1
            except Exception as e:
                continue
    try:
        for thread in threads:
            thread.join(timeout=60)
    except Exception as e:
        pass