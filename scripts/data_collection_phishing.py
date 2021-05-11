import threading
import pandas as pd
import urllib3
import sys
from website_feature_extractor import WebsiteFeatureExtractor
from urllib.parse import unquote, urlparse
from filelock import FileLock



urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

already_scraped_df = pd.read_csv("phish_data_collected.csv", header=None)
print(already_scraped_df.dtypes)
already_scraped_df[0] = already_scraped_df[0].apply(lambda x : unquote(urlparse(unquote(x)).netloc + urlparse(unquote(x)).path))
url_df = pd.read_json("data/urls/phishing_urls.json", orient=True)
url_df.drop(url_df[url_df[0].apply(lambda x : unquote(urlparse(unquote(x)).netloc + urlparse(unquote(x)).path)).isin(already_scraped_df[0].unique())].index, inplace=True)
url_df = url_df[::-1]
url_df = url_df.sample(len(url_df))
print(len(url_df))

def get_features_from_url(url, x):
    print(f"extracting features from {url}")
    w = WebsiteFeatureExtractor(url_df.iloc[i][0])
    s = ",".join([str(x) for x in w.get_features()]) + "\n"
    try:
        open_file = open("phish_data_collected.csv", "a")
        try:
            open_file.write(s)
        finally:
            open_file.close()
    except IOError:
        raise e


number_of_threads = 10
i = 0
while i < len(url_df):
    threads = []
    for x in range(number_of_threads):
        if i < len(url_df):
            try:
                print("creating thread")
                t = threading.Thread(target=get_features_from_url, args=(url_df.iloc[i][0], x))
                t.start()
                # time.sleep(5)
                threads.append(t)
                i += 1
            except Exception as e:
                if "Errno 24" in str(e) or "open files" in str(e):
                    print("This is BAD")
                    raise e
    try:
        for thread in threads:
            thread.join()
    except Exception as e:
        raise e
    for t in threads:
        if t.is_alive():
            print("Why are you still alive??")
            sys.exit()