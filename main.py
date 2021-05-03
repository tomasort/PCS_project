import website_feature_extractor
import naivebayestemp
import rulebased
import numpy as np
import sys
import csv
import pandas as pd
import os


print("Please provide URL to test")
url = input().strip()
whitelist = []
blacklist = []
with open("whitelist.txt", 'r') as f1, open("blacklist.txt", 'r') as f2:
    for line in f1:
        whitelist.append(line.strip())
    for line in f2:
        blacklist.append(line.strip())

if url[:8] != "https://" and url[:7] != "http://":
    url="http://"+url
vector = None
#try:
w = website_feature_extractor.WebsiteFeatureExtractor(url)
vector = w.get_features()
headings = w.get_features_names()
todelete = []


for c in range(len(headings)):
    if ((headings[c] =="url") or (headings[c] == "port") or (headings[c] == "iframes") or (headings[c] =="dir_commas") or (headings[c] == "email_in_url")):
        todelete.append(c)


#testdelete = [107,104,16,102,103,4,20,110,10,38,11,108,8,13,106,15,109,9,12,14,21,39,25,24,27,30,28,29,26,23,32,31,34,33,35,22]

data = np.delete(vector, todelete, 0)
headings = np.delete(headings, todelete, 0)
model = naivebayestemp.MachineLearning()
encoders = model.getencoders()
datalist = data.tolist()

for c in range(len(datalist)):
    if(datalist[c]==''):
        datalist[c] = -1
for c in range(len(headings)):
    if headings[c] == "file_ext":
        datalist[c] = encoders[0].transform([str(datalist[c]).strip('"')])[0]
    elif headings[c] == "tld":
        datalist[c] = encoders[1].transform([str(datalist[c]).strip('"')])[0]
    elif headings[c] == "dom_country":
        datalist[c] = encoders[2].transform([str(datalist[c]).strip('"')])[0]
    elif headings[c] == "asn_ip":
        datalist[c] = encoders[3].transform([str(datalist[c]).strip('"')])[0]

prediction = model.predict([datalist])[0]
# except:
#     e = sys.exc_info()[0]
#     print(e)
#     prediction = -1

rules = rulebased.RuleBased()
flags = rules.flags(url)
numflags = len(flags)
count = 0
for val in flags:
    if val:
        count +=1

if url in whitelist:
    print("You have previously whitelisted this URL\n")
elif url in blacklist:
    print("You have previously blacklisted this URL\n")

if(prediction == 0):
    print("Our model predicted that your URL was not a phishing attack")
    if count > numflags/2:
        print("However, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack. Please use caution when accessing.")
    else:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Your URL is unlikely to be a phishing attack")
elif (prediction ==1):
    print("Our model predicted that your URL was a phishing attack")
    if count > numflags/2:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Your URL is highly likely to be a phishing attack")
    else:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Although your URL does not show many potential signs of phishing, please use caution when accessing.")
else:
    print("Our model was unable to connect to your URL.")
    if count > numflags/2:
        print("However, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack. Please use caution when accessing.")
    else:
        print("However, your URL shows only" + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Your URL is unlikely to be a phishing attack.")


if ((url not in whitelist) and (url not in blacklist)):
    print("Would you like to whitelist or blacklist this URL for future reference? Type \"whitelist\", \"blacklist\", or \"no\".")
    answer = input().strip().lower()
    if answer =="whitelist":
        whitelist.append(url)
        print("Your URL has been whitelisted")
    elif answer == "blacklist":
        blacklist.append(url)
        print("Your URL has been blacklisted")

data = pd.read_csv('data/phishing.csv').fillna(value = -1)
if url not in data.url:
    print("Would you like to provide feedback to our model? If so, type \"phishing\" if you would like to mark this website as phishing, \"safe\" if you would like to mark this site as safe, or \"no\"")
    answer=input().strip().lower()
    if answer == "phishing":
        with open("data/phishing.csv", 'a') as f:
            vector.append(1)
            write = csv.writer(f)
            write.writerow(vector)
            if os.path.exists("data.ser"):
                os.remove("data.ser")
    elif answer =="safe":
        with open("data/phishing.csv", 'a') as f:
            vector.append(0)
            write = csv.writer(f)
            write.writerow(vector)
            if os.path.exists("data.ser"):
                os.remove("data.ser")

with open("whitelist.txt", 'w') as f1, open("blacklist.txt", 'w') as f2:
    for line in whitelist:
        f1.write(line+"\n")
    for line in blacklist:
        f2.write(line+"\n")
