import website_feature_extractor
import naivebayes
import rulebased
import numpy as np

print("Please provide URL to test")
url = input().strip()

if url[:8] != "https://" and url[:7] != "http://":
    url="http://"+url

w = website_feature_extractor.WebsiteFeatureExtractor(url)
vector = w.get_features()
todelete = [107,104,16,102,103,4,20,110,10,38,11,108,8,13,106,15,109,9,12,14,21,39,25,24,27,30,28,29,26,23,32,31,34,33,35,22]
data = np.delete(vector, todelete, 0)

model = naivebayes.MachineLearning()

prediction = model.predict([data])[0]

rules = rulebased.RuleBased()
flags = rules.flags(url)
numflags = len(flags)
count = 0
for val in flags:
    if val:
        count +=1

if(prediction == 0):
    print("Our model predicted that your URL was not a phishing attack")
    if count > numflags/2:
        print("However, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack. Please use caution when accessing")
    else:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Your URL is unlikely to be a phishing attack")
else:
    print("Our model predicted that your URL was a phishing attack")
    if count > numflags/2:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Your URL is highly likely to be a phishing attack")
    else:
        print("In addition, your URL shows " + str(count) + " out of " + str(numflags) + " flags of being a phishing attack.")
        print("Although your URL does not show many potential signs of phishing, please use caution when accessing.")
