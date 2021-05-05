import numpy as np
from sklearn.model_selection import train_test_split
from sklearn import metrics
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder
import pandas as pd
#import time
class RandomForest:
    X_test = []
    y_test = []
    randomforest = None
    leFILEEXT = None
    leTLD = None
    leDOMCOUNTRY = None
    leASNIP = None
    def __init__(self):
    #start = time.time()
        try:
            f = open("randomforest.ser", 'rb')
            self.randomforest = pickle.load(f)
            f.close()
            f = open("data.ser", 'rb')
            data = pickle.load(f)
            f.close()
            #n_cols = data.shape[1]
            #predictors = data[:, 0:n_cols-1]
            #classifier = data[:, n_cols-1]

            #predictorslist = list(map(tuple, predictors))
            #classifierlist = classifier.tolist()
            with open("fileext.ser", 'rb') as f1, open("tld.ser", 'rb') as f2, open("domcountry.ser", 'rb') as f3, open("asnip.ser", 'rb') as f4:
                self.leFILEEXT = pickle.load(f1)
                self.leTLD = pickle.load(f2)
                self.leDOMCOUNTRY = pickle.load(f3)
                self.leASNIP = pickle.load(f4)
            classifier = data.pop("label")
            predictors = data
            #X_train, self.X_test, y_train, self.y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109)
            X_train, self.X_test, y_train, self.y_test = train_test_split(predictors, classifier, test_size=0.2,random_state=109)
        except FileNotFoundError:
            #import data
            with open("data/collected_data.csv") as f:
                #determining number of columns from the first line of text
                n_cols = len(f.readline().split(","))

            #data = np.loadtxt("./dataset_full.csv", delimiter = ",", skiprows=1)
            headers = [*pd.read_csv('data/collected_data.csv', nrows=1)]
            data = pd.read_csv('data/collected_data.csv', usecols=[c for c in headers if c != 'url']).fillna(value = -1)
            #print(data[0])
            #data = np.delete(data, slice(39,n_cols-1),1)
            #todelete = [107,104,16,102,103,4,20,110,10,38,11,108,8,13,106,15,109,9,12,14,21,39,25,24,27,30,28,29,26,23,32,31,34,33,35,22]
            #data = np.delete(data, todelete, 1)
            #n_cols = data.shape[1]
            #data.drop(["url_percents","resolved_ips", "url_questions", "dom_hyphens", "url_tildes", "dom_is_ip", "url_commas", "url_exclamations", "url_asts", "tls_ssl_cert", "url_dollars", "url_spaces", "url_pluses", "url_pounds", "dom_underlines", "dom_server_or_client", "dom_ats", "dom_equals", "dom_exclamations", "dom_commas", "dom_spaces", "dom_tilde", "dom_amps", "dom_questions", "dom_asts", "dom_pluses", "dom_dollars", "dom_pounds", "dom_percents", "dom_slashes"], axis=1, inplace=True)
            #data.drop(["url_percents","resolved_ips", "url_questions", "dom_hyphens", "url_tildes", "dom_is_ip", "url_commas", "url_exclamations", "url_asts", "tls_ssl_cert", "url_dollars", "url_spaces", "url_pluses", "url_pounds", "dom_underlines", "dom_server_or_client", "dom_ats", "dom_equals", "dom_exclamations", "dom_commas", "dom_spaces", "dom_tilde", "dom_amps", "dom_questions", "dom_asts", "dom_pluses", "dom_dollars", "dom_pounds", "dom_percents", "dom_slashes", "dom_country","cookies","redirects","status_code","hidden_elements","display_none_elements","forms","ext_form_actions","page_content_length","popup_windows","disable_right_click","email_in_script","favicon","ext_favicon","img","null_self_redirects","a_tags","ext_links","iframes","port"], axis=1, inplace=True)
            data.drop(["port","iframes", "dir_commas","email_in_url"], axis=1, inplace=True)

            self.leFILEEXT = LabelEncoder()
            col = data.pop("file_ext").astype(str)
            self.leFILEEXT.fit(np.unique(col))
            data["file_ext"] =self.leFILEEXT.transform(col)

            self.leTLD = LabelEncoder()
            col = data.pop("tld").astype(str)
            self.leTLD.fit(np.unique(col))
            data["tld"] = self.leTLD.transform(col)

            self.leDOMCOUNTRY = LabelEncoder()
            col = data.pop("dom_country").astype(str)
            self.leDOMCOUNTRY.fit(np.unique(col))
            data["dom_country"] = self.leDOMCOUNTRY.transform(col)

            self.leASNIP = LabelEncoder()
            col = data.pop("asn_ip").astype(str)
            self.leASNIP.fit(np.unique(col))
            data["asn_ip"] = self.leASNIP.transform(col)

            with open("fileext.ser", 'wb') as f1, open("tld.ser", 'wb') as f2, open("domcountry.ser", 'wb') as f3, open("asnip.ser", 'wb') as f4:
                pickle.dump(self.leFILEEXT, f1)
                pickle.dump(self.leTLD, f2)
                pickle.dump(self.leDOMCOUNTRY, f3)
                pickle.dump(self.leASNIP, f4)

            with open("data.ser", 'wb') as f2:
                pickle.dump(data, f2)

            classifier = data.pop("label")
            predictors = data
            #print(predictors)

            ##predictorslist = list(predictors.to_records(index=False))
            ##classifierlist = list(classifier)


            #predictors = data[:, 0:n_cols-1]
            #classifier = data[:, n_cols-1]

            #predictorslist = list(map(tuple, predictors))
            #classifierlist = classifier.tolist()

            #Randomforest

            X_train, self.X_test, y_train, self.y_test = train_test_split(predictors, classifier, test_size=0.2,random_state=109) # 80% training and 20% test
            self.randomforest = RandomForestClassifier(n_estimators=100, bootstrap = True, max_features = 'sqrt')
            #print(X_train[0])
            #print(y_train)
            self.randomforest.fit(X_train,y_train)
            with open("randomforest.ser", 'wb') as f1:
                pickle.dump(self.randomforest,f1)


    def predict(self,features):
        prediction = self.randomforest.predict(features)
        return prediction
    def probs(self,features):
        probs = self.randomforest.predict_proba(features)[:, 1]
        return probs
    def getstuff(self):
        return [self.X_test, self.y_test]
    def getencoders(self):
        return [self.leFILEEXT, self.leTLD, self.leDOMCOUNTRY, self.leASNIP]


    #end = time.time()
    #print("time to read and train: " + str(end-start))
if __name__ == "__main__":
    m = RandomForest()
    vals = m.getstuff()
    y_pred = m.predict(vals[0])
    probs = m.probs(vals[0])
    #for c in range(1000):
        #print(y_pred[c])
    #print("AUC score: ", roc_auc_score(y_pred, probs))
    x = precision_recall_fscore_support(vals[1], y_pred, average='macro')
    print('Precision: ' + str(x[0]))
    print('Recall: ' + str(x[1]))
    print('F-Score: ' + str(x[2]))
