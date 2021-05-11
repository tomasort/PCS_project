import numpy as np
from sklearn.model_selection import train_test_split
from sklearn import metrics
import pickle
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import roc_auc_score
from sklearn.metrics import precision_recall_fscore_support
from sklearn.preprocessing import LabelEncoder
import pandas as pd
#Random forest machine learning
class RandomForest:
    #variables
    X_test = []
    y_test = []
    randomforest = None
    leFILEEXT = None
    leTLD = None
    leDOMCOUNTRY = None
    leASNIP = None
    def __init__(self):
        #get serialized data
        try:
            f = open("serialized/randomforest.ser", 'rb')
            self.randomforest = pickle.load(f)
            f.close()
            f = open("serialized/data.ser", 'rb')
            data = pickle.load(f)
            f.close()

            with open("serialized/fileext.ser", 'rb') as f1, open("serialized/tld.ser", 'rb') as f2, open("serialized/domcountry.ser", 'rb') as f3, open("serialized/asnip.ser", 'rb') as f4:
                self.leFILEEXT = pickle.load(f1)
                self.leTLD = pickle.load(f2)
                self.leDOMCOUNTRY = pickle.load(f3)
                self.leASNIP = pickle.load(f4)
            classifier = data.pop("label")
            predictors = data
            #set up variables
            X_train, self.X_test, y_train, self.y_test = train_test_split(predictors, classifier, test_size=0.2,random_state=109)
        except FileNotFoundError:
            #import data
            with open("data/phishing.csv") as f:
                #determining number of columns from the first line of text
                n_cols = len(f.readline().split(","))

            #read in data from CSV
            headers = [*pd.read_csv('data/phishing.csv', nrows=1)]
            data = pd.read_csv('data/phishing.csv', usecols=[c for c in headers if c != 'url'], low_memory=False).fillna(value = -1)
            #drop unused columns
            data.drop(["port","iframes", "dir_commas","email_in_url"], axis=1, inplace=True)

            #Encode textual features
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

            #dump encoders to maintain state
            with open("serialized/fileext.ser", 'wb') as f1, open("serialized/tld.ser", 'wb') as f2, open("serialized/domcountry.ser", 'wb') as f3, open("serialized/asnip.ser", 'wb') as f4:
                pickle.dump(self.leFILEEXT, f1)
                pickle.dump(self.leTLD, f2)
                pickle.dump(self.leDOMCOUNTRY, f3)
                pickle.dump(self.leASNIP, f4)

            #dump data
            with open("serialized/data.ser", 'wb') as f2:
                pickle.dump(data, f2)

            #split predictors and classifiers
            classifier = data.pop("label")
            predictors = data

            #train random forest
            X_train, self.X_test, y_train, self.y_test = train_test_split(predictors, classifier, test_size=0.2,random_state=109) # 80% training and 20% test
            self.randomforest = RandomForestClassifier(n_estimators=100, bootstrap = True, max_features = 'sqrt')
            self.randomforest.fit(X_train,y_train)
            with open("serialized/randomforest.ser", 'wb') as f1:
                pickle.dump(self.randomforest,f1)

    #predict whether a URL is phishing from its features
    def predict(self,features):
        prediction = self.randomforest.predict(features)
        return prediction
    #return prediction probabilities for evaluation
    def probs(self,features):
        probs = self.randomforest.predict_proba(features)[:, 1]
        return probs
    #get test data for evaluation
    def getstuff(self):
        return [self.X_test, self.y_test]
    #get encoders for encoding in main
    def getencoders(self):
        return [self.leFILEEXT, self.leTLD, self.leDOMCOUNTRY, self.leASNIP]



if __name__ == "__main__":
    #Testing and evaluation
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
