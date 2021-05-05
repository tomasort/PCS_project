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

            classifier = data.pop("label")
            predictors = data
            #X_train, self.X_test, y_train, self.y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109)
            X_train, self.X_test, y_train, self.y_test = train_test_split(predictors, classifier, test_size=0.2,random_state=109)
        except FileNotFoundError:
            #import data
            with open("data/dataset_full.csv") as f:
                #determining number of columns from the first line of text
                n_cols = len(f.readline().split(","))

            data = np.loadtxt("data/dataset_full.csv", delimiter = ",", skiprows=1)

            #print(data[0])

            todelete = [107,104,16,102,103,4,20,110,10,38,11,108,8,13,106,15,109,9,12,14,21,39,25,24,27,30,28,29,26,23,32,31,34,33,35,22]
            data = np.delete(data, todelete, 1)
            n_cols = data.shape[1]


            with open("data.ser", 'wb') as f2:
                pickle.dump(data, f2)




            predictors = data[:, 0:n_cols-1]
            classifier = data[:, n_cols-1]

            predictorslist = list(map(tuple, predictors))
            classifierlist = classifier.tolist()

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
