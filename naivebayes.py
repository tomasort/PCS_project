import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn import metrics
import pickle
#import time
class MachineLearning:
    X_test = []
    y_test = []
    gnb = None
    def __init__(self):
    #start = time.time()
        try:
            f = open("data/model.ser", 'rb')
            self.gnb = pickle.load(f)
            f.close()
            f = open("data/data.ser", 'rb')
            data = pickle.load(f)
            f.close()
            n_cols = data.shape[1]
            predictors = data[:, 0:n_cols-1]
            classifier = data[:, n_cols-1]

            predictorslist = list(map(tuple, predictors))
            classifierlist = classifier.tolist()
            X_train, self.X_test, y_train, self.y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109)
        except FileNotFoundError:
            #import data
            with open("data/dataset_full.csv") as f:
                #determining number of columns from the first line of text
                n_cols = len(f.readline().split(","))

            data = np.loadtxt("./dataset_full.csv", delimiter = ",", skiprows=1)

            print(data.shape[1])
            #data = np.delete(data, slice(39,n_cols-1),1)
            todelete = [107,104,16,102,103,4,20,110,10,38,11,108,8,13,106,15,109,9,12,14,21,39,25,24,27,30,28,29,26,23,32,31,34,33,35,22]
            data = np.delete(data, todelete, 1)
            n_cols = data.shape[1]
            #print(n_cols)

            predictors = data[:, 0:n_cols-1]
            classifier = data[:, n_cols-1]

            predictorslist = list(map(tuple, predictors))
            classifierlist = classifier.tolist()

            #naive bayes

            X_train, self.X_test, y_train, self.y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109) # 80% training and 20% test
            self.gnb = GaussianNB()
            self.gnb.fit(X_train,y_train)
        with open("data/model.ser", 'wb') as f1, open("data/data.ser", 'wb') as f2:
            pickle.dump(self.gnb,f1)
            pickle.dump(data,f2)

    def predict(self, features):
        prediction = self.gnb.predict(features)
        return prediction
    def getstuff(self):
        return [self.X_test, self.y_test]



    #end = time.time()
    #print("time to read and train: " + str(end-start))
if __name__ == "__main__":
    m = MachineLearning()
    vals = m.getstuff()

    y_pred = m.predict(vals[0])
    print("Accuracy:",metrics.accuracy_score(vals[1], y_pred))
