import numpy as np
from sklearn.naive_bayes import GaussianNB
from sklearn.model_selection import train_test_split
from sklearn import metrics
import pickle
import time
start = time.time()
try:
    f = open("model.ser", 'rb')
    gnb = pickle.load(f)
    f.close()
    f = open("data.ser", 'rb')
    data = pickle.load(f)
    f.close()
    n_cols = data.shape[1]
    predictors = data[:, 0:n_cols-1]
    classifier = data[:, n_cols-1]

    predictorslist = list(map(tuple, predictors))
    classifierlist = classifier.tolist()
    X_train, X_test, y_train, y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109)
except FileNotFoundError:
    #import data
    with open("./dataset_full.csv") as f:
        #determining number of columns from the first line of text
        n_cols = len(f.readline().split(","))

    data = np.loadtxt("./dataset_full.csv", delimiter = ",", skiprows=1)

    predictors = data[:, 0:n_cols-1]
    classifier = data[:, n_cols-1]

    predictorslist = list(map(tuple, predictors))
    classifierlist = classifier.tolist()

    #naive bayes

    X_train, X_test, y_train, y_test = train_test_split(predictorslist, classifierlist, test_size=0.2,random_state=109) # 80% training and 20% test
    gnb = GaussianNB()
    gnb.fit(X_train,y_train)



end = time.time()
print("time to read and train: " + str(end-start))
y_pred = gnb.predict(X_test)
print("Accuracy:",metrics.accuracy_score(y_test, y_pred))

with open("model.ser", 'wb') as f1, open("data.ser", 'wb') as f2:
    pickle.dump(gnb,f1)
    pickle.dump(data,f2)
