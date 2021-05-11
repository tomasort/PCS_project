# Phishermen Project

Command line application to predict if a website is a phishing site or not. 

##Introduction
In this project we use a __Random Forest__ model along with several rules to be able to predict 
with high accuracy if a website is part of a phishing attack or if it is a legitimate website.

We collected the data used in this project using the scripts located in the __scripts__ folder

The datasets used in the project are contained in the **data** folder while the serialized versions of the data, models and encoders are located in the **serialized** folder.
To learn more about the datasets we used and the data we collected please read the readme file in the data folder. 

The code to train the model and to be able to predict the labels of new websites is located in the files **randomforest.py** and **naivebayes.py**.
The code used to scrape the content of target websites provided by users is located in **website_feature_extractor.py**

The main point of entry into our application is **main.py**

##Installation
To be able to run our program you must first install the requirements. To install all the requirements in one go use:
```pip install -r requirements.txt```

##Running the Program
To run our program, use:
```python3 main.py```

##Testing
To test our program please visit https://phishtank.com/ to find phishing URLs. 

Some of the known phishing URLs from Phishtank.com that you can try right now include: 
* http://amazon.user-update.jp.yhi1.top/
* https://solsmnewowsun.ftpaccess.cc/
* http://y1intratactly.space/?s1=no9
* https://uunioreuinn.cf/home/9a95f
* https://amaozm.frj8.com/signin
* https://5873a0c09b1157db75b8420e2cf403e2-dot-gle9392420309493993.rj.r.appspot.com/
* https://contactcloudstorages.s3.ca-tor.cloud-object-storage.appdomain.cloud/authapp.html?alt=media&amp;token=6FDF7A84A2939617678031703176782G456793T026782G456793T022G456793T02-Q9XU-1v9k-t497-Y635386Gvzu530813630655Z366/


Some challenging non-phishing URLs that we have tried and successfully classified are: 

* https://www.youtube.com/watch?v=bdneye4pzMw
* https://piazza.com/class/kjal1llw44i5ms?cid=168
* https://github.com/nyupcs/pcs-sp21-lab6-server
* https://stackoverflow.com/questions/67495536/pandas-pythonic-way-to-find-rows-with-matching-values-in-multiple-columns-hier
* https://nyu.zoom.us/j/8702431951?pwd=TnBOUW9DRkdPbFRtZWtNNWQvQ2RGUT09
* https://www.youtube.com/watch?v=mPY7Mq4M_Co&t=1s&ab_channel=MarcRebillet
* https://gsas.nyu.edu/academic-and-professional-development.html

##Team

Read Brown, rwb319, rwb319@nyu.edu

Tomas Ortega, tor213, tor213@nyu.edu

###Original dataset used until midterm report
the original dataset we used until we decided to collect our own data can be found using this link.

https://data.mendeley.com/datasets/72ptz43s9v/1
