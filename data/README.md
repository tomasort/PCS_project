# Data 

This folder contains the datasets used in this project.

* `phishing_urls.csv` Contains all the phishing URLs we were able to find. We used this list as a seed for our crawler to collect a representative sample of the web in order to build our dataset and we used the scraper we implemented to get the features from each website. 

  
* `legitimate_urls.csv` Contains all the non-phishing URLs we used for our dataset.


* `collected_data.csv` Contains all the data we collected using the scraper and the 
  crawler we implemented (located in the scripts folder). In this file we have 
  non-phishing sites from the Alexa list and other sources such as 'majestic million' 
  and cisco. The phsihing URLs were collected from Phishtank.com
  
  
* `phishing.csv` Contains the data that we are currently using to train our model. This is a subset of the data in collected_data.csv. We decided to use this subset because it has approximately an 80-20 ratio of non-phishing url to phishing urls which we found works best in practice. 

  
* `old_dataset_full.csv` Contains the data we used to build our project until the midterm report phase. Then we decided to collect our own data.
  

* `scraping_headers.json` Contains useful information for building headers to get the features from websites. 
    
