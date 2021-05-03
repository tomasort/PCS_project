import requests
import pandas as pd
import json

df = pd.read_csv("collected_data_merged.csv")
verified_df = pd.read_csv("verified_phish.csv")
df['verified'] = 0
df = df[df['label'] == 1]
df = df[~df['url'].isin(verified_df['url'])]

for label, row in df.iterrows():
    x = {
        "client": {
            "clientId": "companyname",
            "clientVersion": "1.5.2"
        },
        "threatInfo": {
            "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "POTENTIALLY_HARMFUL_APPLICATION"],
            "platformTypes": ["WINDOWS", "CHROME", "OSX", "LINUX"],
            "threatEntryTypes": ["URL"],
            "threatEntries": [
                {"url": row["url"]}
            ]
        }
    }
    i = 0
    error = False
    while True:
        try:
            response = requests.post(url="https://safebrowsing.googleapis.com/v4/threatMatches:find?key=AIzaSyC8bAWVsuNywK2nBbyNUObkLzIBmdGH6g4", json=x, headers={"Content-Type" :"application/json"})
            if i > 5:
                break
            if response.status_code != 200:
                i += 1
                error = True
                break
            y = json.loads(response.content)
            print(f"URL={row['url']}      LABEL={row['label']}     VERIFIED={row['verified']}")
            if y:
                row['verified'] = 1
            else:
                row['verified'] = 0
            print(f"URL={row['url']}      LABEL={row['label']}     VERIFIED={row['verified']}")
            if response.status_code == 200:
                with open("verified_phish.csv", 'a') as open_file:
                    open_file.write(f"{row['url']},{row['label']},{row['verified']}\n")
                break
        except:
            break
    if error:
        break
