import re
import ipaddress
from urllib.parse import urlparse
from googlesearch import search

url = str(input())
stripped = url.strip().replace("http://www.","")
stripped = stripped.strip().replace("https://www.","")
ipv4 = re.compile(r"[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}")
googleAPI_KEY = "AIzaSyAxxDoF9tCpgSQMHrUpekGWtVwZqWjS9cA"

#ip address - Rule 4
isIP = False
hasbadchars = False
try:
    ipaddress.ip_address(stripped)
    isIP = True
except ValueError:
    if(ipv4.match(stripped)):
        isIP = True
    else:
        isIP = False

#bad characters and nonstandard ports - Rule 5
badchars = set('-_0123456789@“”";')
if any((c in badchars) for c in stripped):
    hasbadchars = True



#URL features/length - Rule 6

gethost = re.compile(r"^(?:https?:\/\/)?([^\/]*)(?:\/.*)?$")
hostname = gethost.search(url).group(1)
dots = False
toolong = False
hostnametoolong = False
if(hostname.count(".")>=5):
    dots = True
if(len(url)>75):
    toolong = True
if(len(hostname)>30):
    hostnametoolong = True

hasfeatures = dots or toolong or hostnametoolong


#URL in search engine index - Rule 1
#Domain in search engine index - Rule 2
results = search(url, tld='com', lang='en', num=10, start=0, stop=10, pause=2.0)
urlnotinIndex = True
domainnotinindex = True
for res in results:
    resstripped = res.strip().replace("http://www.","")
    resstripped = resstripped.strip().replace("https://www.","")
    resstripped = resstripped[:-1]
    if(resstripped == stripped):
        urlnotinIndex = False
    reshost = gethost.search(res).group(1).replace("www.","")
    if(reshost == hostname.replace("www.","")):
        domainnotinindex = False




print("IsIP: " + str(isIP))
print("Badchars: " + str(hasbadchars))
print("hasfeatures: " + str(hasfeatures))
print("Url not in Search: " + str(urlnotinIndex))
print("Domain not in Search: " + str(domainnotinindex))
