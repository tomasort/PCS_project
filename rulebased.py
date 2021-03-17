import re
import ipaddress
from urllib.parse import urlparse

url = str(input())
stripped = url.strip().replace("http://","")
ipv4 = re.compile(r"[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}\.[a-fA-F0-9]{1,4}")


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

gethost = re.compile(r"^(?:http:\/\/)?([^\/]*)(?:\/.*)?$")
hostname = gethost.search(url).group(1)
print(hostname)
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




print("IsIP: " + str(isIP))
print("Badchars: " + str(hasbadchars))
print("hasfeatures: " + str(hasfeatures))
