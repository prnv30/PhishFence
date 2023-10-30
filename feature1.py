import ipaddress
import re
import urllib.request
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
import time
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse


class featureExtraction:
    
    try:
        self.response = requests.get(url)
        self.soup = BeautifulSoup(response.text, 'html.parser')
    except:
        pass

    try:
        self.urlparse = urlparse(url)
        self.domain = self.urlparse.netloc
    except:
        pass

    try:
        self.whois_response = whois.whois(self.domain)
    except:
        pass


    
  #Address bar based features (10)
    features = []
    def __init__(self, url):
        
        self.features = []
        
        #self.features.append(self.getDomain(url))
        self.features.append(self.ip_address(url))
        self.features.append(self.have_at_symbol(url))
        self.features.append(self.long_url(url))
        self.features.append(self.getDepth(url))
        self.features.append(self.redirection(url))
        self.features.append(self.httpDomain(url))
        self.features.append(self.shortening_service(url))
        self.features.append(self.prefix_suffix_separation(url))
    
    #Domain based features (4)
        dns = 0
        try:
            domain_name = whois.whois(urlparse(url).netloc)
        except:
            dns = 1
            
        self.features.append(dns)
        self.features.append(self.web_traffic(url))
        self.features.append(1 if dns == 1 else self.domainAge(domain_name))
        self.features.append(1 if dns == 1 else self.domainEnd(domain_name))
        
        self.features.append(self.dot_count(url))
        self.features.append(self.specialcharCount(url))
        self.features.append(self.subdomCount(url))


    # 1.Extracts domain from the given URL
    def getDomain(self, url):
        domain = urlparse(url).netloc
        if re.match(r"^www.",domain):
            domain = domain.replace("www.","")
        return domain
        
    # 2.Checks for IP address in URL (Have_IP)
    def ip_address(self, url):
        try:
            ipaddress.ip_address(url)
            ip = 1
        except:
            ip = 0
        return ip
        
    # 3.Checks the presence of @ in URL (Have_At)
    def have_at_symbol(self, url):
        if "@" in url:
            at = 1 
        else:
            at = 0   
        return at
        
    # 4.Finding the length of URL and categorizing (URL_Length)
    def long_url(self, url):
        if len(url) < 54:
            length = 0    
        else:
            length = 1    
        return length

    # 5.Gives number of '/' in URL (URL_Depth)
    def getDepth(self, url):
        s = urlparse(url).path.split('/')
        depth = 0
        for j in range(len(s)):
            if len(s[j]) != 0:
                depth = depth+1
        return depth
            
    # 6.Checking for redirection '//' in the url (Redirection)
    def redirection(self, url):
        pos = url.rfind('//')
        if pos > 6:
            if pos > 7:
                return 1
            else:
                return 0
        else:
            return 0
        
    # 7.Existence of “HTTPS” Token in the Domain Part of the URL (https_Domain)
    def httpDomain(self, url):
        domain = urlparse(url).netloc
        if 'https://|http://' in domain:
            return 1
        else:
            return 0

        
    # 8. Checking for Shortening Services in URL (Tiny_URL) 
    def shortening_service(self, url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|'
                        'tr\.im|link\.zip\.net', url)
        if match:
            return 1               # phishing
        else:
            return 0               # legitimate
        
        
        
        
    # 9.Checking for Prefix or Suffix Separated by (-) in the Domain (Prefix/Suffix)     
    def prefix_suffix_separation(self, url):
        if "-" in urlparse(url).netloc:
            return 1            # phishing
        else:
            return 0            # legitimate
        
    # 10. DNS Record 

        
    # 11.Web traffic (Web_Traffic)
    def web_traffic(self, url):
        try:
            rank = BeautifulSoup(urllib.request.urlopen(
                "http://data.alexa.com/data?cli=10&dat=s&url=" + url).read(), "xml").find("REACH")['RANK']
            if (int(rank) < 100000):
                return 1
            return 0
        except:
                return 0
            
    # 12.Survival time of domain: The difference between termination time and creation time (Domain_Age)  
    def domainAge(self, domain_name):
        creation_date = domain_name.creation_date
        expiration_date = domain_name.expiration_date
        if (isinstance(creation_date,str) or isinstance(expiration_date,str)):
            try:
                creation_date = datetime.strptime(creation_date,'%Y-%m-%d')
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if ((expiration_date is None) or (creation_date is None)):
            return 1
        elif ((type(expiration_date) is list) or (type(creation_date) is list)):
            return 1
        else:
            ageofdomain = abs((expiration_date - creation_date).days)
            if ((ageofdomain/30) < 6):
                age = 1
            else:
                age = 0
        return age

    # 13.End time of domain: The difference between termination time and current time (Domain_End) 
    def domainEnd(self, domain_name):
        expiration_date = domain_name.expiration_date
        if isinstance(expiration_date,str):
            try:
                expiration_date = datetime.strptime(expiration_date,"%Y-%m-%d")
            except:
                return 1
        if (expiration_date is None):
            return 1
        elif (type(expiration_date) is list):
            return 1
        else:
            today = datetime.now()
            end = abs((expiration_date - today).days)
        if ((end/30) < 6):
            end = 0
        else:
            end = 1
        return end

    # 14. Dot count
    def dot_count(self, url):
        if url.count(".") < 3:
            return 0            # legitimate
        elif url.count(".") == 3:
            return 1            # suspicious
        else:
            return 1            # phishing
            
        
    # 14. Special characters count
    def specialcharCount(self, url):
        cnt = 0
        special_characters = [';','+=','_','?','=','&','[',']','/',':']
        for each_letter in url:
            if each_letter in special_characters:
                cnt = cnt + 1
        return cnt


    # 15. 
    def subdomCount(self, url):

        # separate protocol and domain then count the number of dots in domain
        
        domain = url.split("//")[-1].split("/")[0].split("www.")[-1]
        if(domain.count('.')<=1):
            return 0
        else:
            return 1

    def getFeaturesList(self):
            return self.features