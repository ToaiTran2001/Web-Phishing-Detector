# import sys
import re
# import regex
# from tldextract import extract
import ssl
# import certifi
ssl._create_default_https_context = ssl._create_unverified_context
from datetime import date, datetime
from dateutil.parser import parse as date_parse
import whois
from urllib import request
import requests
from bs4 import BeautifulSoup
# import socket
import xml.etree.ElementTree as ET
from googlesearch import search

class PreprocessUrl:
    # IP
    def url_ip(self, url):
        match = re.search('(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  # IPv4
                        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  # IPv4 in hexadecimal
                        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)  # IPv6
        if match:
            return -1
        return 1

    # URL length
    def url_length(self, url):
        length = len(url)
        if length < 54:
            return 1
        elif length > 75:
            return -1
        return 0

    # URL shorten
    def url_shorten(self, url):
        match = re.search('bit\.ly|goo\.gl|shorte\.st|go2l\.ink|x\.co|ow\.ly|t\.co|tinyurl|tr\.im|is\.gd|cli\.gs|'
                        'yfrog\.com|migre\.me|ff\.im|tiny\.cc|url4\.eu|twit\.ac|su\.pr|twurl\.nl|snipurl\.com|'
                        'short\.to|BudURL\.com|ping\.fm|post\.ly|Just\.as|bkite\.com|snipr\.com|fic\.kr|loopt\.us|'
                        'doiop\.com|short\.ie|kl\.am|wp\.me|rubyurl\.com|om\.ly|to\.ly|bit\.do|t\.co|lnkd\.in|'
                        'db\.tt|qr\.ae|adf\.ly|goo\.gl|bitly\.com|cur\.lv|tinyurl\.com|ow\.ly|bit\.ly|ity\.im|'
                        'q\.gs|is\.gd|po\.st|bc\.vc|twitthis\.com|u\.to|j\.mp|buzurl\.com|cutt\.us|u\.bb|yourls\.org|'
                        'x\.co|prettylinkpro\.com|scrnch\.me|filoops\.info|vzturl\.com|qr\.net|1url\.com|tweez\.me|v\.gd|tr\.im|link\.zip\.net', url)
        if match:
            return -1
        return 1

    # @ in URL
    def url_symbol(self, url):
        if '@' in url:
            return -1
        return 1
    
    # // in URL
    def url_double_slash(self, url):
        list = [x.start(0) for x in re.finditer('//', url)]
        if list[len(list) - 1] > 6:
            return -1
        return 1
    
    # Prefix and Suffix
    def url_prefix_suffix(self, url):
        if re.findall(r"https?://[^\-]+-[^\-]+/", url):
            return -1
        return 1
    
    # Subdomain
    def url_sub_domain(self, url):
        temp = len(re.findall("\.", url))
        if temp <= 1:
            return 1
        elif temp == 2:
            return 0
        return -1
    
    # Registration time
    def registration_time(self, domain):
        try:
            if isinstance(domain.creation_date, list):
                creation_date = domain.creation_date[0]
            else:
                creation_date = domain.creation_date

            creation_date = str(creation_date).split(' ')[0]

            if isinstance(domain.expiration_date, list):
                expiration_date = domain.expiration_date[0]
            else:
                expiration_date = domain.expiration_date

            expiration_date = str(expiration_date).split(' ')[0]
            creation_date = datetime.strptime(str(creation_date), '%Y-%m-%d')
            expiration_date = datetime.strptime(str(expiration_date), '%Y-%m-%d')
            time = abs((expiration_date - creation_date).days)
            year = time/365
            if year <= 1:
                return -1
            return 1
        except:
            return -1
    
    # Favicon
    def favicon(self, soup, domain):
        try:
            if isinstance(domain.domain_name, list):
                domain = domain.domain_name[0].lower()
            else:
                domain = domain.domain_name.lower()

            for head in soup.find_all('head'):
                for head.link in soup.find_all('link', href=True):
                    dots = [x.start(0) for x in re.finditer('\.', head.link['href'])]
                    if domain in head.link['href']:
                        return 1
                    else:
                        return -1
            return -1
        except:
            return -1
    
    # HTTPS token in URL
    def https_token(self, url):
        match = re.search('https://|http://', url)
        if match.start(0) == 0:
            url = url[match.end(0):]
        match = re.search('http|https', url)
        if match:
            return 1
        return -1
    
    # Request URL
    def request_url(self, soup, domain):
        try:
            i = 0
            success = 0

            if isinstance(domain.domain_name, list):
                domain = domain.domain_name[0].lower()
            else:
                domain = domain.domain_name.lower()

            for img in soup.find_all('img', src=True):
                dots = [x.start(0) for x in re.finditer('\.', img['src'])]
                if domain not in img['src']:
                    success = success + 1
                i = i + 1

            for audio in soup.find_all('audio', src=True):
                dots = [x.start(0) for x in re.finditer('\.', audio['src'])]
                if domain not in audio['src']:
                    success = success + 1
                i = i + 1

            for embed in soup.find_all('embed', src=True):
                dots = [x.start(0) for x in re.finditer('\.', embed['src'])]
                if domain not in embed['src']:
                    success = success + 1
                i = i + 1

            for i_frame in soup.find_all('i_frame', src=True):
                dots = [x.start(0) for x in re.finditer('\.', i_frame['src'])]
                if domain not in i_frame['src']:
                    success = success + 1
                i = i + 1
            percentage = success / float(i)
            return round(percentage, 2)
        except:
            return 1

    def evaluate_request(self, soup, domain):
        percentage = self.request_url(soup, domain)
        if percentage < 0.22:
            return 1
        elif percentage > 0.61:
            return -1
        return 0
    
    # SFH
    def sfh(self, soup, domain):
        try:
            if isinstance(domain.domain_name, list):
                domain = domain.domain_name[0].lower()
            else:
                domain = domain.domain_name.lower()

            for form in soup.find_all('form', action = True):
                if form['action'] == "" or form['action'] == "about:blank" :
                    return -1
                elif domain not in form['action']:
                    return 0
                else:
                    return 1
            return 1
        except:
            return -1
    
    # Email
    def submit_to_email(self, soup):
        try:
            for form in soup.find_all('form', action= True):
                if ("mail()" or "mailto:") in form['action']:
                    return -1
            return 1
        except:
            return -1
    
    # Abnormal URL
    def abnormal_url(self, domain, url):
        try:
            if isinstance(domain.domain_name, list):
                for domains in domain.domain_name:
                    if domains.lower() in url:
                        return 1
                return -1
            else:
                if domain.domain_name.lower() in url:
                    return 1
                else:
                    return -1
        except:
            return -1
            
    # Redirect
    def redirect(self, url):
        try:
            count = 0
            while True:
                r = requests.head(url)
                if 300 < r.status_code < 400:
                    url = r.headers['location']
                    count += 1
                else:
                    return count
        except:
            return 0
                
    def is_redirected(self, url):
        count = self.redirect(url)
        if count <= 1:
            return -1
        elif count >= 4:
            return 1
        return 0
    
    # Status bar
    def status_bar(self, html):
        if re.findall("<script>.+onmouseover.+</script>", html):
            return 1
        return -1
    
    # Right mouse
    def right_mouse(self, html):
        if re.findall(r"event.button ?== ?2", html):
            return 1
        return -1
    
    # Pop-up Window
    def pop_up(self, html):
        if re.findall(r"alert\(", html):
            return 1
        return -1
    
    # IFrame
    def iframe(self, soup):
        try:
            for iframe in soup.find_all('iframe', width=True, height=True, frameBorder=True):
                if iframe['width']=="0" and iframe['height']=="0" and iframe['frameBorder']=="0":
                    return 1
                else:
                    return -1
            return -1
        except:
            return 1
    
    # Age of domain
    def diff_month(self, d1, d2):
        return (d1.year - d2.year) * 12 + d1.month - d2.month
    def age_of_domain(self, domain):
        # Requests all the information about the domain
        try:
            whois_response = requests.get("https://www.whois.com/whois/" + (domain.domain_name[0].lower() if isinstance(domain.domain_name, list) else domain.domain_name.lower()))
            registration_date = re.findall(r'Registration Date:</div><div class="df-value">([^<]+)</div>', whois_response.text)[0]
            if self.diff_month(date.today(), date_parse(registration_date)) < 6:
                return 1
            else:
                return -1
        except:
            return 1
    # DNS
    def getDNS(self, url):
        domainTemp = re.findall(r"://([^/]+)/?", url)[0]
        if re.match(r"^www.", domainTemp):
            domainTemp = domainTemp.replace("www.", "")
        dns = 1
        try:
            d = whois.whois(domainTemp)
        except:
            dns = -1
        return dns
    
    # Web traffic
    def web_traffic(self, url):
        try:
            with request.urlopen("http://data.alexa.com/data?cli=10&dat=s&url=" + url) as response:
                html = response.read()
        except:
            return -1

        try:
            tree = ET.fromstring(html.decode())
            rank = (tree.findall('*/REACH'))[0].attrib['RANK']
        except:
            return -1
        if (int(rank) <= 100000):
            return 1
        return 0
    
    # Page rank
    def page_rank(self, global_rank):
        if global_rank > 0 and global_rank < 100000:
            return -1
        return 1
    
    # Google index
    def google_index(self, url):
        site = search(url, 5)
        if site:
            return 1
        else:
            return -1
    
    # Links pointing to page
    def point_to_page(self, html):
        number_of_links = len(re.findall(r"<a href=", html))
        if number_of_links == 0:
            return 1
        elif number_of_links > 2:
            return -1
        return 0
    
    # Generate data
    def generate_data(self, url):
        data = [0]*25

        # Convert the given URL into standard format
        if not re.match(r"^https?", url):
            url = "http://" + url
        
        try:
            response = requests.get(url, timeout=20)
            
            # Get html code
            html = response.text
                
            soup = BeautifulSoup(response.content, 'html.parser')

            domain = whois.whois(url)
            
            # Extract global rank of the website
            rank_checker_response = requests.post("https://www.checkpagerank.net/index.php", {
                "name": domain.domain_name[0].lower() if isinstance(domain.domain_name, list) else domain.domain_name.lower()
            })
            try:
                global_rank = int(re.findall(r"Global Rank: ([0-9]+)", rank_checker_response.text)[0])
            except:
                global_rank = -1

            # Generate data
            data[0] = self.url_ip(url)
            data[1] = self.url_length(url)
            data[2] = self.url_shorten(url)
            data[3] = self.url_symbol(url)
            data[4] = self.url_double_slash(url)
            data[5] = self.url_prefix_suffix(url)
            data[6] = self.url_sub_domain(url)
            data[7] = self.registration_time(domain)
            data[8] = self.favicon(soup, domain)
            data[9] = self.https_token(url)
            data[10] = self.evaluate_request(soup, domain)
            data[11] = self.sfh(soup, domain)
            data[12] = self.submit_to_email(soup)
            data[13] = self.abnormal_url(domain, url)
            data[14] = self.is_redirected(url)
            data[15] = self.status_bar(html)
            data[16] = self.right_mouse(html)
            data[17] = self.pop_up(html)
            data[18] = self.iframe(soup)
            data[19] = self.age_of_domain(domain)
            data[20] = self.getDNS(url)
            data[21] = self.web_traffic(url)
            data[22] = self.page_rank(global_rank)
            data[23] = self.google_index(global_rank)
            data[24] = self.point_to_page(html)

            return data
        except:
            data[0] = self.url_ip(url)
            data[1] = self.url_length(url)
            data[2] = self.url_shorten(url)
            data[3] = self.url_symbol(url)
            data[4] = self.url_double_slash(url)
            data[5] = self.url_prefix_suffix(url)
            data[6] = self.url_sub_domain(url)
            data[7] = -1
            data[8] = -1
            data[9] = self.https_token(url)
            data[10] = -1
            data[11] = -1
            data[12] = -1
            data[13] = -1
            data[14] = self.is_redirected(url)
            data[15] = -1
            data[16] = -1
            data[17] = -1
            data[18] = -1
            data[19] = -1
            data[20] = self.getDNS(url)
            data[21] = self.web_traffic(url)
            data[22] = 1
            data[23] = self.google_index(url)
            data[24] = -1
            
            return data