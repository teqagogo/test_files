#################################################################
# EFG SOC June 2019 
# Name: search_offending_domains.py
# Release: 1.0
# Usage: python3 search_offending_domains.py -h
# 
# Description: search offending domains in db.aa419.org
#              and send results to siem syslog connector
#
#################################################################
from bs4 import BeautifulSoup
import requests
import re
import sys
import logging
import logging.handlers
import socket
import argparse
from querycontacts import ContactFinder

def is_valid_ip(str_ip_addr):
    ip_blocks = str(str_ip_addr).split(".")
    if len(ip_blocks) == 4:
        for block in ip_blocks:
            # Check if number is digit, if not checked before calling this function
            if not block.isdigit():
                return False
            tmp = int(block)
            if 0 > tmp > 255:
                return False
        return True
    return False

# Parse arguments
parser = argparse.ArgumentParser(prog='search_offending_domains.py',description='fake domain check against db.aa419.org using search string')

parser.add_argument('--search', action='store',
       help='search string')
parser.add_argument('--destination', action='store',
       default='127.0.0.1',
       help='destination ip address default is localhost')
parser.add_argument('--port', action='store', type=int,
       default=514,
       help='destination port default port 514')
parser.add_argument('--tcp', action='store_true',
       default=False,
       help='use TCP socket default is set to false')
parser.add_argument('--udp', action='store_true',
       default=True,
       help='use UDP socket default protocol for syslog')
parser.add_argument('--url', action='store_true',
       default=True,
       help='search string in urls database - default is true')
parser.add_argument('--site', action='store_true',
       default=False,
       help='search string in sites database - default is false')
parser.add_argument('--comment', action='store_true',
       default=False,
       help='search string in comments database - default is false')
parser.add_argument('--debug', action='store_true',
       default=False,
       help='debug mode')

if len(sys.argv[1:])==0:
    parser.print_help()
    parser.exit()
else:    
    args = parser.parse_args()
    search_string = args.search
    dest_ip = args.destination
    port = args.port
    tcp = args.tcp
    udp = args.udp
    url = args.url
    site = args.site
    comment = args.comment
    debug = args.debug

# Build and store requested search urls 

tab_urls = []

if url:
    #tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_Url=' + search_string + '&x_ScamType=bank&x_Status=active&x_Expired=N')
    tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_Url=' + search_string + '&x_Status=active&x_Expired=N')

if site:
    #tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_SiteName=' + search_string + '&x_ScamType=bank&x_Status=active&x_Expired=N')
    tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_SiteName=' + search_string + '&x_Status=active&x_Expired=N')

if comment:
    #tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_ScamType=bank&x_Status=active&x_Expired=N&x_PublicComments=' + search_string)
    tab_urls.append('https://db.aa419.org/fakebankslist.php?cmd=ADV&x_Status=active&x_Expired=N&x_PublicComments=' + search_string)

# Init logs 
tab_logs = []

# Looping on the search queries selected
for url in tab_urls:
    # run query
    if debug:
        print('\n[+] Executing search query: ' + url)
    page = requests.get(url, timeout=10)
    # store page content
    page_content=BeautifulSoup(page.content, "html.parser")
    # search for result link(s) in content
    for result in page_content.findAll('a', href=True):
        # filter to get fake domains only
        if re.search('fakebanksview.php',result['href']):
            str_log=''
            # prepare url to get fake domain details
            url_view='https://db.aa419.org/' + result['href']
            if debug:
                print('    [-] retrieving result using url: ' + url_view)
            str_log=url_view + ';'
            # get fake domain details page
            response_view = requests.get(url_view, timeout=10)
            # store result 
            content=BeautifulSoup(response_view.content, "html.parser")
            # parse html table with fake domains details
            divs = content.findAll("table", {"class": "ewTable"})
            abuse = ''
            for div in divs:
                row = ''
                rows = div.findAll('td')
                # process each table row
                for row in rows:
                    # filtering unwanted info and building syslog event
                    if not re.search('Project',row.text) and not re.search('domino',row.text):
                        #  reformat info on multiple lines to a single one and cleaning up output
                        comments = row.text.replace('\n', ' ')
                        comments = re.sub('==+', '', comments)
                        comments = re.sub('  +', ' ', comments)
                        if debug:
                            print('        [--] get value: ' + comments.lstrip().rstrip())
                        if is_valid_ip(comments.strip()):
                            qf = ContactFinder()
                            abuse=qf.find(comments.rstrip())
                            if debug:
                                print('        [++] abuse contact: ' + abuse[0])
                            str_log = str_log + comments.lstrip().rstrip() + ';' + abuse[0] + ';'
                        else:
                            if re.search('Spoofing', comments):
                                tab_comments=re.split(' ',comments.lstrip().rstrip())
                                str_log = str_log + tab_comments[0].replace(':', ' domain ') + tab_comments[1] + ' with email address ' + tab_comments[2] + ';'
                            else:
                                str_log = str_log + comments.lstrip().rstrip() + ';'
            # removing double ;
            str_log = str_log.replace(';;', ';')
            # remove last character if ;
            if str_log.endswith(';'):
                str_log = str_log[:-1]
            # store log line
            tab_logs.append(str_log)

# Create siem logger
siem_logger = logging.getLogger('PhishingDomainsCheck')
# Set logger severity
siem_logger.setLevel(logging.WARNING)

# bind handler
if tcp:
    # Define TCP SyslogHandler 
    if debug:
        print ('\n[+] Connecting to siem syslog connector at ip address ' + dest_ip + ' using TCP port ' + str(port))
    handler = logging.handlers.SysLogHandler(address = (dest_ip,port),  socktype=socket.SOCK_STREAM)
elif udp:
    # Define UDP SyslogHandler 
    if debug:
        print ('\n[+] Connecting to siem syslog connector at ip address ' + dest_ip + ' using UDP port ' + str(port))
    handler = logging.handlers.SysLogHandler(address = (dest_ip,port),  socktype=socket.SOCK_DGRAM)

# link handler to logger
siem_logger.addHandler(handler)

# sort unique logs and syslog them to the siem connector
for log in set(tab_logs):
    if debug:
        print ('\n   [-] sending log: ' + log)
    siem_logger.warning(log)
