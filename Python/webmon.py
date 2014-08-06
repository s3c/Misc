#!/usr/bin/env python3

import sys
import argparse
import string
import csv
import urllib.request
import threading
import time
import hashlib
import os
import re
import urllib.parse
import random

URL_CHARS = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~:/?#[]@!$&'()*+;=%"

def saveoutput(url, respmd5, urlresp, frespmd5, furlresp, reqnum, threadval):
    curhost = urllib.parse.urlparse(url).netloc
    debugfile = open("{0}-{3}-{1}-PreRe-{2}.html".format(curhost, str(reqnum).zfill(3), respmd5, threadval), "wb")  
    debugfile.write(urlresp)
    debugfile.close()
    debugfile = open("{0}-{3}-{1}-PosRe-{2}.html".format(curhost, str(reqnum).zfill(3), frespmd5, threadval), "wb")
    debugfile.write(furlresp)
    debugfile.close()

class URLPollingThread(threading.Thread):
    def __init__(self, reqobj, leave, verbose, increment):
        threading.Thread.__init__(self)
        self.__curreq = reqobj
        self.__leave = leave
        self.__verbose = verbose
        self.__increment = increment
        
    def run(self):
        threadval = str(random.randint(0, 99)).zfill(2)
        if "http" not in self.__curreq["url"]:
            self.__curreq["url"] = "http://" + self.__curreq["url"]
        urlreq = urllib.request.Request(self.__curreq["url"])
        if self.__curreq["cookie"]:
            urlreq.add_header('Cookie', self.__curreq["cookie"])
        if self.__curreq["post"]:
            urlreq.data = self.__curreq["data"]
        waittime = int(self.__curreq["time"])
        reqnum = 0
        while True:
            if self.__verbose:
                print("Checking page: {0}".format(self.__curreq["url"]))
            urlresp = urllib.request.urlopen(urlreq).read()
            furlresp = urlresp
            while True:
                furlresp2 = re.sub(self.__curreq["filter"].encode(), "".encode(), furlresp)
                if furlresp == furlresp2:
                    break
                else:
                    furlresp = furlresp2
            respmd5 = hashlib.md5(urlresp).hexdigest()
            frespmd5 = hashlib.md5(furlresp).hexdigest()
            if self.__curreq["md5"] and self.__curreq["md5"] != frespmd5:
                if self.__verbose == 2:
                    saveoutput(self.__curreq["url"], respmd5, urlresp, frespmd5, furlresp, reqnum, threadval)
                self.__curreq["md5"] = frespmd5
                if self.__verbose:
                    print("Page changed: {0}".format(self.__curreq["url"]))
                if self.__curreq["command"]:
                    curcommand = re.sub("@".encode(), self.__curreq["url"].encode(), self.__curreq["command"].encode()).decode()
                    if self.__verbose:
                        print("Executing command: {0}".format(curcommand))
                    os.system("bash -c \"" + curcommand + "\"")
                if self.__leave:
                    break
            elif not self.__curreq["md5"]:
                self.__curreq["md5"] = frespmd5
                if self.__verbose == 2:
                    saveoutput(self.__curreq["url"], respmd5, urlresp, frespmd5, furlresp, reqnum, threadval)
            elif self.__verbose == 3:
                saveoutput(self.__curreq["url"], respmd5, urlresp, frespmd5, furlresp, reqnum, threadval)
                pass
            if waittime == 0:
                break
            if self.__verbose:
                print("Next Check for {0} in {1}s".format(self.__curreq["url"], waittime))
            time.sleep(waittime)
            waittime += self.__increment
            reqnum += 1

def validset(mstring, dset):
    mstrings = ''.join([mstring[x] for x in range(len(mstring)) if mstring[x] in dset])
    return mstrings == mstring

def formatreq(url, post, cookie, time, command, md5, refilter):
    if not validset(url, URL_CHARS):
        raise ValueError("Invalid URL specified")
    if not validset(cookie, string.printable):
        raise ValueError("Invalid Cookie specified")
    if int(time) < 0:
        raise ValueError("Invalid time specified")
    if not validset(command, string.printable):
        raise ValueError("Command string not valid")
    if not validset(md5, string.hexdigits):
        raise ValueError("Invalid md5 hash specified")
    if not validset(refilter, string.printable):
        raise ValueError("Invalid filter specified")
    return [{"url": url, "post": post, "cookie": cookie, "time": int(time), "command":command, "md5": md5, "filter": refilter}]

def loadbatch(filename):
    batchlist = list()
    inpfile = open(args.batch, "rt")
    csvreader = csv.reader(inpfile)
    for currow in csvreader:
        batchlist += formatreq(*currow)
    inpfile.close()
    return batchlist

def savebatch(filename, batch_list):
    outfile = open(filename, 'wt')
    csvwriter = csv.writer(outfile)
    newlist = [[x["url"], x["post"], x["cookie"], x["time"], x["command"], x["md5"], x["filter"]] for x in batch_list]
    csvwriter.writerows(newlist)
    outfile.close()

parser = argparse.ArgumentParser(description="Monitor web pages for change", epilog="Note, using ',' in filters breaks csv support")
parser.add_argument("-u", "--url", help="URL to check, if none is given a batch file is needed, default uses webmon.csv for batch commands", default="")
parser.add_argument("-p", "--post", help="Use POST method instead with following data", default="")
parser.add_argument("-c", "--cookie", help="Cookie to use for connection", default="")
parser.add_argument("-t", "--time", help="Time in seconds to wait between checks, ie, polling, this is disabled by default", type=int, default=0)
parser.add_argument("-e", "--execute", help="Command to run when page changes, @ is replaced with URL", default="")
parser.add_argument("-m", "--md5", help="MD5 checksum of last run", default="")
parser.add_argument("-f", "--filter", help="ReGex to filter from responses before md5", default="")
parser.add_argument("-b", "--batch", help="Batch file in CSV format with above params in order", default="webmon.csv")
parser.add_argument("-s", "--save", help="Save request in batch file, if no file is specified with -b, webmon.csv file is used", action="count")
parser.add_argument("-l", "--leave", help="Stop polling individual request if change is detected", action="count")
parser.add_argument("-v", "--verbose", help="Verbose output, double for debug", action="count")
parser.add_argument("-i", "--increment", help="Increment time by n units on each iteration", type=int, default=0)
args = parser.parse_args()

if args.url:
    reqlist = formatreq(args.url, args.post, args.cookie, args.time, args.execute, args.md5, args.filter)
else:    
    try:
        reqlist = loadbatch(args.batch)
    except FileNotFoundError:
        if args.batch == "webmon.csv":
            parser.print_help()
            sys.exit(1)
        else:
            print("Failed to load batch file: {0}".format(args.batch))
            sys.exit(2)

threadlist = list()
for threadindex in range(len(reqlist)):
    threadlist += [URLPollingThread(reqlist[threadindex], args.leave, args.verbose, args.increment)]
    threadlist[threadindex].start()
for curthread in threadlist:
    curthread.join()

if args.url and args.save:
    try:
        reqlist += loadbatch(args.batch)
    except FileNotFoundError:
        pass
    savebatch(args.batch, reqlist)
elif not args.url:
    savebatch(args.batch, reqlist)
