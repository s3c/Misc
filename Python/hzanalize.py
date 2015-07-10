#!/usr/bin/env python

import sys, argparse
from collections import defaultdict

def calcfactors(repts):
  ffactors = defaultdict(int)
  for loopvar1 in range(len(repts)-1):
    for loopvar2 in range(loopvar1+1, len(repts)):
      repspc = repts[loopvar2]-repts[loopvar1]
      for loopvar3 in range(2, repspc+1):
        if(repspc % loopvar3 == 0):
          ffactors[loopvar3] += 1
  return dict(ffactors)

def searchrepeats(inpdata, args):
  repeatslist = list()
  for complen in range(int(round(args.max/args.align)*args.align), args.min-1, -args.align):
  #for complen in range(args.max, args.min-1, -1):
    for windowstart in range(0, len(inpdata)-complen+1, args.align):
      if args.verbose >= 2:
        print("Search length: " + str(complen) + " Window position: " + str(windowstart))
      foundrepeats = list()
      foundindex = windowstart
      cursubstr = inpdata[windowstart:windowstart+complen]
      while True:
        foundindex = inpdata.find(cursubstr, foundindex)
        if(foundindex != -1):
          if args.align == 1 or (args.align != 1 and foundindex % args.align == 0):
            foundrepeats += [foundindex]
          foundindex += complen
        else:
          break
      if len(foundrepeats) > 1:
        for loopvar in repeatslist:
          if loopvar["repstr"] == cursubstr:
            break
        else:
          repeatslist += [{"repstr": cursubstr, "replen": complen, "reppos": foundrepeats, "repfac": calcfactors(foundrepeats)}]
  return repeatslist

def displayverbose(repeatslist, inpdata):
  #Todo: disp stats for inpdata
  repstrmax = max([repeatslist[i]["replen"] for i in range(len(repeatslist))]) + 1
  repstrlen = max([len(str(repeatslist[i]["replen"])) for i in range(len(repeatslist))]) + 2
  repposmax = max([len(str(repeatslist[i]["reppos"]).translate(None, "[]")) for i in range(len(repeatslist))]) + 1
  repposlen = max([len(str(len(repeatslist[i]["reppos"]))) for i in range(len(repeatslist))]) + 2
  repfacmax = max([len(str(sorted(repeatslist[i]["repfac"], key=repeatslist[i]["repfac"].get, reverse=True)[:args.factors]).translate(None, "[]")) for i in range(len(repeatslist))]) + 1
  header = "{0:<{1}}|{2:<{3}}|{4:<{5}}|{6:<{7}}|{8:<{9}}".format("Str", repstrmax, "Len", repstrlen, "Cnt", repposlen, "Pos", repposmax, "Fac", repfacmax)
  print("{0}\n{1}".format(header, "-" * len(header)))
  allfactors = defaultdict(int)
  for loopvar in repeatslist:
    curfactors = loopvar["repfac"]
    for curfactor in curfactors:
      allfactors[curfactor] += curfactors[curfactor]
    ffrepfac = str(sorted(curfactors, key=curfactors.get, reverse=True)[:args.factors]).translate(None, "[]")
    ffreppos = str(loopvar["reppos"]).translate(None, "[]")
    print("{repstr:<{0}}|{replen:<{1}}|{6:<{7}}|{4:<{2}}|{5:<{3}}".format(repstrmax, repstrlen, repposmax, repfacmax, ffreppos, ffrepfac, len(loopvar["reppos"]),repposlen, **loopvar))    
  print("Most common factors for repeat distances: {0}".format(str(sorted(allfactors, key=allfactors.get, reverse=True)[:args.factors]).translate(None, "[]")))
  
def displayparse(repeatslist, inpdata):
  repview = [-1] * len(inpdata)
  for loopvar in range(len(repeatslist)):
    for loopvar2 in repeatslist[loopvar]["reppos"]:
      for loopvar3 in range(loopvar2, loopvar2+repeatslist[loopvar]["replen"]):
        #print("LV1: {}, LV2: {}, LV3: {}".format(loopvar, loopvar2, loopvar3))
        if repview[loopvar3] > 0:
          repview[loopvar3] = 0
        elif repview[loopvar3] == -1:
          repview[loopvar3] = loopvar + 1
      #break
  #print(repview) 
  for curchar in range(len(inpdata)):
    sys.stdout.write("\x1b[1;{1}m{0}\x1b[1;0m".format(inpdata[curchar], repview[curchar]+32)) 

parser = argparse.ArgumentParser(description="Search for patterns in files")
parser.add_argument("-f", "--file", help="File to search for patterns", required=True)
parser.add_argument("-m", "--min", help="Minimum pattern length, defaults to 3", type=int, default = 3)
parser.add_argument("-x", "--max", help="Maximum pattern length", type=int, default = 0)
parser.add_argument("-a", "--align", help="Aligh searches on given boundary value", type=int, default = 1)
parser.add_argument("-l", "--len", help="Assume all repeats are len long, not compatible with min, max or align", type=int, default = 0)
parser.add_argument("-v", "--verbose", help="Show status info on current search, use twice for more", action="count")
parser.add_argument("-e", "--factors", help="Display only n most common factors, defaults to 5", type=int, default = 5)
parser.add_argument("-t", "--translate", help="Translate patterns to common alphabet", action="count")
args = parser.parse_args()

try:
  inpfile = open(args.file)
  inpdata = inpfile.read()
  inpfile.close
except:
  sys.exit("Error opening input file")

if args.len != 0 and (args.min != 3 or args.max != 0 or args.align != 1):
  sys.exit("Argument --len not compatible with min, max or align")
elif args.len != 0:
  args.min = args.max = args.align = args.len
elif args.min == args.max == args.align:
  args.len = args.min

if args.max == 0:
  args.max = len(inpdata) / 2

if args.min < 2 or args.max < 2:
  sys.exit("The minimum pattern length must be at least two")  

if args.max < args.align:
  sys.exit("Maximum pattern length can't be less than align length")

repeatslist = searchrepeats(inpdata, args)
      
if args.verbose >= 1:
  displayverbose(repeatslist, inpdata)
displayparse(repeatslist, inpdata)
if args.translate:
  #stuff
  pass
