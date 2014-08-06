#!/usr/bin/env python
#Created by MJS, generates a custom De Bruijn sequence
#De Bruijn code taken directly from Wikipedia

import sys, math, argparse

def de_bruijn(k, n):
    a = [0] * k * n
    sequence = []
    def db(t, p):
        if t > n:
            if n % p == 0:
                for j in range(1, p + 1): sequence.append(a[j])
        else:
            a[t] = a[t - p]
            db(t + 1, p)
            for j in range(a[t - p] + 1, k):
                a[t] = j
                db(t + 1, t)
    db(1,1)
    return sequence

def find_substrings(mainstring, substring):
  if mainstring.count(substring) == 0:
    return "None "
  fwdstrpos = 0;
  outputfind = str()
  for strcount in range(mainstring.count(substring)):
    fwdstrpos = mainstring.find(substring, fwdstrpos)
    outputfind += str(fwdstrpos) + " "
    fwdstrpos += 1;
  return outputfind

try:
  parser = argparse.ArgumentParser(description='Generates a De Bruijn sequence with the given parameters')

  parser.add_argument("-o", "--order", default=0, help="Sequence order", type=int)
  parser.add_argument("-l", "--length", default=0, help="Length of output", type=int)
  parser.add_argument("-a", "--alphabet", default="abcdefghijklmnopqrstuvwxyz", help="Alphabet to use for sequence")
  parser.add_argument("-f", "--find", help="Look for all possible occurences of given data")  

  parseresults = parser.parse_args()

  order = parseresults.order
  length = parseresults.length
  alphabet = parseresults.alphabet
  findstr = parseresults.find
  alphabetlen = len(alphabet)

  if order == 0 and length == 0:
    parser.parse_args(["-h"])

  if alphabetlen == 1:
    sys.exit("Alphabet too short")

  if order == 0 and length != 0:
    order = int(math.ceil(math.log(length)/math.log(alphabetlen)))
    maxlength = int(math.pow(alphabetlen, order))
  elif order != 0 and length == 0:
    maxlength = int(math.pow(alphabetlen, order))
    length = maxlength
  else:
    maxlength = int(math.pow(alphabetlen, order))
    if length > maxlength:
      sys.exit("Length too long for given alphabet and order")
    
  generated = de_bruijn(alphabetlen, order)
  outputstr = str()
  for loop in range(length):
    outputstr += alphabet[generated[loop]]

  print("Alphabet (" + str(alphabetlen) + "): " + alphabet)
  print("Order: " + str(order) + " MaxLen: " + str(maxlength) + " ReqLen: " + str(length))

  if findstr != None:
    print("Searching for: " + findstr)
    print("AscStd: " + find_substrings(outputstr, findstr))
    print("AscRev: " + find_substrings(outputstr, findstr[::-1]))
    try:
      findstrhex = findstr
      if len(findstrhex) % 2:
        findstrhex = "0" + findstrhex
      print("HexStd: " + find_substrings(outputstr, findstrhex.decode("hex")))
      revfindstrhex = str()
      for revloop in range(-2, -len(findstrhex)-1, -2):
        revfindstrhex += findstrhex[revloop] + findstrhex[revloop+1]
      print("HexRev: " + find_substrings(outputstr, revfindstrhex.decode("hex")))
    except:
      print("HexStd: None")
      print("HexRev: None")
  else:
    print("Output: " + outputstr)

except Exception as GenExep:
  print(GenExep)
  sys.exit("Something bad happened.")
