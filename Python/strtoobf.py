#!/usr/bin/env python3
#Takes a string input and for each character converts it to a random binary representation of n bits where n is calculated to use the least amount of bits for the hard coded character set 

import sys, string, random, math

if len(sys.argv) != 2:
  print("You fucked up, single string param, we strip all non alphabetic")
  exit(1)

mcharset = list("abcdefghijklmnopqrstuvwxyz")
random.shuffle(mcharset)
mcharset = ''.join(mcharset)
msyml = math.ceil(math.log(len(mcharset), 2))
fstr = str()

minpstr = sys.argv[1].lower()
mfinpstr = [minpstr[x] for x in range(len(minpstr)) if minpstr[x] in mcharset]

if len(mfinpstr) == 0:
  print("You fucked up, give us some decent input")
  exit(2)

for lvar in range(len(mfinpstr)):
  mcharpos = mcharset.index(mfinpstr[lvar])
  moutpt = str(bin(mcharpos))[2:].zfill(msyml)
  fstr += moutpt.translate(str.maketrans("01", "ab"))
print(fstr)
