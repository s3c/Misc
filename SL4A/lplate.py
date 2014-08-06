#!/usr/bin/env python

import android
import re

droid = android.Android()

finp = open("/sdcard/sl4a/scripts/wordsEn.txt")
#finp = open("wordsEn.txt")
readw = finp.read()
readw = readw.split()

while True:
    ucode = droid.dialogGetInput("Input", "Enter Letters", "").result
    if not ucode:
        exit()
    
    wlist = list()
    ostr = str()
    sstr = ''.join([x + ".*" for x in ucode])
    
    for curword in readw:
        if re.search(sstr, curword):
            wlist += [curword]
            
    wlist.sort(key=len, reverse=True)
    for i in range(min(10, len(wlist))):
        ostr += wlist[i] + "\n"
        
    if len(ostr) == 0:
        ostr = "No matches found"
    
    #print(ostr)
    
    droid.dialogCreateAlert("Result", ostr)
    droid.dialogSetPositiveButtonText('Ok')
    droid.dialogShow()
    droid.dialogGetResponse().result
    
