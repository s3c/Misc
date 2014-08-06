#!/bin/bash

if [ -z $1 ]; then
    echo "Specify host file"
    exit
fi

if [ -z $2 ]; then
    echo "Specify output file"
    exit
fi

if [ ! -f "/usr/bin/dot" ]; then
    echo "Dot not found, install graphviz first"
    exit
fi

if [ ! -f "/usr/bin/tcptraceroute" ]; then
    echo "Tcptraceroute not found, go install it"
    exit
fi

rm $2.png &>/dev/null
rm $2.dot &>/dev/null

echo "strict graph $2 {" >> $2.dot

for hosts in `cat $1`
do
    echo Tracing to: $hosts
    curcolor="0.$[$RANDOM % 100] 0.$[$RANDOM % 100] 0.$[$RANDOM % 100]"
    prev=LOCAL
    mloop=1
    lastvalid=LOCAL
    tcptraceroute -n -q 1 -w 1 -m 10 $hosts 2>/dev/null >> tempfile.txt
    while read curdst; do
        hopip=`echo $curdst | grep -o -E '([0-9]{1,3}\.){3}[0-9]{1,3}'`
        if [ -z $hopip ]; then
            echo "\"$prev\" -- \"Prev $lastvalid Hop $mloop\" [color=\"$curcolor\"]" >> $2.dot
            prev="Prev $lastvalid Hop $mloop"
        else
            final=`echo $curdst | grep -o -E '(\[open\]|\[closed\])'`
            if [ "$final" == "[open]" -o "$final" == "[closed]" ]; then
                hopname=`nslookup $hopip | grep -o -E '=.+' | grep -o -E '[^= ].+'`
                echo "\"$prev\" -- \"$hopip\n$hopname\" [color=\"$curcolor\"]" >> $2.dot
            else  
                echo "\"$prev\" -- \"$hopip\" [color=\"$curcolor\"]" >> $2.dot
            fi
            lastvalid=$hopip
            prev=$hopip
        fi
        let "mloop=$mloop+1"       
    done < tempfile.txt
    rm tempfile.txt
done

echo "}" >> $2.dot

dot -Tpng -o $2.png $2.dot &>/dev/null
