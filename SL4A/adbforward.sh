#!/bin/bash

#.bashrc
#export AP_PORT=9999
#export export PATH=$PATH:/home/user/android-sdk-linux/platform-tools

adb forward tcp:9999 tcp:4321
