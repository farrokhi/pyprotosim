#!/bin/sh
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3 Last change at Oct 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Script to compile calc tool

# Uncheck only one platform
PLATFORM=WIN
#PLATFORM=UNIX

if [ $PLATFORM = "UNIX" ]
then 
    CFLAGS="-MMD -O2 -Wall -g"
fi

gcc $CFLAGS a3a8.c -o a3a8

if [ $PLATFORM = "UNIX" ]
then 
    strip a3a8
else
    strip a3a8.exe
fi   
