#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.2.6 Last change at Mar 18, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Testing handling basic AVP types
from diamClient import *



if __name__ == '__main__':
    #logging.basicConfig(level=logging.DEBUG)
    logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictDiameter.xml")
    # Int32
    AVP=encodeAVP("Error-Cause",1025)
    decodeAVP(AVP)
    # Int64
    AVP=encodeAVP("Value-Digits",12345)
    decodeAVP(AVP)
    # Unsigned32
    AVP=encodeAVP("NAS-Port",2345)
    decodeAVP(AVP)
    # Unsigned64
    AVP=encodeAVP("Framed-Interface-Id",2345)
    decodeAVP(AVP)
    # Float32
    AVP=encodeAVP("Token-Rate",12.34)
    decodeAVP(AVP)
    # Float64
    AVP=encodeAVP("SCAP-Cost",12.34)
    decodeAVP(AVP)    
    # IP Address
    AVP=encodeAVP("Host-IP-Address",'172.30.211.2')
    decodeAVP(AVP)
    # OctetString
    AVP=encodeAVP("User-Password",'teststr')
    decodeAVP(AVP)
    # UTF8 String
    AVP=encodeAVP("User-Name",'testutf')
    decodeAVP(AVP)
    # Grouped
    list=[]
    list.append(encodeAVP("SIP-Authentication-Scheme","EAP-AKA'"))
    AVP=encodeAVP("SIP-Auth-Data-Item",list)
    decodeAVP(AVP)

