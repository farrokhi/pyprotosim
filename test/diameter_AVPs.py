#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.1 Last change at Nov 17, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Dummy tests for manual verification

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Testing handling basic AVP types
from libDiameter import *

if __name__ == "__main__":
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
    # IP Address v4 
    AVP=encodeAVP("Host-IP-Address","172.30.211.2")
    decodeAVP(AVP)
    # IP Address v6
    AVP=encodeAVP("NAS-IP-Address","::ffff:d9c8:4cca")
    decodeAVP(AVP)
    # OctetString
    AVP=encodeAVP("User-Password","teststr")
    decodeAVP(AVP)
    # UTF8 String 
    AVP=encodeAVP("User-Name","testutf")
    decodeAVP(AVP)
    # Grouped
    AVP=encodeAVP("Non-3GPP-User-Data", [
            encodeAVP("Subscription-Id", [
                encodeAVP("Subscription-Id-Data", "123456789"),
                encodeAVP("Subscription-Id-Type", 0)]), 
            encodeAVP("Non-3GPP-IP-Access", 0),
            encodeAVP("Non-3GPP-IP-Access-APN", 0),
            encodeAVP("MIP6-Feature-Vector", 1),
            encodeAVP("APN-Configuration", [
                encodeAVP("Context-Identifier", 1), 
                encodeAVP("Service-Selection", "a1"), 
                encodeAVP("PDN-Type", 0), 
                encodeAVP("AMBR", [
                    encodeAVP("Max-Requested-Bandwidth-UL", 500), 
                    encodeAVP("Max-Requested-Bandwidth-DL", 500)]), 
                encodeAVP("EPS-Subscribed-QoS-Profile", [
                    encodeAVP("QoS-Class-Identifier", 1), 
                    encodeAVP("Allocation-Retention-Priority", [
                        encodeAVP("Priority-Level", 0)])])]),
            encodeAVP("Context-Identifier", 0)])
    decodeAVP(AVP)
    # Time
    # Nov 17, 2012, 10:30:00
    unixtime=date2epoch(2012,11,17,10,30,00)
    AVP=encodeAVP("Event-Timestamp",unixtime)
    (tName,tValue)=decodeAVP(AVP)
    print epoch2date(tValue)
    # Enumerated name replacement
    AVP=encodeAVP("Service-Type","Framed")
    decodeAVP(AVP)
    AVP=encodeAVP("Service-Type",2)
    decodeAVP(AVP)    

######################################################        
# History
# Ver 0.2.6 - Mar 18, 2012 - initial version
# Ver 0.2.8 - May 12, 2012 - Grouped, Float
# Ver 0.3.1 - Nov 17, 2012 - Time, IPv6, enum named support
                

