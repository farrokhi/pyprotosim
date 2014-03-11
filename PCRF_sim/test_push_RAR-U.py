#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2014
# Version 0.1.1, Last change on Mar 06, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")

# THIS TEST WILL SEND RAR-U MESSAGE TO PCRF server (IP_PCRF_SERVER:3869) WHICH WILL
# SEND RAR-U request to PCEF client
# YOUR PCEF CLIENT MUST BE CONNECTED TO PCRF BEFORE YOU SEND RAR-U
# EDIT PROPER VALUES IN SESSION_ID, CHARGING-RULE-NAME, 

from libDiameter import *

import datetime
import time

 

 

def create_RAR():

    # Let's build RAR-U
    RAR_avps=[ ]
    RAR_avps.append(encodeAVP('Session-Id', SESSION_ID))
    RAR_avps.append(encodeAVP('Product-Name', 'PCRF'))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 0))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 10415))
    RAR_avps.append(encodeAVP('Supported-Vendor-Id', 11111))
    RAR_avps.append(encodeAVP('Auth-Application-Id', 16777238))
    RAR_avps.append(encodeAVP('Destination-Realm', 'myrealm.example'))
    RAR_avps.append(encodeAVP('Destination-Host', 'vmclient.myrealm.example'))
    RAR_avps.append(encodeAVP('Re-Auth-Request-Type', 0))
    RAR_avps.append(encodeAVP('Subscription-Id',[encodeAVP('Subscription-Id-Data',IDENTITY), encodeAVP('Subscription-Id-Type', 0)]))
    RAR_avps.append(encodeAVP('Charging-Rule-Install',[encodeAVP('Charging-Rule-Name', 'activate_service_smtp'), encodeAVP('Charging-Rule-Name', 'set_service_1234_on')]))
    RAR_avps.append(encodeAVP('Charging-Rule-Remove',[encodeAVP('Charging-Rule-Name', 'activate_service_filter'), encodeAVP('Charging-Rule-Name', 'set_service_14445_off')]))

    # Create message header (empty)
    RAR=HDRItem()
    # Set command code
    RAR.cmd=dictCOMMANDname2code("Re-Auth")
    # Set Application-Id
    RAR.appId=16777238
    # Set Hop-by-Hop and End-to-End
    initializeHops(RAR)
    # Set Proxyable flag
    setFlags(RAR,DIAMETER_HDR_PROXIABLE)
    # Add AVPs to header and calculate remaining fields
    msg=createReq(RAR,RAR_avps)
    # msg now contains RAR Request as hex string
    return msg
   
 
if __name__ == "__main__":
    
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("../dictDiameter.xml")
    ################
    # THIS IS IP AND PORT OF PCRF_SERVER  WHICH LISTENS COMMANDS FROM YOU.
    # DON'T CHANGE THIS PORT TO 3868 WHERE PCRF SERVER IS CONNECTED FROM PCEF client
    # SET HERE YOUR PCRF SIMULATOR IP/PORT:
    
    HOST="127.0.0.1"
    PORT=3869
    IDENTITY="1234567891"                        
    APPLICATION_ID=4
    
    # SET THIS TO YOUR SESSION ID
    SESSION_ID='example;1226572656725762572676'
    # Let's assume that my Diameter messages will fit into 4k
    MSG_SIZE=4096
    # Connect to server
    Conn=Connect(HOST,PORT)
    ###########################################################

    msg=create_RAR()
    # msg now contains STR as hex string
    logging.debug("+"*30)
    # send data
    Conn.send(msg.decode("hex"))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    print "Received RAR",received.encode("hex")

    ###########################################################
    # And close the connection
    Conn.close()

