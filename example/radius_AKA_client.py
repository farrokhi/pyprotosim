#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.7, Last change on May 16, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

#Next two lines are to include parent directory for testing
import sys
sys.path.append("..")
# Remove them normally

# Radius EAP-AKA client

from libRadius import *
import eap
import datetime
import time

def prepareKeysFromTriplets(a1,a2,a3):
    #a=Authentication-Information-SIM
    #Treat as String, not hex
    #47fccae1253d85d2+fb86d937+cbfe6115271cc21db2d3e000
    rand=a1[0:16]+a2[0:16]+a3[0:16]
    kc=a1[32:48]+a2[32:48]+a3[32:48]
    return rand,kc

def Payload_Identity():
    # Let's build EAP-Payload Identity AVP
    # Create EAP-Payload (empty)
    EAP=eap.EAPItem()
    # Set command code
    # Remember - Requests normally starts from AAA-> UE, so 
    # even when skipped, identity is actually an response
    EAP.cmd=eap.EAP_CODE_RESPONSE
    # Set id
    EAP.id=1
    # Set type
    EAP.type=eap.EAP_TYPE_IDENTITY
    # Add Identity
    EAP.msg=eap.addEAPIdentity(IDENTITY)
    Payload=eap.encode_EAP(EAP)
    return Payload

def Payload_AKA_Identity(ID,ETYPE):
    # Let's build EAP-Payload with AT_IDENTITY AVP
    # Create EAP-Payload (empty)
    EAP=eap.EAPItem()
    # Set command code
    # Remember - Requests normally starts from AAA-> UE, so 
    # even when skipped, identity is actually an response
    EAP.cmd=eap.EAP_CODE_RESPONSE
    # Set id 
    EAP.id=ID
    # Set type
    EAP.type=ETYPE
    # Set sub-type
    EAP.stype=eap.dictEAPSUBname2type("AKA-Identity")
    EAP.avps.append(("AT_IDENTITY",IDENTITY.encode("hex")))
    Payload=eap.encode_EAP(EAP)
    # Payload now contains EAP-Payload AVP
    return Payload  

def Payload_Challenge_Response(ID,RAND,ETYPE):
    # Let's build EAP-Payload Challenge-Response AVP
    # Create EAP-Payload (empty)
    EAP=eap.EAPItem()
    # Set command code
    EAP.cmd=eap.EAP_CODE_RESPONSE
    # Set id 
    EAP.id=ID
    # Set type
    EAP.type=ETYPE
    # Set sub-type
    EAP.stype=eap.dictEAPSUBname2type("AKA-Challenge")
    # RAND is copied from Challenge
    # These values can be calculated or entered manually
    #XRES,CK,IK,AK,AKS=eap.aka_calc_milenage(OP,Ki,RAND)
    # Or copy from MAA
    # IK=Identity-Key
    # CK=Confidentiality-Key
    # XRES=SIP-Authorization
    IK   = "952A44900B7FAFF249763475B3AA77EE"; 
    CK   = "F16A4BB5112DBA580132E29882FEC143"; 
    XRES = "E818FBF691AE3B97";
    KENCR,KAUT,MSK,EMSK,MK=eap.aka_calc_keys(IDENTITY,CK,IK)
    # Add AT_RES
    EAP.avps.append(("AT_RES",XRES))
    # Add AT_MAC as last
    eap.addMAC(EAP,KAUT,"")
    # Do not add any AVPs after adding MAC
    Payload=eap.encode_EAP(EAP)
    # Payload now contains EAP-Payload AVP
    return Payload
    
def create_Identity_Request():
    # Let's build Request+EAP-Identity-Payload 
    REQ_avps=[]
    REQ_avps.append(encodeAVP("NAS-Identifier", "default"))
    REQ_avps.append(encodeAVP("Calling-Station-Id", CALLING_ID))
    Payload=Payload_Identity()
    REQ_avps.append(encodeAVP("EAP-Message",Payload.decode("hex")))
    REQ_avps.append(encodeAVP("Called-Station-Id", CALLED_ID))
    REQ_avps.append(encodeAVP("NAS-IP-Address", NAS_IP))
    REQ_avps.append(encodeAVP("NAS-Port-Id", NAS_PORT))
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.Code=dictCOMMANDname2code("Access-Request")
    REQ.Authenticator=createAuthenticator()
    REQ.Identifier=1
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains CER Request as hex string
    return msg   

def create_Identity_Response(RID,ID,ETYPE):
    # Let's build Response+EAP-Payload with AT_IDENTITY
    REQ_avps=[]
    REQ_avps.append(encodeAVP('State', STATE))
    REQ_avps.append(encodeAVP("NAS-Identifier", "default"))
    REQ_avps.append(encodeAVP("Calling-Station-Id", CALLING_ID))
    Payload=Payload_AKA_Identity(ID,ETYPE)
    REQ_avps.append(encodeAVP("EAP-Message",Payload.decode("hex")))
    REQ_avps.append(encodeAVP("Called-Station-Id", CALLED_ID))
    REQ_avps.append(encodeAVP("NAS-IP-Address", NAS_IP))
    REQ_avps.append(encodeAVP("NAS-Port-Id", NAS_PORT))
    # Create message header (empty)
    REQ=HDRItem()
    # Set command code
    REQ.Code=dictCOMMANDname2code("Access-Request")
    REQ.Authenticator=createAuthenticator()
    REQ.Identifier=RID
    # Add AVPs to header and calculate remaining fields
    msg=createReq(REQ,REQ_avps)
    # msg now contains CER Request as hex string
    return msg
    
def create_Challenge_Response(RID,ID,RAND,ETYPE):
    # Create message header (empty)
    RES=HDRItem()
    # Set command code
    RES.Code=dictCOMMANDname2code("Access-Request")
    RES.Authenticator=createAuthenticator()
    RES.Identifier=RID
    # Let's build Response+Response-Payload 
    RES_avps=[]
    RES_avps.append(encodeAVP("State", STATE))
    RES_avps.append(encodeAVP("Calling-Station-Id", CALLING_ID))
    Payload=Payload_Challenge_Response(ID,RAND,ETYPE)
    RES_avps.append(encodeAVP("EAP-Message",Payload.decode("hex")))
    RES_avps.append(encodeAVP("Called-Station-Id", CALLED_ID))
    RES_avps.append(encodeAVP("NAS-Identifier", "default"))
    RES_avps.append(encodeAVP("User-Name", "testuser"))
    RES_avps.append(encodeAVP("User-Password", PwCrypt("mms",RES.Authenticator,"secret")))
    RES_avps.append(encodeAVP("Acct-Session-Id", "a1"))
    RES_avps.append(encodeAVP("NAS-IP-Address", NAS_IP))
    RES_avps.append(encodeAVP("NAS-Port-Id", NAS_PORT))
    # Add AVPs to header and calculate remaining fields
    msg=createReq(RES,RES_avps)
    # msg now contains Response as hex string
    return msg    
    
def dump_Payload(avps):
    for avp in avps:
        (name,value)=decodeAVP(avp)
        if name=='EAP-Message':
           print 'Response:',name,'=',value.encode('hex')
           E=eap.decode_EAP(value.encode('hex'))
           for eavp in E.avps:
               (code,data)=eavp
               print code,'=',data
        else:
           print 'Response:',name,'=',value.encode("hex")
           
    
if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    #logging.basicConfig(level=logging.INFO)
    LoadDictionary("../dictRadius.xml")
    eap.LoadEAPDictionary("../dictEAP.xml")
    HOST="10.14.5.148"
    PORT=1812
    #First digit is 1 for SIM, 0 for AKA
    IDENTITY="0121111234561000@wlan.mnc023.mcc262.3gppnetwork.org"
    CALLING_ID="1234"
    CALLED_ID="mms"
    NAS_IP="1.2.3.4"
    NAS_PORT="19"
    ETYPE=eap.EAP_TYPE_AKA
    SIMULATOR=0
    # Let's assume that my Radius messages will fit into 4k
    MSG_SIZE=4096
    ###########################################################
    Conn=socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    # socket is in blocking mode, so let's add a timeout
    Conn.settimeout(5)
    ###########################################################  
    # Create Identity Payload    
    msg=create_Identity_Request()
    # msg now contains EAP Request+Identity Payload as hex string
    logging.debug("+"*30)
    # send data
    Conn.sendto(msg.decode("hex"),(HOST,PORT))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # Process response
    EAPAnyId=HDRItem()
    stripHdr(EAPAnyId,received.encode("hex"))
    RID=EAPAnyId.Identifier+1    
    Identity_avps=splitMsgAVPs(EAPAnyId.msg)
    Identity_Payload=findAVP("EAP-Message",Identity_avps)
    STATE=findAVP("State",Identity_avps)
    # Display response for better undestanding
    dump_Payload(Identity_avps)    
    E=eap.decode_EAP(Identity_Payload.encode('hex'))
    ###########################################################
    # If Identity round is not skipped, we need to send AT_IDENTITY
    msg=create_Identity_Response(RID,E.id,ETYPE)
    # msg now contains EAP Request+Identity Payload as hex string
    logging.debug("+"*30)
    # send data
    Conn.sendto(msg.decode("hex"),(HOST,PORT))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    ###########################################################
    # Process Challenge
    # split header and AVPs
    EAPChallenge=HDRItem()
    stripHdr(EAPChallenge,received.encode("hex"))
    RID=EAPChallenge.Identifier+1
    # If you do not want to process full msg, you can stop here without any harm
    # We need Payload from EAP-Challenge
    Challenge_avps=splitMsgAVPs(EAPChallenge.msg)
    # Display response for better undestanding
    dump_Payload(Challenge_avps)
    Challenge_Payload=findAVP("EAP-Message",Challenge_avps)
    if Challenge_Payload<>ERROR:
        # We need AT_RAND to create response
        E=eap.decode_EAP(Challenge_Payload.encode('hex'))
        RAND=findAVP("AT_RAND",E.avps)
        if RAND == ERROR:
	        bailOut("no RAND received")	
    else:
        bailOut("No Payload received")
    ###########################################################
    msg=create_Challenge_Response(RID,E.id,RAND,ETYPE)
    # msg now contains EAP Response as hex string
    logging.debug("+"*30)
    # send data
    Conn.sendto(msg.decode("hex"),(HOST,PORT))
    # Receive response
    received = Conn.recv(MSG_SIZE)
    # split header and AVPs
    EAPOK=HDRItem()
    stripHdr(EAPOK,received.encode("hex"))
    # No decoding is needed.
    # Normally - this is the end.
    ###########################################################
    # And close the connection
    Conn.close()
    
    
######################################################        
# History
# 0.2.8 - Oct 04, 2012 - Radius EAP-AKA initial version
