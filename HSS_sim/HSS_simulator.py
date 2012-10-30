#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - October 2012
# Version 0.2.9, Last change on Oct 10, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# HSS Simulator build upon libDiameter 
# interrupt the program with Ctrl-C

#Next two lines include parent directory for where libDiameter is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import SocketServer
from libDiameter import *

class MyTCPHandler(SocketServer.BaseRequestHandler):
    """
    The RequestHandler class for our server.

    It is instantiated once per connection to the server, and must
    override the handle() method to implement communication to the
    client.
    """

    def __init__(self, request, client_address, server):
        SocketServer.BaseRequestHandler.__init__(self, request, client_address, server)
        return
    BUFFER_SIZE =1024 
    def handle(self):
        # self.request is the TCP socket connected to the client
        while 1:
            dbg="Connection:",self.client_address[0]
            logging.info(dbg)
            #get input ,wait if no data
            data=self.request.recv(self.BUFFER_SIZE)
            #suspect more data (try to get it all without stopping if no data)
            if (len(data)==self.BUFFER_SIZE):
                while 1:
                    try:
                        data+=self.request.recv(self.BUFFER_SIZE, socket.MSG_DONTWAIT)
                    except:
                        #error means no more data
                        break
            #no data found exit loop (posible closed socket)
            if (data != ""): 
                #processing input
                dbg="Incomming message",data.encode("hex")
                logging.info(dbg)
                ret=process_request(data.encode("hex")) 
                if ret==ERROR:
                    dbg="Error responding",ret
                    logging.error(dbg)
                else:
                    dbg="Sending response",ret
                    logging.info(dbg)
                    self.request.send(ret.decode("hex"))


def create_CEA(H):
    # Let's build Capabilites-Exchange Answer
    CEA_avps=[]
    CEA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    CEA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    CEA_avps.append(encodeAVP("Vendor-Id", 28458))
    CEA_avps.append(encodeAVP("Product-Name", "aaaClient-HSSsim"))
    CEA_avps.append(encodeAVP("Host-IP-Address", "1.1.3.5"))
    CEA_avps.append(encodeAVP("Acct-Application-Id", 4294967295L))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 10415))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 12951))
    CEA_avps.append(encodeAVP("Supported-Vendor-Id", 5535))
    CEA_avps.append(encodeAVP("Inband-Security-Id", 0))
    CEA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    CEA=HDRItem()
    # Set command code
    CEA.cmd=H.cmd
    # Set Application-id
    CEA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    CEA.HopByHop=H.HopByHop
    CEA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(CEA,CEA_avps)
    # ret now contains CEA Response as hex string
    return ret

def create_DWA(H):
    # Let's build Diameter-WatchdogAnswer 
    DWA_avps=[]
    DWA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DWA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DWA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    # Create message header (empty)
    DWA=HDRItem()
    # Set command code
    DWA.cmd=H.cmd
    # Set Application-id
    DWA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DWA.HopByHop=H.HopByHop
    DWA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DWA,DWA_avps)
    # ret now contains DWA Response as hex string
    return ret

def create_UTC(H,msg):
    # Let's build Unable to comply packet
    DWA_avps=[]
    DWA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    DWA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    DWA_avps.append(encodeAVP("Result-Code", 5012)) #UNABLE TO COMPLY 5012
    DWA_avps.append(encodeAVP("Error-Message", msg))
    # Create message header (empty)
    DWA=HDRItem()
    # Set command code
    DWA.cmd=H.cmd
    # Set Application-id
    DWA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    DWA.HopByHop=H.HopByHop
    DWA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(DWA,DWA_avps)
    # ret now contains DWA Response as hex string
    return ret

def create_SAA(H):
    # Let's build Service-Asignment Answer
    # We need Session-Id from Request
    SAR_avps=splitMsgAVPs(H.msg)
    sesID=findAVP("Session-Id",SAR_avps) 
    userName=findAVP("User-Name",SAR_avps)
    SAA_avps=[]
    SAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    SAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    SAA_avps.append(encodeAVP("Session-Id", sesID))
    SAA_avps.append(encodeAVP("User-Name", userName))
    SAA_avps.append(encodeAVP("User-Name", userName))
    # Grouped AVPs are encoded like this
    #SAA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
    #    encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
    #    encodeAVP("Auth-Application-Id",APPLICATION_ID)]))
    SAA_avps.append(encodeAVP("Auth-Session-State", 1)) # 1 - NO_STATE_MAINTAINED    
    SAA_avps.append(encodeAVP("Result-Code", 2001))   #DIAMETER_SUCCESS 2001
    #Non-3GPP-User-Data
    SAA_avps.append("000005dcc0000114000028af000001bb4000002c000001bc4000001731323131313232323230303036323300000001c24000000c00000000000005ddc0000010000028af00000000000005dec0000010000028af000000000000007c40000010000000000000000100000596c000009c000028af0000058fc0000010000028af00000001000001ed4000000a61310000000005b0c0000010000028af000000000000059bc000002c000028af00000204c0000010000028af000001f400000203c0000010000028af000001f400000597c0000038000028af00000404c0000010000028af000000010000040ac000001c000028af00000416c0000010000028af000000000000058fc0000010000028af00000000")
    # Create message header (empty)
    SAA=HDRItem()
    # Set command code
    SAA.cmd=H.cmd
    # Set Application-id
    SAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    SAA.HopByHop=H.HopByHop
    SAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(SAA,SAA_avps)
    # ret now contains SAA Response as hex string
    return ret    
    
def build_MAA(H,AppId,UserName,SIP_Auth):
    # Let's build Multimedia-Authentication Answer
    MAA_avps=[]
    MAA_avps.append(encodeAVP("Origin-Host", ORIGIN_HOST))
    MAA_avps.append(encodeAVP("Origin-Realm", ORIGIN_REALM))
    MAA_avps.append(encodeAVP("Vendor-Specific-Application-Id",[
         encodeAVP("Vendor-Id",dictVENDORid2code('TGPP')),
        encodeAVP("Auth-Application-Id",AppId)])) 
    MAA_avps.append(encodeAVP("Auth-Session-State",1)) #NO_STATE_MAINTAINED
    MAA_avps.append(encodeAVP("User-Name",UserName))
    MAA_avps.append(encodeAVP("Result-Code", 2001)) #DIAMETER_SUCCESS 2001
    MAA_avps.append(encodeAVP("SIP-Number-Auth-Items",len(SIP_Auth)))
    for s in SIP_Auth:
	MAA_avps.append(s)
    # Create message header (empty)
    MAA=HDRItem()
    # Set command code
    MAA.cmd=H.cmd
    # Set Application-id
    MAA.appId=H.appId
    # Set Hop-by-Hop and End-to-End from request
    MAA.HopByHop=H.HopByHop
    MAA.EndToEnd=H.EndToEnd
    # Add AVPs to header and calculate remaining fields
    ret=createRes(MAA,MAA_avps)
    # ret now contains MAA Response as hex string
    return ret

def create_MAA(H):
    # We need to decode SIP-Auth-Data-Item
    # If it has Authentication-Method : for radius 0=SIM, 1=AKA
    # If it has SIP-Authentication-Scheme, :for diameter value states AKA or AKA'
    MAR_avps=splitMsgAVPs(H.msg)
    UserName=findAVP("User-Name",MAR_avps)
    NumOfItems=findAVP("SIP-Number-Auth-Items",MAR_avps)
    Auth_Data=findAVP("SIP-Auth-Data-Item",MAR_avps)
    Auth_Method=findAVP("Authentication-Method",Auth_Data)
    Auth_Scheme=findAVP("SIP-Authentication-Scheme",Auth_Data)
    if Auth_Method==0:
        logging.info("Responding with Wx SIM")
        return build_MAA(H,16777219,UserName,getRadiusTriplet(UserName,NumOfItems,Auth_Method))
    if Auth_Method==1:
        logging.info("Responding with Wx AKA")
        return build_MAA(H,16777219,UserName,getRadiusQuintet(UserName,NumOfItems,Auth_Method))
    if Auth_Scheme=="EAP-AKA":
        logging.info("Responding with SWx AKA")
        return build_MAA(H,16777265,UserName,getQuintet(UserName,NumOfItems,Auth_Scheme))
    if Auth_Scheme=="EAP-AKA'":
        logging.info("Responding with SWx AKA'")
        return build_MAA(H,16777265,UserName,getQuintet(UserName,NumOfItems,Auth_Scheme))
    return ERROR

def process_request(rawdata):
    H=HDRItem()
    stripHdr(H,rawdata)
    if H.cmd==257:
        logging.info("Processing Capabilities-Exchange")
        return create_CEA(H)
    if H.cmd==303:
        logging.info("Processing Multimedia-AuthRequest")
        return create_MAA(H)
    if H.cmd==280:
        logging.info("Processing Device-WatchdogRequest")
        return create_DWA(H)
    if H.cmd==301:
        logging.info("Processing Server-AssignmentRequest")
        return create_SAA(H)        
    return create_UTC(H,"Unknown command code")

def getRadiusTriplet(UserName,NumOfItems,AuthMethod):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("SIP-Item-Number",i+1),
            encodeAVP("Authentication-Method",AuthMethod),
            encodeAVP("Authentication-Information-SIM","8b7e0f1147f9af050809bbaf50881dbb08014ca81b36d9fa".decode("hex")),
            encodeAVP("Authorization-Information-SIM","334131fc".decode("hex")) ]))
    return ret

def getRadiusQuintet(UserName,NumOfItems,AuthMethod):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("Authentication-Method",AuthMethod),
            encodeAVP("SIP-Authorization","e818fbf691ae3b97".decode("hex")),
            encodeAVP("Confidentiality-Key","f16a4bb5112dba580132e29882fec143".decode("hex")),
            encodeAVP("Integrity-Key","952a44900b7faff249763475b3aa77ee".decode("hex")),
            encodeAVP("SIP-Authenticate","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52bdc449bce0800098c737a73bc7c191".decode("hex"))
             ]))
    return ret

def getQuintet(UserName,NumOfItems,AuthScheme):
    ret=[]
    for i in range(NumOfItems):
        ret.append(encodeAVP("SIP-Auth-Data-Item",[
            encodeAVP("SIP-Authentication-Scheme",AuthScheme),
            encodeAVP("SIP-Authorization","e818fbf691ae3b97".decode("hex")),
            encodeAVP("Confidentiality-Key","f16a4bb5112dba580132e29882fec143".decode("hex")),
            encodeAVP("Integrity-Key","952a44900b7faff249763475b3aa77ee".decode("hex")),
            encodeAVP("SIP-Authenticate","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb52bdc449bce0800098c737a73bc7c191".decode("hex"))
             ]))
    return ret
    
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    logging.basicConfig(filename='/tmp/log', level=logging.INFO)
    #logging.basicConfig(level=logging.INFO)
    # Define server_host:port to use
    HOST, PORT = "10.14.5.148", 3869
    
    ORIGIN_HOST="server.test.com"
    ORIGIN_REALM="test.com"
    LoadDictionary("../dictDiameter.xml")
    # Create the server, binding to HOST:PORT
    # To allow SO_REUSEADDR, set allow_resue_address to True BEFORE bind
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

######################################################        
# History
# 0.2.7 - Sep 28, 2012 - initial version
# 0.2.8 - Oct 04, 2012 - tested radius SIM/AKA OK
# 0.2.9 - Oct 10, 2012 - added SAR/SAA

