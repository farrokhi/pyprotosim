#!/usr/bin/python

##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3, Last change on Oct 26, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# LDAP Simulator build upon libLdap
# interrupt the program with Ctrl-C

#Next two lines include parent directory for where libLDAP is located
import sys
sys.path.append("..")
# Remove them if everything is in the same dir

import SocketServer
from libLdap import *

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
                    break
                else:
                    dbg="Sending response",ret
                    logging.info(dbg)
                    if isinstance(ret,str):
                        self.request.send(ret.decode("hex"))
                    else:
                        for r in ret:
                            self.request.send(r.decode("hex"))

def process_request(rawdata):
    opt=decodeMSG(rawdata)
    msgId,appId,code,optList=groupPairs(opt)
    if appId==0:
        logging.info("bindRequest")
        return create_bindRes(msgId)
    if appId==2:
        logging.info("unbindRequest")
        return ERROR
    if appId==3:
        logging.info("searchRequest")
        return create_searchRes(msgId,code,optList)
    return ERROR

def create_bindRes(msgId):
    ret=create_statusRes(msgId,'61',0,'','')
    return ret
    
def create_searchEntry(msgId,list):
    # Adding attributes in order
    ret=''
    baseObject=list.pop(0)
    for l in list:
        r=l.split(':',1)
        ret=ret+encodeKeyValue(r[0],r[1])
    ret=encodeToStr('30',ret.decode('hex'))
    # skip dn: before adding
    ret=encodeToStr('04',baseObject[3:])+ret
    ret=encodeToStr('64',ret.decode('hex'))
    ret=encodeToStr('02',msgId.decode('hex'))+ret
    ret=encodeToStr('30',ret.decode("hex"))    
    return ret

def create_searchRes(msgId,code,optList):    
    L=decodeFinal(msgId,code,optList)
    ret=do_search(msgId,L.baseObject,L.scope)
    if len(ret)==0:
        # SearchResDone - No such object
        s,mDN=L.baseObject.split(',',1)
        ret.append(create_statusRes(msgId,'65',32,mDN,''))
    else:
        # SearchResDone - OK
        ret.append(create_statusRes(msgId,'65',0,'',''))
    return ret    

def do_search(msgId,baseObject,scope):
    ldif=findInLdif(baseObject,LDIF)
    ret=[]
    if len(ldif)==0:
        return ret
    else:
        # Do we search for baseObject or wholeSubTree
        res=splitOnNextObject(ldif)
        if scope==0:
            #baseObject - end on NextObject:
            return [create_searchEntry(msgId,res[0])]
        else:
            #wholeSubTree - split on each NextObject:
            for l in res:
                ret.append(create_searchEntry(msgId,l))
            return ret
    return ERROR

def splitOnNextObject(list):
    ret=[]
    tmp=[]
    start=ERROR
    for line in list:
        # Return found only between dn lines
        if line.startswith("NextObject:"):
            ret.append(tmp)
            tmp=[line[11:]]
        else:
            tmp.append(line)
    if len(tmp)>0:
        ret.append(tmp)
    return ret
        
#Version is not needed    
#line that begins with a single space is a continuation of the previous (non-empty) line.
#line that begins with a pound-sign ("#", ASCII 35) is a comment line
#zero-length attribute value is represented as AttributeDescription ":" FILL SEP.  Example: "seeAlso:" followed by a newline
#Values or distinguished names that end with SPACE SHOULD be base-64 encoded

def loadLDIF(file):
    # Load file
    f=open(file)
    list=f.readlines()
    f.close()
    # Join splitted lines
    ret=[]
    prev=''
    # Add extra line to process last line
    list.append('')
    for line in list:
        # Remove CR/LF
        ln=line.rstrip()
        if len(ln)>1:
            if ln[0]==" ":
                if ln[1].isalpha():
                    # join splitted lines (but ommit leading blank)
                    prev=prev+ln[1:]
                    ln=""
        if len(prev)!=0:
            if prev[0]!="#":
                ret.append(removeSpaces(prev))
        prev=ln
    return ret
    
def removeSpaces(line):
    for x in string.whitespace:
        line = line.replace(x,"")
    return line

def findInLdif(value,list):
    ret=[]
    start=ERROR
    # No spaces allowed in value for search
    what=removeSpaces(value)
    for line in list:
        # Return found only between dn lines
        if line.startswith("dn:"):
            start=line.find(what)
        if start!=ERROR:
            ret.append(line)
    return ret
                       
if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    # logging.basicConfig(filename='/path/to/your/log', level=logging.INFO)
    logging.basicConfig(level=logging.INFO)
    
    # Load ldif file
    LDIF=loadLDIF("ldap.ldif")
    
    # Define server host:port to use
    HOST, PORT = "10.14.5.148", 16611
    
    # Create the server, binding to HOST:PORT
    # To allow SO_REUSEADDR, set allow_resue_address to True BEFORE bind
    SocketServer.TCPServer.allow_reuse_address = True
    server = SocketServer.TCPServer((HOST, PORT), MyTCPHandler)

    # Activate the server; this will keep running until you
    # interrupt the program with Ctrl-C
    server.serve_forever()

######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.0 - Oct 26, 2012 - finally got it working
#       - Oct 29, 2012 - msgId encoding fixed, reuseaddr fixed

