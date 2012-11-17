#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - Nov 2012
# Version 0.3.1, Last change on Nov 14, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode SMPP (Short Message Peer to Peer) messages

import xml.dom.minidom as minidom
import struct
import codecs
import socket
import sys
import logging
import time
import string

# Header fields

SMPP_HDR_REQUEST    = 0x80

# Include common routines for all modules
ERROR = -1
 
# Hopefully let's keep dictionary definition compatibile
class AVPItem:
    def __init__(self):
        self.code=0
        self.name=""
        self.type=""
        self.mandatory=""
        
class HDRItem:
    def __init__(self):
        self.len=0
        self.id=0
        self.status=0
        self.number=0
        self.msg=""
        self.mandatory=""
        self.optional=""
        
# Load simplified dictionary from <file>
def LoadDictionary(file):
    global dict_commands
    global dict_optional
    doc = minidom.parse(file)
    node = doc.documentElement
    dict_msg = doc.getElementsByTagName("msg")
    dict_optional = doc.getElementsByTagName("optional")

# Find Command definition in dictionary: 257->Capabilities-Exchange
def dictMSGcode2name(code):
    cmd=ERROR
    for cmd in dict_msg:
         cName=cmd.getAttribute("name")
         cCode=cmd.getAttribute("code")
         if code==cCode:
            return cName
    dbg="Unknown command",code
    bailOut(dbg)
    
def dictFindMandatoryAVP(code):
    ret=[]
    for command in dict_msg:
         cCode=command.getAttribute("code")
         if code==cCode:
            for cMandatory in command.getElementsByTagName("mandatory"):
                cName=cMandatory.getAttribute("name")
                ret.append(cName)
            return ret
    return ERROR

def dictFindOptionalAVP(code):
    ret=[]
    for command in dict_optional:
         cCode=command.getAttribute("code")
         cName=command.getAttribute("name")
         if code==cCode:
            for cMandatory in command.getElementsByTagName("mandatory"):
                cName=cMandatory.getAttribute("name")
                ret.append(cName)
            return ret
    return ERROR
    
def dictFindDetails(code,mName):
    for command in dict_commands:
         cCode=command.getAttribute("code")
         if code==cCode:
            for cMandatory in command.getElementsByTagName("mandatory"):
                cName=cMandatory.getAttribute("name")
                cType=cMandatory.getAttribute("type")
                cMax=cMandatory.getAttribute("max")
                if cName==mName:
                    return cName,cType,cMax
    dbg="Unknown",mName,"for code",code
    bailOut(dbg) 
    
#----------------------------------------------------------------------
#
# Decoding section
#

def decode_Integer32(data):
    ret=struct.unpack("!I",data.decode("hex"))[0]
    return int(ret)
    
def decode_Int(data):
    return ord(data.decode("hex"))
    
def decode_Integer16(data):
    ret=struct.unpack("!H",data.decode("hex"))[0]
    return int(ret)    
 

#----------------------------------------------------------------------
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
def smart_chop(msg,cMax):
    ret=''
    count=0
    while msg[:2]!='00':
        (cc,msg)=chop_msg(msg,2)
        ret=ret+cc
        count+=1
        if count==cMax:
            break
        if len(msg)==0:
            return (ret,msg)
    if count!=cMax:
        (cc,msg)=chop_msg(msg,2)
    return (ret,msg)
    
#---------------------------------------------------------------------- 
#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command length                           | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command id                               | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Command status                           | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |                      Sequence number                          | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |  Message=first Mandatory, then Optional parameters.....

# Main message decoding routine
# Input: diameter message as HEX string    
# Result: class H with splitted message (header+message)
# AVPs in message are NOT splitted
def stripHdr(H,msg):
    dbg="Incoming Diameter msg",msg
    logging.info(dbg)
    if len(msg)==0:
        return ERROR
    (slen,msg)=chop_msg(msg,8)
    (sid,msg)=chop_msg(msg,8)
    (sstatus,msg)=chop_msg(msg,8)
    (snumber,msg)=chop_msg(msg,8)
    dbg="Split hdr","L",slen,"I",sid,"S",sstatus,"N",snumber,"D",msg
    logging.debug(dbg)
    H.len=decode_Integer32(slen)
    H.id=sid
    H.status=decode_Integer32(sstatus)
    H.number=decode_Integer32(snumber)
    dbg=dictCOMMANDcode2name(sid)
    logging.info(dbg)
    H.msg=msg
    return 

# Split AVPs from message
# Input: H.msg as hex string
# Result: list of undecoded AVPs
def splitMsgAVPs(H):
    ret=[]
    dbg="Incoming avps",H.msg
    opt=decodeMandatory(H)
    decodeOptional(H,opt)
    return

def decodeMandatory(H):
    msg=H.msg
    for mandatory in dictFindMandatoryAVP(H.id):
        cName,cType,cMax=dictFindDetails(H.id,mandatory)
        print cName,cType,cMax
        if cType=="Int":
            (sInt,msg)=chop_msg(msg,2)
            print sInt
            ret.append(cName+'='+str(decode_Int(sInt)))
        else:
            (sValue,msg)=smart_chop(msg,cMax)
            print sValue
            ret.append(cName+'='+sValue.decode("hex"))    
    H.mandatory=ret
    return msg

#    0                   1                   2                   3
#    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |              Tag              |             Length            | 
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
#   |             Value             |
#   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+  
    
def decodeOptional(H,msg):
    ret=[]
    while msg!='':
        (sTag,msg)=chop_msg(msg,4)
        (sLen,msg)=chop_msg(msg,4)
        vLen=decode_Integer16(sLen)
        (sValue,msg)=chop_msg(msg,2*vLen)
        cName=dictFindOptionalAVP(sTag)
#---------------------------------------------------------------------- 
######################################################        
# History
# Ver 0.3.1 - Nov 16, 2012 - initial version
