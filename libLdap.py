#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - May 2012
# Version 0.2.9, Last change on Oct 11, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode LDAP messages

import struct
import codecs
import socket
import sys
import logging
import time
import string

ERROR = -1

# Encoding structure: CLASS(bit 7,8)+PC(bit 5)+Tag (bit 0-4)

dict_class={'UNIVERSAL':0x00,
            'APPLICATION':0x40,
            'CONTEXT_SPECIFIC':0x80,
            'PRIVATE':0xC0}
dict_pc={'PRIMITIVE':0,'CONSTRUCTED':0x20}

dict_tag={'EOC':0,
            'BOOLEAN':1,
            'INTEGER':2,
            'BIT_STRING':3,
            'OCTET_STRING':4,
            'NULL':5,
            'OBJECT_IDENTIFIER':6,
            'OBJECT_DESCRIPTOR':7,
            'EXTERNAL':8,
            'FLOAT':9,
            'ENUMERATED':10,
            'EMBEDDED':11,
            'UTF8':12,
            'RELATIVE_OID':13,
            'SEQUENCE':16,
            'SET':17,
            'NUMERIC_STRING':18,
            'PRINTABLE_STRING':19,
            'T61STRING':20,
            'VIDEOTEXT_STRING':21,
            'IA5STRING':22,
            'UTC_TIME':23,
            'GENERALIZED_TIME':24,
            'GRAPHIC_STRING':25,
            'VISIBLE_STRING':26,
            'GENERAL_STRING':27,
            'UNIVERSAL_STRING':28,
            'CHARACTER_STRING':29,
            'BMP_STRING':30,
            'LONG_FORM':31}


dict_RES={'success':0,
        'operationsError':1,
        'protocolError':2,
        'timeLimitExceeded':3,
        'sizeLimitExceeded':4,
        'compareFalse':5,
        'compareTrue':6,
        'authMethodNotSupported':7,
        'strongerAuthRequired':8,
        'referral':10,
        'adminLimitExceeded':11,
        'unavailableCriticalExtension':12,
        'confidentialityRequired':13,
        'saslBindInProgress':14,
        'noSuchAttribute':16,
        'undefinedAttributeType':17,
        'inappropriateMatching':18,
        'constraintViolation':19,
        'attributeOrValueExists':20,
        'invalidAttributeSyntax':21,
        'noSuchObject':32,
        'aliasProblem':33,
        'invalidDNSyntax':34,
        'aliasDereferencingProblem':36,
        'inappropriateAuthentication':48,
        'invalidCredentials':49,
        'insufficientAccessRights':50,
        'busy':51,
        'unavailable':52,
        'unwillingToPerform':53,
        'loopDetect':54,
        'namingViolation':64,
        'objectClassViolation':65,
        'notAllowedOnNonLeaf':66,
        'notAllowedOnRDN':67,
        'entryAlreadyExists':68,
        'objectClassModsProhibited':69,
        'affectsMultipleDSAs':71,
        'other':80 }


dict_APP= {'bindRequest': 0,
            'bindResponse':1,
            'unbindRequest':2,
            'searchRequest':3,
            'searchResultEntry':4,
            'searchResultDone':5,
            'searchResultReference':6,
            'modifyRequest':7,
            'modifyResponse':8,
            'addRequest':9,
            'addResponse':10,
            'delRequest':11,
            'delResponse':12,
            'modifyDNRequest':13,
            'modifyDNResponse':14,
            'compareRequest':15,
            'compareResponse':16,
            'abandonRequest':17,
            'extendedRequest':18,
            'extendedResponse':19,
            'intermediateResponse':20 }        

class bindReq:
    def __init__(self):
        self.messageId=0    
        self.code=0
        self.version=3
        self.name=""
        self.authentication=""

class bindRes:
    def __init__(self):
        self.messageId=0     
        self.code=0
        self.result=0
        self.matchedDN=""
        self.errorMSG=""
        
class searchReq:
    def __init__(self):
        self.messageId=0     
        self.code=0
        self.baseObject=3
        self.scope=""
        self.derefAliases=""        
        self.sizeLimit=1
        self.timeLimit=0
        self.typesOnly=False
        self.filter=""

class searchRes:        
    def __init__(self):
        self.messageId=0      
        self.code=0
        self.objectName=""
        self.attributes=[]
        
class HDRItem:
    def __init__(self):
        self.code=0
        self.messageID=0
        self.isApp=0
        self.appId=0
        self.msg=""
    
#long-form identifier shall be encoded as follows:
#Tag field encoded as 11111
#The subsequent octets shall encode the number of the tag as follow
#bit 8 of each octet shall be set to one unless it is the last octet of the identifier octets
#bits 7 to 1 of the first subsequent octet, followed by bits 7 to 1 of each subsequent octets 
#including the last subsequent octet shall be the encoding of an unsigned binary integer of tag number

def calc_len(len):
    #for indefinite form, len starts with 0x80 and MUST be closed with END_OF_OCTETS
    if len<=127:
        #short form
        ret="%02X"%int(len)
    else:
        #long form limited to 2 bytes (65535 bytes) for my usage
        if len<256:
            ret="0x81"+"%02X"%int(len)
        else:
            ret="0x82"+"%04X"%int(len)
    return ret
    
def BERencode(cls,pc,tag):
        if tag<32:
            enc=cls+pc+tag
            return "%02X"%int(enc)
        else:
            #limited to 2 bytes for my usage
            enc=cls+0x3F
            if tag<127:
                return "%02X"%int(enc)+"%02X"%int(tag)
            else:
                tag1=int(tag/128)
                tag2=tag%128
                return "%02X"%int(enc)+"%02X"%int(0x80+tag1)+"%02X"%int(tag2)

def BERdecode(byte):
    cls=ord(byte)>>6
    pc=(ord(byte)>>5)&1
    tag=ord(byte)&0x1F
    return cls,pc,tag
    
def dec_len(msg):
    (mlen,msg)=chop_msg(msg,2)
    if mlen>"80":
        # Multibyte
        nlen=ord(mlen.decode("hex"))&0x7f
        (mlen,msg)=chop_msg(msg,2*nlen)
    return (decodeToInt(mlen),msg)
    
def decodeToInt(msg):
    while len(msg)<8:
        msg="00"+msg
    ret=struct.unpack("!I",msg.decode("hex"))[0]
    return ret

def encodeToInt(op,value):
    ret=op
    ret=ret+'04' # len
    r=struct.pack("!I",int(value))
    ret=ret+r.encode("hex")
    return ret
    
def encodeToStr(op,value):
    ret=op
    if len(value)<128:
        ret=ret+"%02X"%len(value)
    else:
        ret=ret+"82"+"%04X"%len(value)
    ret=ret+value.encode("hex")
    return ret
 
def encodeTo(op,value):
    ret=op
    mlen=len(value)/2
    if len(value)<128:
        ret=ret+"%02X"%mlen
    else:
        ret=ret+"82"+"%04X"%mlen
    ret=ret+value
    return ret
    
# Quit program with error
def bailOut(msg):
    logging.error(msg)
    sys.exit(1)
    
#Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])
    
def decodeMSG(msg):
    ret=[]
    un=[]
    un.append(msg)
    while len(un)>0:
        msg=un.pop(0)
        while len(msg)>0:
            dbg="Decoding :",msg
            logging.debug(dbg)
            (op,msg)=chop_msg(msg,2)
            (oplen,msg)=dec_len(msg)
            cls,pc,tag=BERdecode(op.decode("hex"))
            (val,msg)=chop_msg(msg,2*oplen)
            dbg="Decoded cls:",cls,"pc",pc,"tag",tag,"op",op,"oplen",oplen,val
            logging.debug(dbg)
            if pc==0:   #PRIMITIVE
                ret.append((op,val))
            else:
                logging.debug("Recursive")
                ret.append(op)
                un.append(msg)
                msg=val
    return ret
    
def groupPairs(list):
    ret=[]
    last="T"
    list.pop(0)
    (op,msgID)=list.pop(0)
    if isinstance(list[0],tuple):
        (appId,x)=list.pop(0)
    else:
        appId=list[0]
    cls,pc,tag=BERdecode(appId.decode("hex"))
    # Let's pack attributes
    i=0
    tmp=[]
    for i in range(len(list)):
        if isinstance(list[i],tuple):
            tmp.append(list[i])
        else:
            if len(tmp)>0:
                ret.append(tmp)
            tmp=[]
            ret.append(list[i])
    if len(tmp)>0:
        ret.append(tmp)
    return msgID,tag,appId,ret

def dictCmd2Name(dictionary,value):
    keys=dictionary.keys()
    values=dictionary.values()
    index=[i for i,x in enumerate(values) if x == value]
    return keys[index[0]]

def decodeValue(t):
    (op,value)=t
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag in [1,2,10]:
        # Decode Integer
        return decodeToInt(value)
    if tag in [7,4,0]:
        return value.decode("hex")
    return "Dec Unknown type "+str(tag)

def encodeValue(op,value):
    cls,pc,tag=BERdecode(op.decode("hex"))
    dbg="Encoding with CLS",cls,"PC",pc,"TAG",tag,"V",value
    logging.info(dbg)
    if tag in [1,2,10]:
        # Encode integer
        return encodeToInt(op,value)
    if tag in [7,4,0]:
        return encodeToStr(op,value)
    return "Enc Unknown type "+str(tag)
    
def encodeKeyValue(key,value):
    k=encodeToStr('04',key).decode('hex')
    v=encodeToStr('04',value).decode('hex')
    ret=encodeToStr('30',k+encodeToStr('31',v).decode('hex'))
    return ret

def decodeFinal(msgId,op,list):
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag==0:
        L=bindReq
        L.messageId=msgId
        L.code=op
        L.version=decodeValue(list[1][0])
        L.name=decodeValue(list[1][1])
        L.authentication=decodeValue(list[1][2])
        return L
    if tag==1:
        L=bindRes
        L.messageId=msgId
        L.code=op
        L.result=decodeValue(list[1][0])
        L.matchedDN=decodeValue(list[1][1])
        L.errorMSG=decodeValue(list[1][2])    
        return L
    if tag==2:
        L=bindRes
        L.messageId=msgId
        L.code=op
        return L        
    if tag==3:
        L=searchReq
        L.messageId=msgId
        L.code=op
        L.baseObject=decodeValue(list[1][0])
        L.scope=decodeValue(list[1][1])
        L.derefAliases=decodeValue(list[1][2])
        L.sizeLimit=decodeValue(list[1][3])           
        L.timeLimit=decodeValue(list[1][4])
        L.typesOnly=decodeValue(list[1][5])
        L.filter=decodeValue(list[1][6])
        return L
    if tag==4:
        L=searchRes
        L.messageId=msgId
        L.code=op
        L.objectName=decodeValue(list[1][0])
        att=[]
        key=""
        val=""
        last=0
        for a in list[2:]:
            if isinstance(a,str):
                last=a
            else:
                if last=='30':
                    key=decodeValue(a[0])
                else:
                    for b in a:
                        value=decodeValue(b)
                        att.append(key+'='+value)
        L.attributes=att
        return L   
    if tag==5:
        L=bindRes
        L.code=op
        L.messageId=msgId
        L.result=decodeValue(list[1][0])
        L.matchedDN=decodeValue(list[1][1])
        L.errorMSG=decodeValue(list[1][2])  
        return L
    dbg="Don't know how to process AppId",tag
    bailOut(dbg)
    
def create_statusRes(msgId,code,result,matchedDN,errorMSG):
    # Adding from end to the beginning in Tree-like structure
    # 04="%02X"%dict_tag['OCTET_STRING']    
    ret=''
    ret=encodeValue('04',errorMSG)+ret
    ret=encodeValue('04',matchedDN)+ret
    ret=encodeValue('0A',result)+ret
    ret=encodeToStr(code,ret.decode("hex"))
    ret=encodeValue('02',msgId)+ret
    ret=encodeToStr('30',ret.decode("hex"))
    return ret
