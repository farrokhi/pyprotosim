#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 -
# Version 0.3.1, Last change on Oct 26, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# All functions needed to build/decode LDAP messages

import struct
import sys

ERROR = -1

# Encoding structure: CLASS(bit 7,8)+PC(bit 5)+Tag (bit 0-4)

dict_class={'UNIVERSAL':0x00,
            'APPLICATION':0x40,
            'CONTEXT_SPECIFIC':0x80,
            'PRIVATE':0xC0}

dict_pc={'PRIMITIVE':0,
         'CONSTRUCTED':0x20}

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
    def __init__(self,msgId=0,code=0,version=3,name="",authentication=""):
        self.messageId=msgId    
        self.code=code
        self.version=version
        self.name=name
        self.authentication=authentication

class LDAPResult:
    def __init__(self,msgId=0,code=0,result=0,matchedDN="",errorMSG=""):
        self.messageId=msgId
        self.code=code
        self.result=result
        self.matchedDN=matchedDN
        self.errorMSG=errorMSG
        
class searchReq:
    def __init__(self,msgId=0,code=0,baseO="",scope=3,derefA=0,filter=""):
        self.messageId=msgId     
        self.code=code
        self.baseObject=baseO
        self.scope=scope
        self.derefAliases=derefA
        self.sizeLimit=1
        self.timeLimit=0
        self.typesOnly=False
        self.filter=filter

class searchRes:        
    def __init__(self,msgId=0,code=0,objectN="",attr=[]):
        self.messageId=msgId
        self.code=code
        self.objectName=objectN
        self.attributes=attr
        
class HDRItem:
    def __init__(self,msgId=0,code=0,isApp=0,appId=0,msg=""):
        self.code=code
        self.messageID=msgId
        self.isApp=isApp
        self.appId=appId
        self.msg=msg
    
#-----------------------------------------------------------------------------
#- Only the definite form of length encoding is used.
#- OCTET STRING values are encoded in the primitive form only.
#- If the value of a BOOLEAN type is true, the encoding of the value octet is 
#  set to hex "FF".
#- If a value of a type is its default value, it is absent. Only some BOOLEAN
#  and INTEGER types have default values
#- These restrictions do not apply to ASN.1 types encapsulated inside of 
#  OCTET STRING values, such as attribute values, unless otherwise stated.


# Calculate object len (currently supports up to 64K)
def calc_len(len):
    if len<=127:
        #short form
        ret="%02X"%int(len)
    else:
        #long form limited to 2 bytes (64K)
        if len<256:
            ret="0x81"+"%02X"%int(len)
        else:
            ret="0x82"+"%04X"%int(len)
    return ret
    
# Pack according to ASN.1  (Abstract Syntax Notation One)
# Basic Encoding Rules to get identifier from Class(cls), Variable-Type(pc) and Data-Type (tag)
# see dict_class, dict_pc, dict_tag for values
def BERencode(cls,pc,tag):
    enc=cls+pc+tag
    return "%02X"%int(enc)

# Decode according to ASN.1
def BERdecode(byte):
    cls=ord(byte)>>6
    pc=(ord(byte)>>5)&1
    tag=ord(byte)&0x1F
    return cls<<6,pc<<5,tag
    
# Decode Integer value    
def decodeToInt(msg):
    while len(msg)<8:
        msg="00"+msg
    ret=struct.unpack("!I",msg.decode("hex"))[0]
    return ret

# Encode <value> as int with <op> identifier
# Reduce len if possible  
def encodeInt(op,value):
    ilen=4
    r=struct.pack("!I",int(value)).encode("hex")
    while r[:2]=='00':
        r=r[2:]
        ilen-=1
        if ilen==1:
            break
    ret=op+'%02X'%ilen+r
    return ret

# Encode <value> as string with <op> identifier    
def encodeStr(op,value):
    ret=op
    if len(value)<128:
        ret=ret+"%02X"%len(value)
    else:
        ret=ret+"82"+"%04X"%len(value)
    ret=ret+value.encode("hex")
    return ret
 
# Quit program with error
def bailOut(msg):
    print msg
    sys.exit(1)
    
# Split message into parts (remove field from remaining body)
def chop_msg(msg,size):
    return (msg[0:size],msg[size:])

# Chop len from message
def chop_len(msg):
    (mlen,msg)=chop_msg(msg,2)
    if mlen>"80":
        # Multibyte
        nlen=ord(mlen.decode("hex"))&0x7f
        (mlen,msg)=chop_msg(msg,2*nlen)
    return (decodeToInt(mlen),msg)
    
# Decode msg (hex) as LDAP message into list of decoded primitive values 
#(if it is tuple, it is decoded primitive)
# NOTE: It should be list of decoded objects, but I only needed list of all
# attributes. Parent-child relationship is not relevant here. Should be
# fixed in normal implementation
def decodeMSG(msg):
    ret=[]
    un=[]
    un.append(msg)
    while len(un)>0:
        msg=un.pop(0)
        while len(msg)>0:
            (op,msg)=chop_msg(msg,2)
            (oplen,msg)=chop_len(msg)
            cls,pc,tag=BERdecode(op.decode("hex"))
            (val,msg)=chop_msg(msg,2*oplen)
            if pc==0:   #PRIMITIVE
                ret.append((op,val))
            else:
                ret.append(op)
                un.append(msg)
                msg=val
    return ret
    
# From decodeMSG output grep tuples into list
def groupPairs(list):
    ret=[]
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

# From dict_* (dictionary) find index for value    
def dictCmd2Name(dictionary,value):
    keys=dictionary.keys()
    values=dictionary.values()
    index=[i for i,x in enumerate(values) if x == value]
    return keys[index[0]]

# For tuple (t) decode value (default decoding method is as string)    
def decodeValue(t):
    (op,value)=t
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag in [1,2,10]:
        # Decode Integer
        return decodeToInt(value)
    else:
        return value.decode("hex")
        
# Encode Value 
def encodeValue(op,value):
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag in [1,2,10]:
        # Encode integer
        return encodeInt(op,value)
    else:
        return encodeStr(op,value)

# Encode key=value pair (everything is as string from LDIF)
def encodeKeyValue(key,value):
    k=encodeStr('04',key).decode('hex')
    if isinstance(value,list):
        v=''
        for vv in value:
            v=v+encodeStr('04',vv).decode('hex')
    else:
        v=encodeStr('04',value).decode('hex')
    ret=encodeStr('30',k+encodeStr('31',v).decode('hex'))
    return ret

# Decode to proper object (match option to attribute)    
def decodeFinal(msgId,op,list):
    cls,pc,tag=BERdecode(op.decode("hex"))
    if tag==0:  # bindReq
        return decode_bindReq(msgId,op,list)
    if tag==1:  # bindRes
        return decode_bindRes(msgId,op,list)
    if tag==2:  # unbindReq
        return decode_unbindReq(msgId,op,list)
    if tag==3:  # searchReq
        return decode_searchReq(msgId,op,list)
    if tag==4:  # searchResEntry
        return decode_searchResEntry(msgId,op,list)
    if tag==5:  # searchresDone
        return decode_searchResDone(msgId,op,list)
    dbg="Don't know how to process AppId",tag
    bailOut(dbg)

def decode_bindReq(msgId,op,list):
    L=bindReq()
    L.messageId=msgId
    L.code=op
    L.version=decodeValue(list[1][0])
    L.name=decodeValue(list[1][1])
    L.authentication=decodeValue(list[1][2])
    return L
        
def decode_bindRes(msgId,op,list):    
    L=LDAPResult()
    L.messageId=msgId
    L.code=op
    L.result=decodeValue(list[1][0])
    L.matchedDN=decodeValue(list[1][1])
    L.errorMSG=decodeValue(list[1][2])    
    return L
        
def decode_unbindReq(msgId,op,list):
    L=LDAPResult()
    L.messageId=msgId
    L.code=op
    return L  
        
def decode_searchReq(msgId,op,list):
    L=searchReq()
    L.messageId=msgId
    L.code=op
    L.baseObject=decodeValue(list[1][0])
    L.scope=decodeValue(list[1][1])
    L.derefAliases=decodeValue(list[1][2])
    L.sizeLimit=decodeValue(list[1][3])           
    L.timeLimit=decodeValue(list[1][4])
    L.typesOnly=decodeValue(list[1][5])
    if len(list[1])>6:
        L.filter=decodeValue(list[1][6])
    else:
        if list[2]=='a4':
            (c,v)=list[5][0]
            L.filter=decodeValue(list[3][0])+"="+v.decode("hex")
    return L
    
def decode_searchResEntry(msgId,op,list):
    L=searchRes()
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
        
def decode_searchResDone(msgId,op,list):
    L=LDAPResult()
    L.code=op
    L.messageId=msgId
    L.result=decodeValue(list[1][0])
    L.matchedDN=decodeValue(list[1][1])
    L.errorMSG=decodeValue(list[1][2])  
    return L
    
# Create generic Response message    
def create_LDAPResult(msgId,code,result,matchedDN,errorMSG):
    # Adding from end to the beginning
    #    LDAPResult ::= SEQUENCE {
    #         resultCode         ENUMERATED,
    #         matchedDN          LDAPDN,
    #         diagnosticMessage  LDAPString,
    #         referral           [3] Referral OPTIONAL }             
    # 04="%02X"%dict_tag['OCTET_STRING']    
    # 0A="%02X"%dict_tag['ENUMERATED']
    ret=''
    ret=encodeValue('04',errorMSG)+ret
    ret=encodeValue('04',matchedDN)+ret
    ret=encodeValue('0A',result)+ret
    ret=encodeStr(code,ret.decode("hex"))
    ret=encodeStr('02',msgId.decode("hex"))+ret
    ret=encodeStr('30',ret.decode("hex"))
    return ret

######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.0 - Oct 26, 2012 - finally got it working
#       - Oct 29, 2012 - msgId encoding fixed, reuseaddr fixed
#                      - encodeTo<Type> renamed to encode<Type> (more logical)
#                      - multiple values for key now supported
#                      - int len now not fixed
# 0.3.1 - Nov 05, 2012 - comments added, code cleanup
#                      - logging removed because it conflicts with threaded
#                        LDAP simulator
