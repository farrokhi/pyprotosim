#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - November 2012
# Version 0.3.1, Last change on Nov 15, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode LDAP packet

from libLdap import *
import sys

if __name__ == "__main__":
    msg=sys.argv[1]
    print "="*30
    opt=decodeMSG(msg)
    print "Splitted",opt
    msgId,appId,code,optList=groupPairs(opt)
    print "Application",appId,dictCmd2Name(dict_APP,appId)
    print "Values",optList
    L=decodeFinal(msgId,code,optList)    
    if appId==0:
        print "messageId:",L.messageId
        print L.code
        print L.version
        print "name",L.name
        print "passwd",L.authentication
    if appId==1:
        print "messageId:",L.messageId
        print L.code
        print L.result
        print "matchedDN",L.matchedDN
        print "errorMSG",L.errorMSG
    if appId==3:
        print "messageId:",L.messageId
        print L.code    
        print "baseObject",L.baseObject
        print "scope",L.scope
        print "derefAliases", L.derefAliases
        print "sizeLimit",L.sizeLimit
        print "timeLImit",L.timeLimit
        print "typesOnly",L.typesOnly
        print "filter",L.filter
    if appId==4:
        print "messageId:",L.messageId
        print L.code    
        print "objectName",L.objectName
        print "attributes",L.attributes   
    if appId in [5,7,9,11]:
        print "messageId:",L.messageId
        print L.code
        print L.result
        print "matchedDN",L.matchedDN
        print "errorMSG",L.errorMSG       
    if appId==6:
        print "messageId:",L.messageId
        print L.code
        print "objectName",L.objectName
        print "operation",L.operation
        print "modification",L.modification 
    if appId==8:
        print "messageId:",L.messageId
        print L.code    
        print "objectName",L.objectName
        print "attributes",L.attributes     
    if appId==10:
        print "messageId:",L.messageId
        print L.code    
        print "objectName",L.objectName
    
######################################################        
# History
# 0.2.9 - Oct 11, 2012 - initial version
# 0.3.1 - Nov 15, 2012 - add/delete/modify support