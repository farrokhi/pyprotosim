#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.2.3 Last change at Feb 25, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# levels for logging are: DEBUG, INFO, WARNING, ERROR, CRITICAL

import xml.dom.minidom as minidom
import sys
import os

def Q(val):
    return chr(34)+val+chr(34)

def M(mandatory):
    if mandatory=='must':
       return ' mandatory='+Q(mandatory)
    else:
       return ''

def V(vendor):
   if vendor=='':
      return ''
   else:
      return ' vendor-id='+Q(vendor)
    
# Load diameter dictionary
def LoadDictionary(file,tag,vtag):
    doc = minidom.parse(file)
    node = doc.documentElement
    avps = doc.getElementsByTagName(tag)
    for avp in avps:
        Name=avp.getAttribute('name')
        Code=avp.getAttribute('code')
        vId=avp.getAttribute('vendor-id')
        Mand=avp.getAttribute('mandatory')
        typeObj = avp.getElementsByTagName('type')
        if typeObj.length==0:
            Type=''
        else:
            Type = typeObj[0].getAttribute('type-name')
        processed=False
        vtag=vId
        if vtag==vId:
            processed=False
            #if Type=='Enumerated':
               # Find all enumerated parts
               # print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'>'
               # enumObj=avp.getElementsByTagName('enum')
               # if enumObj.length!=0:
               #     for enum in enumObj:
               #         eName=enum.getAttribute('name')
               #         eCode=enum.getAttribute('code')
               #         print '    <enum code='+Q(eCode)+' name='+Q(eName)+'/>'
               # print '</avp>'
               # processed=True
            #if Type=='':
               # Find all grouped parts
               # print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q('Grouped')+M(Mand)+'>'
               # groupObj=avp.getElementsByTagName('gavp')
               # if groupObj.length!=0:
               #     for gavp in groupObj:
               #         eName=gavp.getAttribute('name')
               #         print '    <gavp name='+Q(eName)+'/>'
               # print '</avp>'
               # processed=True
            if not processed:
               print '<avp code='+Q(Code)+V(vId)+' name='+Q(Name)+' type='+Q(Type)+M(Mand)+'/>'

if __name__ == "__main__":
    DIR="./diameter"
    # Dont ask me why, but parser broke on this file
    skip=["mobileipv6.xml"]
    # And I prefer to have main dictionary first, and other in alphabetical order
    skip.append("dictionary.xml")
    LoadDictionary(DIR+"/dictionary.xml","avp","")
    #Now we can process dictionaries
    dirList=os.listdir("./diameter")
    for fname in dirList:
        print fname
        if fname.endswith(".xml"):
            if fname in skip:
                print "SKIPPING"
            #else:
            #    LoadDictionary(DIR+"/"+fname,"avp","")



