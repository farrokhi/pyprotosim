#!/usr/bin/env python
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - March 2012
# Version 0.2.5, Last change on Mar 16, 2012
# This software is distributed under the terms of BSD license.    
##################################################################

# Decode radius packet into individual AVPs

from radClient import *
import sys

if __name__ == "__main__":
    # level for decoding are: DEBUG, INFO, WARNING, ERROR, CRITICAL
    #logging.basicConfig(level=logging.DEBUG)
    LoadDictionary("dictRadius.xml")
    Authenticator='0x60c4b0f70deb400016813e4f8e352532'
    msg=sys.argv[1]
    print "="*30
    H=HDRItem()
    stripHdr(H,msg)
    avps=splitMsgAVPs(H.msg)
    cmd=dictCOMMANDcode2name(H.flags,H.cmd)
    if cmd==ERROR:
        print 'Unknown command',H.cmd
    else:
        print cmd
    print "Hop-by-Hop=",H.HopByHop,"End-to-End=",H.EndToEnd,"ApplicationId=",H.appId
    for avp in avps:
      print "RAW AVP",avp
      print "Decoded AVP",decodeAVP(avp)
    print "-"*30    
#! /usr/bin/perl -w

# Use this script takes the following parameters:
# 
#   --encrypt and --decrypt - mandatory and mutually exclusive.  Indicates
#                             whether you want to decrypt or encrypt the
#                             supplied password.
#   --authenticator hexstr  - mandatory, the authenticator field as a hexa-
#                             decimal string (like the one reported by
#                             tethereal -V)
#   --password (hex)str     - mandatory, the User-Password attribute.  If
#                             you're using --encrypt this should be a plain
#                             string, with --decrypt it should be a hexa-
#                             decimal string (again, like the one reported by
#                             tethereal -V)
#   --secret str            - mandatory, the shared secret as a plain string.
#   --dictionary dictfile   - optional, override the default dictionary
#                             location (/usr/share/freeradius/dictionary).
#
# Example:
#
#   $ radiuspwd --encrypt --authenticator 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
#               --password ThePassword --secret TheSharedSecret
#   outputs: ef0eefabb67b550033d70ba5caf27ded
#
#   $ radiuspwd --decrypt --authenticator 0xAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA \
#               --password ef0eefabb67b550033d70ba5caf27ded \
#               --secret TheSharedSecret
#   outputs: ThePassword
#
# Written by Tore Anderson <tore@linpro.no> 2005, public domain.
################################################################

#use strict;
#use Getopt::Long;
#use Net::Radius::Packet;
#use Net::Radius::Dictionary;

#my $encrypt = 0;
#my $decrypt = 0;
#my $dictionary = "/usr/share/freeradius/dictionary";
#my $authenticator;
#my $password;
#my $secret;

#GetOptions ("encrypt" => \$encrypt,
#	    "decrypt" => \$decrypt,
#	    "dictionary=s" => \$dictionary,
#	    "authenticator=s" => \$authenticator,
#	    "password=s" => \$password,
#	    "secret=s" => \$secret);

#die ("you must use one (and only one) of --encrypt or --decrypt\n")
#	unless($encrypt^$decrypt);

#$authenticator =~ s/(^0x|\s)//gi;
#$password =~s/(^0x|\s)//gi if($decrypt);

#my $d = new Net::Radius::Dictionary($dictionary);
#my $p = new Net::Radius::Packet($d);

#$p->set_authenticator(pack("H*", $authenticator));

#if($encrypt) {
#	$p->set_password($password, $secret);
#	print unpack("H*", $p->attr("User-Password")) . "\n";
#} elsif($decrypt) {
#	$p->set_attr("User-Password", pack("H*", $password));
#	print $p->password($secret) . "\n";
#}
