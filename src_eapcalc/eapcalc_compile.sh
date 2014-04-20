#!/bin/sh
##################################################################
# Copyright (c) 2012, Sergej Srepfler <sergej.srepfler@gmail.com>
# February 2012 - 
# Version 0.3.2 Last change at Apr 20, 2014
# This software is distributed under the terms of BSD license.    
##################################################################

# Script to compile eapcalc tool under multiple platforms

# Uncomment to enable debug display in code
#DEBUG="-DDEBUG"

#On RHEL
#yum install python-devel
# if gcc is not installed: yum install gcc

#On Ubuntu
#apt-get install python-dev
# if gcc not installed: apt-get install build-essential

# On Solaris
#ln -s /usr/local/lib/libgcc_s.so.1 /usr/lib/libgcc_s.so.1

# Delete old versions if exist
Delete_old () {
    if [ -s "eapcalc" ]
    then
        rm eapcalc &> /dev/null
    fi    
    if [ -f eapcalc.exe ]
    then
        rm eapcalc.exe
    fi 
}

# Execute test to verify compilation 
Execute_test () {
echo ""
echo "Testing standalone executable"
./eapcalc_test.sh
}

# Display compile environment
Echo_environment () {
PF="bin/platform.txt"
set |grep "^OS=" > $PF
set |grep "^PROCESSOR_AR" >> $PF
uname -a >> $PF
gcc -v 2>&1 |egrep "^Target|^gcc" >> $PF
}

# On x64 Windows enable -DMS_WIN64 for x64 compile
ARCH=`set |grep AMD64`
if [ ! -z "$ARCH" ]
then
    WINFLAG="-DMS_WIN64"
    echo "Compiling for 64-bit windows"
fi

# Detect target system 
TARGET=`set |grep "^OS="`
if [ -z "$TARGET" ]
then
    TARGET=`set |grep "^OS"`
fi
case $TARGET in
    "OS=Windows_NT")
        # Compile for Windows (tested on XP and Win7-x64)
        PLATFORM="WIN"
        ;;
    "OSTYPE=linux-gnu")
        PLATFORM="LINUX"
        if [ -f  /etc/redhat-release ]
        then
            # Compile for RHEL Linux
            P_VER="2.6"
        else
            # Compile for Ubuntu
            P_VER="2.7"
        fi
        ;;
    "OSTYPE=solaris")
        # Compile for x86 Solaris
        PLATFORM="SOLARIS"
        ;;
    *)
        PLATFORM="UNKNOWN"
        ;;
esac

EAP="eap/eap_common.c eap/mschapv2.c"
CRYP_AES="crypto/aes-ctr.c crypto/aes-cbc.c crypto/aes-internal.c crypto/aes-internal-enc.c crypto/aes-internal-dec.c crypto/aes-encblock.c"
CRYP_SHA="crypto/sha1.c crypto/sha1-internal.c crypto/sha256.c crypto/sha256-internal.c crypto/fips_prf_internal.c"
CRYP_MIL="crypto/milenage.c"
CRYP_MS="crypto/ms_funcs.c crypto/md4-internal.c crypto/des-internal.c crypto/rc4.c"

if [ $PLATFORM = "LINUX" ]
then 
    #gcc -fPIC -shared -I/usr/include/python2.7 -lpython2.7 -o myModule.so myModule.c
    # Clean-up first
    Delete_old
    UTL="utils/os_unix.c utils/wpabuf.c utils/wpa_debug.c"
    # Set all flags
    CFLAGSP="-O2 -Wall -fPIC -shared -I/usr/include/python$P_VER -lpython$P_VER"
    CFLAGS="-O2 -Wall "
    # Compile standalone tools
    gcc $CFLAGS -Iutils -Icrypto -Ieap  -I. \
        eapcalc.c $EAP $CRYP_AES $CRYP_SHA $CRYP_MIL $CRYP_MS $UTL -o eapcalc
    # Remove debug info
    strip eapcalc
    # Execute test to verify correct compilation
    Execute_test
    # Copy final result to destination directory
    cp eapcalc bin
fi

if [ $PLATFORM = "SOLARIS" ]
then 
    #gcc -fPIC -I/usr/include/python2.4 -L/usr/lib/python2.4 myModule.c -lpython2.4 -shared -o myModule.so
    # Clean-up first
    Delete_old
    UTL="utils/os_unix.c utils/wpabuf.c utils/wpa_debug.c"
    # Set all flags
    # TO DO: It seems that latest Sol10u7 has newer python 
    CPYFLAGS="-O2 -Wall -fPIC -shared -I/usr/include/python2.4 -L/usr/lib/python2.4 -lpython2.4"
    CFLAGS="-O2 -Wall"
    # Compile standalone tools
    gcc $CFLAGS -Iutils -Icrypto -Ieap  -I. \
        eapcalc.c $EAP $CRYP_AES $CRYP_SHA $CRYP_MIL $CRYP_MS $UTL -o eapcalc
    # Remove debug info
    strip eapcalc
    # Execute test to verify correct compilation
    Execute_test
    # Copy final result to destination directory
    cp eapcalc bin
fi

if [ $PLATFORM = "WIN" ]
then
    #gcc -Ic:/Python27/include -Lc:/Python27/libs myModule.c -lpython27 -shared -o myModule.pyd 
    # Clean-up first
    Delete_old
    UTL="utils/os_win32.c utils/wpabuf.c utils/wpa_debug.c"
    # Set all flags
    CFLAGS="-O2 -Wall -Ic:/Python27/include -Lc:/Python27/libs  -shared "
    # Compile standalone tools
    gcc  -Iutils -Icrypto -Ieap -I. \
        eapcalc.c $EAP $CRYP_AES $CRYP_SHA $CRYP_MIL $CRYP_MS $UTL -o eapcalc
    # Remove debug info
    strip eapcalc.exe
    # Execute test to verify correct compilation
    Execute_test    
    # Copy final result to destination directory
    cp eapcalc.exe bin
fi

if [ $PLATFORM = "UNKNOWN" ]
then
    echo "Nothing to do - FIX ME!!!"
fi

######################################################        
# History
#0.2.5 - May 25 '12 - Initial version
#0.2.8 - Aug    '12 - SIM calculations added
#0.3.0 - Oct 22 '12 - Platform automatically recognized
#      - Mar 28 '13 - separated compile on Solaris/RHEL (python version differs)
#      - May 23 '13 - Ubuntu support
#      - Sep 10 '13 - Win7 x64 support
#      - Sep 17 '13 - Redhat/Ubuntu differentiation automated
#      - Oct 11 '13 - MS-CHAPv2 functions added
#                   - fixed false error when deleting eapcalc on windows
#0.3.2 - Oct 17 '13 - added compilation platform info