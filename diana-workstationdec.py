#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2015, Francesco "dfirfpi" Picasso <francesco.picasso@gmail.com>
# Copyright 2022, Tijl "Photubias" Deneut <@tijldeneut>
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
"""VMware Workstation password (offline) decryptor"""

import optparse, os, re
import base64, urllib.parse, hashlib, hmac
from Crypto.Cipher import AES

bStaticKey = bytes.fromhex('a0142a55c74d1f63715f13f53b69d3ac')
sStaticPassword = '{23F781A1-4126-4bba-BC8A-9DD33D0E2362}'

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        exit('[-] You must provide the VMware folder containing at least 2 files:\npreferences-private.ini and ace.dat.')
    if not options.masterkeydir:
        exit('[-] You must provide the user DPAPI folder, see <usage>.')
    if not options.sid:
        try: options.sid = re.findall(r"S-1-[0-5]-\d{2}-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
        except: exit('[-] You must provide the user SID to decrypt password.')
    if options.sid and not options.password and not options.pwdhash: 
        options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: options.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
    if not os.path.isfile(os.path.join(args[0],'preferences-private.ini')):
        exit('[-] Fatal error: file \'preferences-private.ini\' not found in folder {}'.format(args[0]))

def parseHosts(bData):
    lstCreds = []
    sHost = sUser = sPass = ''
    for bLine in bData.split(b'\n'):
        if '.hostID' in bLine.decode(): sHost = bLine.split(b' = ')[1].decode().replace('"','')
        elif '.username' in bLine.decode(): sUser = bLine.split(b' = ')[1].decode().replace('"','')
        elif '.password' in bLine.decode(): sPass = bLine.split(b' = ')[1].decode().replace('"','')
        if sHost and sUser and sPass:
            lstCreds.append((sHost,sUser,sPass))
            sHost = sUser = sPass = ''
    return lstCreds

def parseAce(sFilepath):
    sData = ''
    try: 
        with open(sFilepath,'r') as file:
            sLine = file.readline()
            while sLine:
                if sLine.startswith('data'): 
                    sData = sLine.split(' = ')[1].strip().replace('"','')
                    break
                sLine = file.readline()
    except: exit('[-] Error: file ' + sFilepath + ' not found or corrupt.')
    finally: file.close()
    bData = base64.b64decode(sData)
    return bData

def parsePreferences(sFilepath, mkp, boolVerbose):
    # userKey (DPAPI blob with AES key, 32 bytes), keySafe (x bytes), data (x bytes)
    sUserKey = sKeySafe = sData = ''
    try: 
        with open(sFilepath,'r') as file:
            sLine = file.readline()
            while sLine:
                if sLine.startswith('encryption.userKey'): sUserKey = sLine.split(' = ')[1].strip().replace('"','')
                elif sLine.startswith('encryption.keySafe'): sKeySafe = sLine.split(' = ')[1].strip().replace('"','')
                elif sLine.startswith('encryption.data'): sData = sLine.split(' = ')[1].strip().replace('"','')
                sLine = file.readline()
    except: exit('[-] Error: file ' + sFilepath + ' not found or corrupt.')
    finally: file.close()
    # userKey
    oBlob = blob.DPAPIBlob(base64.b64decode(sUserKey))
    mks = mkp.getMasterKeys(oBlob.mkguid.encode())
    for mk in mks:
        if mk.decrypted:
            oBlob.decrypt(mk.get_key())
            if oBlob.decrypted: 
                bUserKey = base64.b64decode(urllib.parse.unquote(oBlob.cleartext.decode()).split(':key=')[1])
    # keySafe
    bKeySafe = base64.b64decode(urllib.parse.unquote(sKeySafe.split('/')[len(sKeySafe.split('/'))-1].split(',')[2].replace(')','')))
    # data
    bData = base64.b64decode(sData)
    if boolVerbose:
        print('[+] Decrypted User Key:       {}'.format(bUserKey.hex()))
        print('[+] Parsed Key Safe:          {}'.format(bKeySafe.hex()))
        print('[+] Extracted encrypted data: {}'.format(bData.hex()))
    return (bUserKey, bKeySafe, bData)

def stripLastChars(bData): ## Remove trailing characters
    if bData[-1:] == b'\n': 
        bData = bData.rstrip(bData[-1:])
        return bData + b'\n'
    else: return bData.rstrip(bData[-1:])

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] VMware-folder\n\n'
        'It decrypts VMware Workstation credentials stored in\n'
        '\\<User>\\AppData\\Roaming\\VMware; files ace.dat and preferences-private.ini\n'
        'You must provide the folder with these 2 files, the corresponding user SID, password or hash,\n'
        'and the user DPAPI MasterKeys, stored in\n'
        '\\<User>\\AppData\\Roaming\\Microsoft\\Protect\\<SID>'
        )

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empty hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--verbose', '-v', metavar='BOOL', action='store_true', default=False, help='Be more verbose (optional)')

    (options, args) = parser.parse_args()

    check_parameters(options, args)
    boolVerbose = True if options.verbose else False
    
    mkp = masterkey.MasterKeyPool()
    mkp.loadDirectory(options.masterkeydir)
    if options.credhist:
        mkp.addCredhistFile(options.sid, options.credhist)
    if options.password:
        mkp.try_credential(options.sid, options.password)
    if options.pwdhash:
        mkp.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    
    (bUserKey, bKeySafe, bEncPrefData) = parsePreferences(os.path.join(args[0],'preferences-private.ini'), mkp, boolVerbose)

    # Step 1: decrypt keySafe with userKey (first 16 bytes are the IV, last 20 bytes are verification)
    bDataStep1 = stripLastChars(AES.new(bUserKey, AES.MODE_CBC, bKeySafe[:16]).decrypt(bKeySafe[16:-20]))
    if boolVerbose: print('[+] Step 1 decrypted data:    {}'.format(bDataStep1.decode()))
    ## Optional verification: 
    bVerification1 = hmac.new(bUserKey, bDataStep1, hashlib.sha1).digest()
    if not bVerification1 == bKeySafe[-20:]: exit('[-] Error during decryption of step 1; current result:\n    ' + bDataStep1.decode(errors='ignore'))
    bKeyStep2 = base64.b64decode(urllib.parse.unquote(bDataStep1.decode().split(':key=')[1]))
    
    # Step 2: decrypt "encryption.data" (bEncPrefData) from preferences-private.ini with decrypted key from keySafe
    bDataStep2 = stripLastChars(AES.new(bKeyStep2, AES.MODE_CBC, bEncPrefData[:16]).decrypt(bEncPrefData[16:-20]))
    bVerification2 = hmac.new(bKeyStep2, bDataStep2, hashlib.sha1).digest()
    if not bVerification2 == bEncPrefData[-20:]: exit('[-] Error during decryption of step 2; current result:\n    ' + bDataStep2.decode(errors='ignore'))
    print('[+] Host decryption successful:')
    print(urllib.parse.unquote(bDataStep2.strip(b'\n').decode()))
    print('-'*25)
    lstCreds = parseHosts(bDataStep2)
    
    # Step 3: decrypt ace.dat with a static AES 256 key
    if not os.path.isfile(os.path.join(args[0],'ace.dat')): exit('[-] Error: No credentials found or VMware is using the Credential Manager. Try \'diana-creddec.py\'')
    bData3 = parseAce(os.path.join(args[0],'ace.dat'))
    bDataStep3 = stripLastChars(AES.new(bStaticKey, AES.MODE_CBC, bData3[:16]).decrypt(bData3[16:-20]))
    bVerification3 = hmac.new(bStaticKey, bDataStep3, hashlib.sha1).digest()
    if not bVerification3 == bData3[-20:]: exit('[-] Error during decryption of step 3; current result:\n    ' + bDataStep3.decode(errors='ignore'))
    iRounds = int(bDataStep3.split(b':rounds=')[1].split(b':')[0])
    bSalt = base64.b64decode(urllib.parse.unquote(bDataStep3.split(b':salt=')[1].split(b':')[0].decode()))
    bData4 = base64.b64decode(urllib.parse.unquote(bDataStep3.split(b':data=')[1].split(b':')[0].decode()))

    # Step 4: decrypt the decrypted data from ace.dat using a derived key
    bDerivedKey = hashlib.pbkdf2_hmac('sha1', sStaticPassword.encode(), bSalt, iRounds)[:16]
    bDataStep4 = stripLastChars(AES.new(bDerivedKey, AES.MODE_CBC, bData4[:16]).decrypt(bData4[16:-20]))
    bVerification4 = hmac.new(bDerivedKey, bDataStep4, hashlib.sha1).digest()
    if not bVerification4 == bData4[-20:]: exit('[-] Error during decryption of step 4; current result:\n    ' + bDataStep4.decode(errors='ignore'))
    bPassKey = base64.b64decode(urllib.parse.unquote(bDataStep4.split(b':key=')[1].decode()))
    
    # Step 5: final decryption of the credential(s)
    for lstCred in lstCreds:
        bPassData = base64.b64decode(lstCred[2])
        bPassword = stripLastChars(AES.new(bPassKey, AES.MODE_CBC, bPassData[:16]).decrypt(bPassData[16:-20]))
        bVerification5 = hmac.new(bPassKey, bPassword, hashlib.sha1).digest()
        if not bVerification5 == bPassData[-20:]: exit('[-] Error during decryption of step 5; current result:\n    ' + bPassword.decode(errors='ignore'))
        iPasslength = int(bPassword[16:][:4].hex(),16)
        sPassword = bPassword[20:20+iPasslength].decode()
        print('[+] Host:     {}\n    Username: {}\n    Password: {}'.format(lstCred[0], lstCred[1], sPassword))