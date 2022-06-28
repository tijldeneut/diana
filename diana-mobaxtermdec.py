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

# Second part if this script source: https://github.com/HyperSine/how-does-MobaXterm-encrypt-password
## The MobaXterm Master Password is SHA2 512 hashed and then DPAPI stored in registry
## This hash is then the key and IV for the AES encryption of the credentials
##  So masterpassword is not stored cleartext

""" Mobatek MobaXterm DPAPI BLOB decryption utility."""

import optparse, sys, re, base64
from Crypto.Cipher import AES

try: from dpapick3 import blob, masterkey, registry
except ImportError: raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1:
        sys.exit('[-] You must provide the ntuser.dat file (or reg save hkcu ntuser.dat).')
    if not options.masterkeydir:
        sys.exit('You must provide a masterkeys directory!')
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except:
            sys.exit('[-] You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash and not options.pvk:
        print('[!] No password provided, assuming user has no password.')
        options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'

def parseRegistry(sFile, boolVerbose = False):
    with open(sFile, 'rb') as f:
        sEntropy = lstAllCreds = sUsername = sHostname = oBlob = None
        r = registry.Registry.Registry(f)
        oBase = r.open('SOFTWARE\\Mobatek\\MobaXterm')
        sEntropy = oBase.value('SessionP').value()
        if boolVerbose: print('[+] Found DPAPI Entropy {}'.format(sEntropy))
        for oKey in oBase.subkeys():
            if oKey.name() == 'M': ## DPAPI Masterkey
                sUsername = oKey.values()[0].name().split('@')[0]
                sHostname = oKey.values()[0].name().split('@')[1]
                if boolVerbose: print('[+] Found username {} and system hostname {}'.format(sUsername, sHostname))
                sKeyPortion = oKey.values()[0].value()
                oBlob = blob.DPAPIBlob(bytes.fromhex('01000000d08c9ddf0115d1118c7a00c04fc297eb') + base64.b64decode(sKeyPortion))
            elif oKey.name() == 'P':
                lstAllCreds = []
                for oCredValue in oKey.values():
                    lstAllCreds.append((oCredValue.name(), oCredValue.value())) ## Contains Cred Details and AES Encrypted Password
                if boolVerbose: print('[+] Found {} credentials'.format(len(lstAllCreds)))
    return oBlob, sEntropy, sUsername, sHostname, lstAllCreds

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] NTUSER\n\n'
        'It decrypts MobaXterm credentials from NTUSER.dat.\n'
        '\'reg save hkcu ntuser.dat\'\n'
        'Currently tested only with Master Password protection enabled.\n'
        'Needs user MasterKey and either SID+password/hash or Domain PVK')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', '-k', help='Optional: Depending on MK; domain RSA PVK keyfile')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    oBlob, sEntropy, sUsername, sHostname, lstAllCreds = parseRegistry(args[0])
        
    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
    if options.password: oMKP.try_credential(options.sid, options.password)
    elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    if options.pvk: oMKP.try_domain(options.pvk)

    mks = oMKP.getMasterKeys(oBlob.mkguid.encode())

    bEntropy = sEntropy.encode()
    
    if len(mks) == 0:
        sys.exit('[-] Unable to find MK for blob %s' % oBlob.mkguid)

    bMobaXtermKey = None
    for mk in mks:
        if mk.decrypted:
            oBlob.decrypt(mk.get_key(), entropy = bEntropy)
            if oBlob.decrypted:
                bMobaXtermKey = base64.b64decode(oBlob.cleartext)
                print('[+] MobaXterm Master Password Hash Decrypted (to a SHA2-512 hash): ')
                print('    {}'.format(bMobaXtermKey.hex()))
            else:
                sys.exit('[-] Unable to decrypt blob')
        else:
            sys.exit('[-] Unable to decrypt master key')
        
    ## Decrypting the credentials
    bMobaXtermKey = bMobaXtermKey[0:32]
    bIV = AES.new(key = bMobaXtermKey, mode = AES.MODE_ECB).encrypt(b'\x00' * AES.block_size)
    
    print('\n[+] Decrypting {} MobaXterm credentials for user {} on machine {}'.format(len(lstAllCreds), sUsername, sHostname))
    print('-' * 79)
    lstDecryptedCreds = []
    for lstCred in lstAllCreds:
        oCipher = AES.new(key = bMobaXtermKey, iv = bIV, mode = AES.MODE_CFB, segment_size = 8)
        try: 
            sPassword = oCipher.decrypt(base64.b64decode(lstCred[1])).decode(errors='ignore')
            lstDecryptedCreds.append((lstCred[0], sPassword))
            print('  {}  :  {}'.format(lstCred[0], sPassword))
        except: pass
    print('-' * 79)
    print('\n[+] Successfully decrypted {} / {} credentials'.format(len(lstDecryptedCreds), len(lstAllCreds)))

