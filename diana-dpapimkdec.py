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

""" Windows DPAPI system's MasterKeys decryption utility."""

import hashlib, optparse, os, sys, re

try: from dpapick3 import masterkey, registry
except ImportError: raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def checkParameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args: sys.exit('You must provide at least one masterkey.')

    boolEmpty = True
    for x in options.__dict__: 
        if 'export' == x: continue
        if getattr(options,x): boolEmpty = False
    
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", args[0])[0]
            print('[+] Detected SID: ' + options.sid)
        except: pass
    
    if boolEmpty:
        print('[!] No decryption details provided, just parsing the masterkey')
        return False
    
    if options.sid:
        if not options.password and not options.pwdhash and not options.pvk: sys.exit('You must provide the user password or password hash!')
        options.security = options.system = None
    else:
        for x in [options.security, options.system]: 
            if not os.path.exists(x): sys.exit('File {} not found.'.format(x))
    return True

def createHash(oMK, sSID):
    ## John & Hashcat format: $DPAPImk$<version>*<context>*<SID>*<cipheralgo>*<hashalgo>*<rounds>*<iv>*<length-ciphertext>*<ciphertext>
    ##>> context is local (1) or domain MK (2) or new-domain MK (3)
    sHash = ''
    sContext = '1'
    sCipherAlgo = oMK.masterkey.cipherAlgo.name.lower().replace('-','')
    sHashAlgo = oMK.masterkey.hashAlgo.name.lower().replace('-','')
    sRounds = str(oMK.masterkey.rounds)
    sIV = oMK.masterkey.iv.hex()
    sLengthCipher = len(oMK.masterkey.ciphertext.hex())
    sCipher = oMK.masterkey.ciphertext.hex()
    sHash = '$DPAPImk$2*{}*{}*{}*{}*{}*{}*{}*{}'.format(sContext, sSID, sCipherAlgo, sHashAlgo, sRounds, sIV, sLengthCipher, sCipher)
    ## Assuming v2, Hashcat mode 15900
    open('{}.hc15900'.format(oMK.guid.decode()),'a').write(sHash)
    print('[+] Exported hash to {}.hc15900'.format(oMK.guid.decode()))
    return sHash

def parseGUID(bData):
    def reverseByte(bByteInput):
        sReversed = ''
        sHexInput = bByteInput.hex()
        for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
        return bytes.fromhex(sReversed)
    return reverseByte(bData[:4]).hex() + '-' + reverseByte(bData[4:6]).hex() + '-' + reverseByte(bData[6:8]).hex() + '-' + bData[8:10].hex() + '-' + bData[10:].hex()

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] MKfile1 MKfile2 etc.\n\n'
        'This script tries to unlock (decrypt) MasterKey files provided.\n'
        ' Default User MK location: %appdata%\\Microsoft\\Protect\n'
        ' Default System MK locations: Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\{User}')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--system', metavar='HIVE', help=r'SYSTEM file; example: Windows\System32\config\SYSTEM')
    parser.add_option('--security', metavar='HIVE', help=r'SECURITY file; example: Windows\System32\config\SECURITY')
    parser.add_option('--sid', metavar='SID', dest='sid', help='User SID in case of user blobs, will try extract from folder')
    parser.add_option('--credhist', metavar='FILE', dest='credhist', help='User CREDHIST file')
    parser.add_option('--password', metavar='PASSWORD', dest='password', help='User password in case of user blobs')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empty SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', metavar='FILE', help='Depending on MK; domain RSA PVK keyfile')
    parser.add_option('--export', action='store_true', help='Export hashes for John/Hashcat')

    (options, args) = parser.parse_args()
    
    boolResult = checkParameters(options, args)

    oMKP = masterkey.MasterKeyPool()
    for sArg in args:
        sArg = sArg.replace('*','')
        if os.path.isfile(sArg):
            if sArg == 'Preferred': print('[+] Preferred Key is ' + parseGUID(open(sArg,'rb').read())[:36])
            else:
                if not '-' in sArg: continue
                try: oMKP.addMasterKey(open(sArg,'rb').read())
                except: continue
        else:
            for sFile in os.listdir(sArg):
                sFilepath = os.path.join(sArg, sFile)
                if not os.path.isfile(sFilepath): continue
                if sFile == 'Preferred': print('[+] Preferred Key is ' + parseGUID(open(sFilepath,'rb').read())[:36])
                else:
                    if not '-' in sFile: continue
                    try: oMKP.addMasterKey(open(sFilepath,'rb').read())
                    except: continue
    
    if not boolResult: 
        for oMKL in list(oMKP.keys.values()):
            for oMK in oMKL: 
                print(oMK)
                if options.export: createHash(oMK, options.sid)
        exit()
    
    if options.security and options.system:
        oReg = registry.Regedit()
        oSecrets = oReg.get_lsa_secrets(options.security, options.system)
        bDpapiSystem = oSecrets.get('DPAPI_SYSTEM')['CurrVal']
        oMKP.addSystemCredential(bDpapiSystem)
    
    oMKP.try_credential_hash(None, None)
    
    if options.sid:
        if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
        if options.password: oMKP.try_credential(options.sid, options.password)
        elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
        if options.pvk: oMKP.try_domain(options.pvk)

    for oMKL in list(oMKP.keys.values()):
        for oMK in oMKL:
            print('')
            print(('[!] Working on MK GUID %s\n-------------' % oMK.guid.decode()))
            if oMK.decrypted:
                print('[+] MASTER KEY UNLOCKED!')
                mkey = oMK.get_key()
                print(('[+] KEY: %s' % mkey.hex()))
                print(('[+] SHA1: %s' % hashlib.sha1(mkey).digest().hex()))
            else:
                print(('[-] MK guid: %s' % oMK.guid))
                print('[-] UNABLE to UNLOCK master key')
            print('')
