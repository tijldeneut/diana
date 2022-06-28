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

""" Windows DPAPI BLOB decryption utility."""

import optparse, os, sys, re

try: from dpapick3 import blob, masterkey, registry
except ImportError: raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def checkParameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1: sys.exit('You must provide an argument.')
    if not options.masterkeydir and not options.mkclearhex: 
        print('[!] No decryption details provided, parsing the blob')
        return False
    if options.mkclearhex: return True
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except: pass
    if options.sid:
        if not options.password and not options.pwdhash and not options.pvk: sys.exit('You must provide the user password or password hash!')
    else:
        for x in [options.security, options.system]: 
            if not os.path.exists(x): sys.exit('You must provide SYSTEM and SECURITY hives.')
    return True

def showResult(oBlob):
    print('Blob Decrypted, HEX and TEXT following...')
    print(('-' * 79))
    print((oBlob.cleartext.hex()))
    print(('-' * 79))
    print((oBlob.cleartext))
    print(('-' * 79))
    print((oBlob.cleartext.decode('UTF-16LE',errors='ignore')))
    print(('-' * 79))
    return

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] BLOB\n\n'
        'This script tries to decrypt a user|system DPAPI encrypted BLOB.\n'
        'User blob masterkeydir: %APPDATA%\\Microsoft\\Protect\\<SID>\n'
        'User blob needs sid and password (hash).\n'
        'System blob masterkeydir: Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\{User}\n'
        'System blob needs system and security at least.\n'
        '==> Alternative: just blob + decrypted masterkey')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir', help='')
    parser.add_option('--system', metavar='HIVE', dest='system', default=os.path.join('Windows','System32','config','SYSTEM'))
    parser.add_option('--security', metavar='HIVE', dest='security', default=os.path.join('Windows','System32','config','SECURITY'))
    parser.add_option('--sid', metavar='SID', dest='sid', help='User SID in case of user blobs, will try extract from folder')
    parser.add_option('--credhist', metavar='FILE', dest='credhist', help='User CREDHIST file')
    parser.add_option('--password', metavar='PASSWORD', dest='password', help='User password in case of user blobs')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empty SHA1 hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--entropy_hex', metavar='HEX', dest='entropy_hex',help='Some blobs required extra entropy bytes')
    parser.add_option('--pvk', help='Depending on MK; domain RSA PVK keyfile')
    parser.add_option('--clearmasterkey', metavar='HEX', dest='mkclearhex', help='Provide manually decrypted DPAPI key here')

    (options, args) = parser.parse_args()

    boolResult = checkParameters(options, args)

    oBlob = blob.DPAPIBlob(open(args[0], 'rb').read())

    if not boolResult: 
        print(oBlob)
        exit()

    bEntropy = None
    if options.entropy_hex: bEntropy = bytes.fromhex(options.entropy_hex)

    if options.mkclearhex:
        print('[+] Trying the decrypted masterkey {} for this blob.'.format(options.mkclearhex))
        oBlob.decrypt(bytes.fromhex(options.mkclearhex), entropy=bEntropy)
        if oBlob.decrypted: 
            showResult(oBlob)
            exit()
        else: print('[-] Unable to decrypt blob')

    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.sid:
        if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
        if options.password: oMKP.try_credential(options.sid, options.password)
        elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
        if options.pvk: oMKP.try_domain(options.pvk)
    else:
        reg = registry.Regedit()
        secrets = reg.get_lsa_secrets(options.security, options.system)
        dpapi_system = secrets.get('DPAPI_SYSTEM')['CurrVal']

        oMKP.addSystemCredential(dpapi_system)
        oMKP.try_credential_hash(None, None)

    mks = oMKP.getMasterKeys(oBlob.mkguid.encode())

    if len(mks) == 0:
        sys.exit('[-] Unable to find MK for blob %s' % oBlob.mkguid)

    for mk in mks:
        if mk.decrypted:
            oBlob.decrypt(mk.get_key(), entropy=bEntropy)
            if oBlob.decrypted:
                showResult(oBlob)
            else:
                print('[-] Unable to decrypt blob')
        else:
            print('[-] Unable to decrypt master key')
