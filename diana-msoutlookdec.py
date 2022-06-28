#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
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

"""
Microsoft Outlook Registry DPAPI password decryption utility.
Note: newer O365 / MS Live accounts use tokens and are stored in Vaults and Credential files
"""

import optparse, sys, re, os
try: from dpapick3 import blob, masterkey, registry
except ImportError: raise ImportError('[-] Missing dpapick3, please install via pip install dpapick3.')

def check_parameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1: sys.exit('[-] You must provide the ntuser.dat file (or reg save hkcu ntuser.dat).')
    if not os.path.exists(args[0]): sys.exit('[-] Error: file {} not found'.format(args[0]))
    if not options.masterkeydir: sys.exit('You must provide a masterkeys directory!')
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except:
            sys.exit('[-] You must provide the user\'s SID textual string.')
    if not options.password and not options.pwdhash and not options.pvk:
        print('[!] No password provided, assuming user has no password.')
        options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        #options.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0' ## NT hash sometimes also works

def decryptPass(oBlob, oMKP):
    lstMKs = oMKP.getMasterKeys(oBlob.mkguid.encode())
    if len(lstMKs) == 0: print('[-] Unable to find MK for blob %s' % oBlob.mkguid)
    for oMK in lstMKs:
        if oMK.decrypted: oBlob.decrypt(oMK.get_key())
    if oBlob.decrypted: sClearPass = oBlob.cleartext.decode('UTF-16LE')
    else: sClearPass = None
    return sClearPass

def parseRegistry(sHive):
    lstAllAccounts = []
    lstAllEmails = []
    with open(sHive, 'rb') as oHive:
        oReg = registry.Registry.Registry(oHive)
        oBase = oReg.open('SOFTWARE\\Microsoft\\Office')
        iHighestVersion = 0
        for oVersionKey in oBase.subkeys():
            try: float(oVersionKey.name())
            except: continue
            if float(oVersionKey.name().split('.')[0])>iHighestVersion: iHighestVersion = float(oVersionKey.name())
        if iHighestVersion == 0: return None
        oBase = oReg.open('SOFTWARE\\Microsoft\\Office\\{}\\Outlook\\Profiles'.format(iHighestVersion))
        for oProfileKeys in oBase.subkeys():
            for oMailAccountKeys in oProfileKeys.subkey('9375CFF0413111d3B88A00104B2A6676').subkeys():
                sAccountName = sDisplayName = sEmail = sIMAPUser = bIMAPPassword = oBlob = None
                for oValue in oMailAccountKeys.values():
                    sAccountName = oValue.value() if oValue.name().lower() == 'account name' else sAccountName
                    sDisplayName = oValue.value() if oValue.name().lower() == 'display name' else sDisplayName
                    sEmail = oValue.value() if oValue.name().lower() == 'email' else sEmail
                    sIMAPUser = oValue.value() if oValue.name().lower() == 'account name' else sIMAPUser
                    bIMAPPassword = oValue.value() if oValue.name().lower() == 'imap password' else bIMAPPassword
                if '@' in sAccountName: lstAllEmails.append(sAccountName)
                if not bIMAPPassword: continue
                if bIMAPPassword[0] == 2: 
                    oPasswordBlob = blob.DPAPIBlob(bIMAPPassword[1:])
                    lstAllAccounts.append((sAccountName, sDisplayName, sEmail, sIMAPUser, oPasswordBlob))
    return lstAllAccounts, lstAllEmails

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] NTUSER\n\n'
        'It decrypts MS Outlook credentials from NTUSER.dat.\n'
        '\'reg save hkcu ntuser.dat\'\n'
        'Also needs user MasterKey and either SID+password/hash or Domain PVK')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', '-k', help='Optional: Depending on MK; domain RSA PVK keyfile')

    (options, args) = parser.parse_args()

    check_parameters(options, args)

    lstAllAccounts, lstAllEmails = parseRegistry(args[0])

    if len(lstAllAccounts) > 0: print('[+] Found {} account(s), decrypting now'.format(len(lstAllAccounts)))
    else: 
        if len(lstAllEmails) == 0:
            print('[-] No accounts found')
            exit()
        else: 
            print('[!] Found {} undecryptable email-addresses:'.format(len(lstAllEmails)))
            for sAccount in lstAllEmails: print('     - {}'.format(sAccount))
            exit()
        
    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
    if options.password: oMKP.try_credential(options.sid, options.password)
    elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))
    if options.pvk: oMKP.try_domain(options.pvk)

    for lstAccount in lstAllAccounts:
        ## sAccountName, sDisplayName, sEmail, sIMAPUser, oPasswordBlob
        sClearPass = decryptPass(lstAccount[4], oMKP)
        if sClearPass:
            print('[+] Decrypted account {}: '.format(lstAccount[0]))
            print('    Email "{}" and Display Name "{}"'.format(lstAccount[2], lstAccount[1]))
            print('    IMAP User "{}" and IMAP Password "{}"'.format(lstAccount[3], sClearPass))
