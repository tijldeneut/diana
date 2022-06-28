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
'''
Decrypting Stored Passwords in WinSCP, the data can be found in the registry at this location:
HKCU\SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\
Or: NTUSER.DAT in SOFTWARE\Martin Prikryl\WinSCP 2\Sessions\
'''
import optparse, os
from Registry.Registry import Registry ## python3 -m pip install --upgrade python-registry

def getData(sNTUSERhive):
    lstCreds = []
    oSoftReg = Registry(sNTUSERhive)
    try: oKeys = oSoftReg.open(r'Software\Martin Prikryl\WinSCP 2\Sessions')
    except: return lstCreds
    for oSubKey in oKeys.subkeys():
        if oSubKey.name() == 'Default%20Settings': continue
        try: lstCreds.append((oSubKey.value('HostName').value(), oSubKey.value('UserName').value(), oSubKey.value('Password').value(), oSubKey.name()))
        except: continue
    return lstCreds

def decryptWinSCP(sHostname, sUsername, hexPassword):
    def decrypt(bData): return ~(bData ^ 0xA3)%256 ## MAGIC BYTE
    bPassword = bytes.fromhex(hexPassword)
    if decrypt(bPassword[0]) == 0xFF: ## New Version
        bPassword = bPassword[1:] 
        iLen = decrypt(bPassword[1])
    else: ## Older Version
        iLen = decrypt(bPassword[0]) 
    iOffset = decrypt(bPassword[2])
    bPassword = bPassword[3+iOffset:]
    sResult = ''
    for bChar in bPassword:
        sResult += chr(decrypt(bChar))
    sResult = sResult[:iLen] ## only the first characters are useful
    ## Result at this point is HOSTNAME+USERNAME+PASSWORD
    if not sHostname == '' and not sUsername == '' and sUsername.lower() + sHostname.lower() in sResult.lower():
        return sResult[len(sHostname) + len(sUsername):]
    else:
        return sResult
        
if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] NTUSER\n\n'
        'Decrypting credentials from WinSCP (2) from registry\n'
        'The required data can be found at\n'
        'HKCU\\SOFTWARE\\Martin Prikryl\\WinSCP 2\\Sessions\\\n'
        'which is inside the NTUSER.DAT in the user folder')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--export', '-e', dest='export', metavar='FILE', help='Export decrypted sessions to CSV file')

    (options, args) = parser.parse_args()

    if len(args) == 0: exit('[-] Error: please specify the NTUSER hive')
    if not os.path.exists(args[0]): exit('[-] Error: file {} not found'.format(args[0]))
    lstSessions = getData(args[0])

    ## HostName, UserName, HexPassword, SessionName
    if len(lstSessions) == 0: exit('[-] No sessions found')
    
    print('[+] Found {} sessions, decrypting now: '.format(len(lstSessions)))
    if options.export and os.path.exists(options.export): oFile = open(options.export,'a')
    elif options.export:
        oFile = open(options.export,'w')
        oFile.write('SessionName,Hostname,Username,Password\n')
        
    for lstSession in lstSessions:
        sClearPass = decryptWinSCP(lstSession[0], lstSession[1], lstSession[2])
        print('     Session {}: {} @ {} with password {}'.format(lstSession[3], lstSession[1], lstSession[0], sClearPass))
        if options.export: oFile.write('{},{},{},{}\n'.format(lstSession[3], lstSession[1], lstSession[0], sClearPass))
    if options.export: oFile.close()
        
    