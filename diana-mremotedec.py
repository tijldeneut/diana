#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2022, Tijl "Photubias" Deneut <@tijldeneut>
# 
# Based on and shoutout to: https://github.com/haseebT/mRemoteNG-Decrypt
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
Decrypting Stored Passwords in mRemoteNG confCons.xml, with or without a master password:
%appdata%\mRemoteNG\confCons.xml
'''
import optparse, os, xml.dom.minidom, hashlib, base64
from Crypto.Cipher import AES

def decrypt(sEncData, sMasterPass, iRounds=1000, sBlockCipherMode='GCM', sEncAlgo='AES', sHashAlgo='sha1'):
    bSalt = sEncData[:16]
    bNonce = sEncData[16:32]
    bCiphertext = sEncData[32:-16]
    bTag = sEncData[-16:]
    bKey = hashlib.pbkdf2_hmac(sHashAlgo, sMasterPass.encode(), bSalt, iRounds, dklen=32)
    oCipher = AES.new(bKey, getattr(AES, 'MODE_{}'.format(sBlockCipherMode)), nonce=bNonce)
    oCipher.update(bSalt)
    sPlaintext = oCipher.decrypt_and_verify(bCiphertext, bTag).decode('utf-8')
    return sPlaintext

def getData(sFile, sMasterPass):
    lstCreds = []
    oDoc = xml.dom.minidom.parseString(open(sFile,'rb').read())
    sEncAlgo = oDoc.getElementsByTagName('mrng:Connections')[0].getAttribute('EncryptionEngine')
    sBlockCipherMode  = oDoc.getElementsByTagName('mrng:Connections')[0].getAttribute('BlockCipherMode')
    iRounds = int(oDoc.getElementsByTagName('mrng:Connections')[0].getAttribute('KdfIterations'))
    for oConn in oDoc.getElementsByTagName('Node'):
        try: 
            sName = oConn.getAttribute('Name')
            sProtocol = oConn.getAttribute('Protocol')
            sEncPassword = base64.b64decode(oConn.getAttribute('Password'))
            sDomain = oConn.getAttribute('Domain')
            sUsername = oConn.getAttribute('Username')
            sHostname = oConn.getAttribute('Hostname')
            sDescription = oConn.getAttribute('Descr')
            sClearPass = decrypt(sEncPassword, sMasterPass, iRounds, sBlockCipherMode, sEncAlgo)
            lstCreds.append((sName, sHostname, sProtocol, sDomain, sUsername, sClearPass, sDescription))
        except: continue
        #except Exception as e: print('Error: {}'.format(e))
    return lstCreds

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] xml-file\n\n'
        'Decrypting credentials from mRemoteNG XML connections file\n'
        'Default file location:\n'
        '%appdata%\\mRemoteNG\\confCons.xml')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterpass', '-p', dest='password', metavar='STRING', help='mRemoteNG master password, if any', default='mR3m')
    parser.add_option('--export', '-e', dest='export', metavar='FILE', help='Export decrypted sessions to CSV file')

    (options, args) = parser.parse_args()

    if len(args) == 0: exit('[-] Error: please specify the confCons XML file')
    if not os.path.exists(args[0]): exit('[-] Error: file {} not found'.format(args[0]))
    ## sName, sHostname, sProtocol, sDomain, sUsername, sClearPass, sDescription
    lstSessions = getData(args[0], options.password)
        
    if options.export and os.path.exists(options.export): oFile = open(options.export,'a')
    elif options.export:
        oFile = open(options.export,'w')
        oFile.write('SessionName,Hostname,Protocol,Domain,Username,Password,Description\n')

    if len(lstSessions)>0: print('[+] Decrypted {} connections: '.format(len(lstSessions)))
    
    print('    {0:30} | {1:30} | {2:5} | {3:20} | {4:20}'.format('Session', 'Hostname', 'Type', 'Username', 'Password'))
    for lstSession in lstSessions:
        sCred = lstSession[3] + '\\' + lstSession[4] if not lstSession[3] == '' else lstSession[4]
        #print('    {} : Host {} ({}); Username {} and password {}'.format(lstSession[0], lstSession[1], lstSession[2], sCred, lstSession[5]))
        print('    {0:30} | {1:30} | {2:5} | {3:20} | {4:20}'.format(lstSession[0], lstSession[1], lstSession[2], sCred, lstSession[5]))
        if options.export: oFile.write('{},{},{},{},{},{},{}\n'.format(lstSession[0], lstSession[1], lstSession[2], lstSession[3], lstSession[4], lstSession[5], lstSession[6]))