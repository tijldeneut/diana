#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2022, Photubias <tijl.deneut@howest.be>
#
## C:\Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\MicrosoftAccount\<id>\Cache
##  Relation between ID and account: HKLM\SOFTWARE\Microsoft\IdentityStore\LogonCache\D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F\Name2Sid
##  #> This ID is a 32byte (64 char) cloud key: it is the same on each machine, maybe this is the unique MS Live ID? 
##  #> Also the DPAPI user key is probably derived from the cleartext password because the DPAPI key is the same on multiple machines until password changes
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
""" Windows Microsoft Account DPAPI key decryption utility."""

import hashlib, optparse, os, sys
from Crypto.Cipher import AES ## pip3 install pycryptodome

def checkParams(options, args):
    if not options.cachedatafile or not options.password:
        sys.exit('You must provide cleartext password and cachedata file.')
    if not os.path.isfile(options.cachedatafile):
        sys.exit('File not found: {}.'.format(options.cachedatafile))
    return

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def getEncryptedData(bLeftoverData):
    ## The data is divided into DataLength + Data, the DPAPI data can be the first or even the last
    lstReturnData = []
    while len(bLeftoverData) > 0:
        iLength = int(reverseByte(bLeftoverData[:4]).hex(), 16)
        bData = bLeftoverData[4:4+iLength]
        if b'RSA1' in bData: 
            ## The RSA1 public key does not follow the Length+Data system, just skip over (assuming 256 byte RSA1 modulus)
            bLeftoverData = bLeftoverData[4+0x3D8:]
            continue
        if iLength > 48: lstReturnData.append(bData)
        bLeftoverData = bLeftoverData[4+iLength:]
    return lstReturnData

def parseDecryptedCache(bClearData, boolVerbose = True):
    sPassword = None
    ## DPAPI Password should be at offset 48, length 88 bytes
    try: sPassword = bClearData[48:136].decode('UTF-16LE')
    except: return None
    
    if not boolVerbose: return sPassword
    ## Offset 48+88+4 bytes (140) should be the length of the rest of the file
    bData = bClearData[140:]
    iLength = int(reverseByte(bData[:4]).hex(), 16) 
    bData = bData[4:4+iLength][48:] ## 48 bytes UNKnown
    sStableUserId = bData[:32].decode('UTF-16LE')
    bData = bData[32:]
    ## Now an XML should follow, starting with a Unicode Null Byte and ending with one
    if bData[:2] == b'\x00\x00': 
        bXML = bData[2:].split(b'\x00\x00')[0]+b'\x00'
        sXML = bXML.decode('UTF-16LE')
    else: 
        print('[-] Parsing error')
        return sPassword
    bData = bData[2+len(bXML)+2:]
    ## Now there could be a DPAPI blob first
    if bData[:8] == bytes.fromhex('0100000001000000'):
        ## DPAPI Blob now
        print('[+] Found SYSTEM DPAPI blob')
        bBlob = bData[8:].split(bytes.fromhex('010b00000000000b'))[0]
        bData = bData[8+len(bBlob):]
    if bData[:8] == bytes.fromhex('010b00000000000b'):
        #print(bData[8+4+40:].hex())
        bAccount = bData[8+4+40:].split(b'\x00\x00')[0]+b'\x00'
        sAccount = bAccount.decode('UTF-16LE')
    else: return sPassword
    print('[+] Decoded:')
    print('    StableUserID : {} (There should be a SQLite archive at %localappdata%\\ConnectedDevicesPlatform\\{}\\)'.format(sStableUserId, sStableUserId))
    print('    User Account : {}'.format(sAccount))
    print('    XML Cipher : {}'.format(sXML))
    print('')
    return sPassword

def walkThroughFile(bCacheDataOrg, oCipher):
    ## Let's walk through the file reading 4 bytes at a time, looking for "length" headers
    for i in range(0,len(bCacheDataOrg),4):
        iLength = int(reverseByte(bCacheDataOrg[i:i+4]).hex(), 16) 
        ## Let's assume the encrypted datalength is less than 65535 bytes
        if iLength>=0xffff or iLength==0: continue
        bEncrData = bCacheDataOrg[i+4:i+4+iLength]
        try: 
            ## If the datalength is a factor of 16 bytes, this always works
            bClearData = oCipher.decrypt(bEncrData)
            if not b'\x00\x40\x00' in bClearData: continue
            sPassword = parseDecryptedCache(bClearData, True)
            if sPassword: 
                print('[+] Success, use this as your DPAPI cleartext user password:\n    {}'.format(sPassword))
                break
            i+=iLength
        #except Exception as e: print(e)
        except: pass
    return

if __name__ == '__main__':
    usage = (
        'usage: %prog [options]\n\n'
        'It tries to unlock (decrypt) the Microsoft Account DPAPI password.\n'
        'NOTE: only works when the *cleartext* password is known\n'
        'NOTE: currently does not support the AzureAD Cache\n'
        r' Default Location: Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\MicrosoftAccount\<id>\Cache\CacheData')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--cachedatafile', '-f', metavar='FILE', help=r'CloudAPCache CacheData', default=os.path.join('Windows','System32','config','systemprofile','AppData','Local','Microsoft','Windows','CloudAPCache','MicrosoftAccount','CacheData'))
    parser.add_option('--password', '-p', metavar='STRING', help=r'Clear Text User Password')
    parser.add_option('--export', '-e', action="store_true", default=False, metavar='BOOL', help=r'Export a (crackable) Hash, TODO: write Hashcat module')

    (options, args) = parser.parse_args()
    
    checkParams(options, args)

    bDecryptionKey = hashlib.pbkdf2_hmac('sha256', options.password.encode('UTF-16LE'), b'', 10000)
    
    file = open(options.cachedatafile,'br')
    bCacheDataOrg = file.read()
    file.close()

    if not bCacheDataOrg[72:72+4] == b'\x02\x00\x00\x00':
        exit('[-] Error: Not a valid Microsoft Live Account CacheData file?')

    oCipher = AES.new(bDecryptionKey, AES.MODE_CBC, b'\x00'*16)
    
    ## First 124 are "static length", from then on length + data
    bCacheData = bCacheDataOrg[124:]
    sPassword = None
    lstCandidates = getEncryptedData(bCacheData)
    sToExport = ''
    for bEncrData in lstCandidates:
        if options.export: sToExport += bEncrData[-64:].hex()+"\n"
        bClearData = oCipher.decrypt(bEncrData)
        ## Since we know the MS Live Emailaddress is in the decoded data, there should be a unicode '@'
        if not b'\x00\x40\x00' in bClearData: continue
        sPassword = parseDecryptedCache(bClearData, True)
        if sPassword: print('[+] Success, use this as the DPAPI cleartext user password:\n    {}'.format(sPassword))
    if not sPassword: print('[-] Wrong password?')
    if options.export and not sToExport == '': print('\n[+] This should be crackable with PBKDF2-SHA256+AES256 and decrypted should contain bytes "004000":\n{}'.format(sToExport))
    
    #walkThroughFile(bCacheDataOrg, oCipher)