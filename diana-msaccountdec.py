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

import hashlib, optparse, os, sys, hmac, struct, binascii, json
from Crypto.Cipher import AES ## pip3 install pycryptodome
import dpapick3.eater as eater
from enum import IntEnum
from typing import List

class DPAPICredKeyBlob(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwBlobSize = data.eat("L")
        self.dwField4 = data.eat("L")
        self.dwCredKeyOffset = data.eat("L")
        self.dwCredKeySize = data.eat("L")
        self.Guid = "%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x" % data.eat("L2H8B")
        assert data.ofs == self.dwCredKeyOffset
        self.CredKey = data.eat_string(self.dwCredKeySize)

class CacheNodeType(IntEnum):
    PASSWORD = 1
    UNKNOW_TWO = 2
    UNKNOW_THREE = 3
    UNKNOW_FOUR = 4
    PIN = 5

class CacheDataNodeHeader(eater.DataStruct):
    def __init__(self, raw):
        eater.DataStruct.__init__(self, raw)

    def parse(self, data):
        self.dwNodeType = data.eat("L")
        self.dwCryptoBlobSize = data.eat("L")
        self.dwField8 = data.eat("L")
        self.dwEncryptedPRTSize = data.eat("L")
        self.dwField10 = data.eat("L")


class CacheDataNode:
    def __init__(self, header : CacheDataNodeHeader):
        self._header : CacheDataNodeHeader = header
        self._cryptoBlob : bytes = None
        self._encryptedPrtBlob : bytes = None

    @property
    def cryptoBlob(self):
        return self._cryptoBlob

    @cryptoBlob.setter
    def cryptoBlob(self, value):
        self._cryptoBlob = value

    @property
    def encryptedPRTBlob(self):
        return self._encryptedPrtBlob

    @encryptedPRTBlob.setter
    def encryptedPRTBlob(self, value):
        self._encryptedPrtBlob = value

    def is_node_type_password(self) -> bool:
        return self._header.dwNodeType == CacheNodeType.PASSWORD

    def is_node_type_pin(self) -> bool:
        return self._header.dwNodeType == CacheNodeType.PIN

def checkParams(options, args):
    if not options.cachedatafile or not options.password:
        sys.exit('You must provide cleartext password and cachedata file.')
    if not os.path.isfile(options.cachedatafile):
        sys.exit(f'File not found: {options.cachedatafile}.')
    return

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parse_cache_data(file_path) -> List[CacheDataNode]:
    cache_data_node_list = list()
    print(f'[+] Parsing CacheData file {file_path}')
    with open(file_path, "rb") as f:
        file_size = f.seek(0, os.SEEK_END)
        f.seek(0, os.SEEK_SET)
        # First 4 byte is a version number
        (version,) = struct.unpack("<I", f.read(4))
        print(f"[+] CacheData file version is 0x{version:x}")
        # 32 following bytes is the sha256 expected checksum
        sha256_checksum = f.read(32)
        # Compute checksum to check if matching
        payload = f.read(file_size - f.tell())
        # Read raw file
        f.seek(0, os.SEEK_SET)
        raw_payload = f.read(file_size)

    m = hashlib.sha256()
    m.update(payload)
    print(f"[+] CacheData expected sha256: {str(binascii.hexlify(sha256_checksum), 'ascii')}")
    print(f"[+] CacheData computed sha256: {m.hexdigest()}")
    assert version == 0x02
    assert sha256_checksum == m.digest()

    cache_data_node_count, = struct.unpack("<I", raw_payload[0x50:0x54])
    offset = 0x54

    print(f"[+] Parsing Cache node headers")
    for i in range (0, cache_data_node_count):
        cache_data_node_header = CacheDataNodeHeader(raw_payload[offset:offset+0x14])
        print(f"[+]\tFound CacheNode of type 0x{cache_data_node_header.dwNodeType:x}, CryptoBlobSize = 0x{cache_data_node_header.dwCryptoBlobSize:x}, EncryptedPRTSize = 0x{cache_data_node_header.dwEncryptedPRTSize:x}")
        cache_data_node_list.append(CacheDataNode(cache_data_node_header))
        offset += 0x14

    print(f"[+] Parsing raw blob")
    i = 0
    while offset < len(raw_payload):
        blob_size, = struct.unpack("<I", raw_payload[offset:offset+4])
        offset += 4
        if blob_size == 0:
            continue
        print(f'[+]\tFound blob of size 0x{blob_size:x} (offset = 0x{offset:x}/0x{len(raw_payload):x})')
        blob = raw_payload[offset:offset+blob_size]
        offset += blob_size
        if offset % 4 != 0:
            offset += (4 - (offset % 4))
        index_cache_data_node_list = i // 2
        # For each cache node, there is one cryptoBlob and one encryptedPRTBlob
        if i % 2 == 0:
            cache_data_node_list[index_cache_data_node_list].cryptoBlob = blob
        else:
            cache_data_node_list[index_cache_data_node_list].encryptedPRTBlob = blob
        i += 1

    return cache_data_node_list

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
    print(f'    StableUserID : {sStableUserId} (There should be a SQLite archive at %localappdata%\\ConnectedDevicesPlatform\\{sStableUserId}\\)')
    print(f'    User Account : {sAccount}')
    print(f'    XML Cipher : {sXML}')
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
                print(f'[+] Success, use this as your DPAPI cleartext user password:\n    {sPassword}')
                break
            i+=iLength
        #except Exception as e: print(e)
        except: pass
    return

if __name__ == '__main__':
    usage = (
        'usage: %prog [options]\n\n'
        'It tries to unlock (decrypt) the Microsoft Account DPAPI password or Azure AD one.\n'
        'NOTE: only works when the *cleartext* password is known\n'
        r' Default Location: Windows\System32\config\systemprofile\AppData\Local\Microsoft\Windows\CloudAPCache\[MicrosoftAccount|AzureAD]\<id>\Cache\CacheData')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--cachedatafile', '-f', metavar='FILE', help=r'CloudAPCache CacheData', default=os.path.join('Windows','System32','config','systemprofile','AppData','Local','Microsoft','Windows','CloudAPCache','MicrosoftAccount','CacheData'))
    parser.add_option('--password', '-p', metavar='STRING', help=r'Clear Text User Password')
    parser.add_option('--export', '-e', action="store_true", default=False, metavar='BOOL', help=r'Export a (crackable) Hash, TODO: write Hashcat module')

    (options, args) = parser.parse_args()
    
    checkParams(options, args)

    bDecryptionKey = hashlib.pbkdf2_hmac('sha256', options.password.encode('UTF-16LE'), b'', 10000)
    
    candidates = parse_cache_data(options.cachedatafile)
    file = open(options.cachedatafile,'br')
    bCacheDataOrg = file.read()
    file.close()

    oCipher = AES.new(bDecryptionKey, AES.MODE_CBC, b'\x00' * 16)
    
    ## First 124 are "static length", from then on length + data
    sPassword = None
    key = None
    sToExport = ''
    for entry in candidates:
        if not entry.is_node_type_password():
            continue
        if options.export: sToExport += entry.encryptedPRTBlob[-64:].hex() + "\n"
        bClearData = oCipher.decrypt(entry.encryptedPRTBlob)
        ## Since we know the MS Live Emailaddress is in the decoded data, there should be a unicode '@'
        if not b'\x00\x40\x00' in bClearData:
            continue
        # AzureAD
        if b'Version' in bClearData:
            version, flags, dword3, raw_dpapi_cred_key_size = struct.unpack("<IIII", bClearData[0:0x10])
            decrypted_prt = bClearData[0x70:]
            dpapi_cred_key_blob = bClearData[0x10:0x10 + raw_dpapi_cred_key_size]
            dpapi_cred_key_blob_obj = DPAPICredKeyBlob(dpapi_cred_key_blob)
            print(f'[+] Dumping raw DPAPI Cred key, with GUID {dpapi_cred_key_blob_obj.Guid} (0x40 bytes):')
            print(dpapi_cred_key_blob_obj.CredKey)
            decrypted_prt_end = decrypted_prt.rfind(b'}')
            decrypted_prt = decrypted_prt[:decrypted_prt_end + 1]
            key = hashlib.sha1(dpapi_cred_key_blob_obj.CredKey).digest()
            j = json.loads(decrypted_prt)
            sid = j['UserInfo']['PrimarySid']
            encoded_sid = (sid + '\0').encode('UTF-16-LE')
            key = hmac.new(key, encoded_sid, hashlib.sha1).hexdigest()
        # Microsoft Account
        else:
            sPassword = parseDecryptedCache(bClearData, True)
        if sPassword:
            print(f'[+] Success, use this as the DPAPI cleartext user password:\n    {sPassword}')
        if key:
            print(f'[+] Success, use this key to decrypt masterkeys of the user: 0x{key}')
    if not sPassword and not key:
        print('[-] Wrong password?')
    if options.export and not sToExport == '':
        print(f'\n[+] This should be crackable with PBKDF2-SHA256+AES256 and decrypted should contain bytes "004000":\n{sToExport}')
    
    #walkThroughFile(bCacheDataOrg, oCipher)
