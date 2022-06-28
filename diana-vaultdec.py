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
"""DECRYPTING VAULT FILES (VCRD) """

import optparse, os, sys, time, re
from Crypto.Cipher import AES

try:
    import dpapick3.blob as blob
    import dpapick3.masterkey as masterkey
    import dpapick3.registry as registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3.')

def checkParameters(options, args):
    """Simple checks on the parameters set by the user."""
    if not args or not len(args) == 1: sys.exit('Please specify a Vault (directory).')
    if not options.masterkeydir and not options.mkclearhex: 
        options.security = options.system = None
        print('[!] No decryption details provided, just parsing the vault(s)')
        return False
    if options.mkclearhex: return True
    if not options.sid:
        try:
            options.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", options.masterkeydir)[0]
            print('[+] Detected SID: ' + options.sid)
        except: pass
    if options.sid:
        options.security = options.system = None
        if not options.password and not options.pwdhash and not options.pvk: 
            print('[+] No password/hash/pvk provided, will assume empty password')
            options.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
    else:
        for x in [options.security, options.system]: 
            if not os.path.exists(x): sys.exit('You must provide SYSTEM and SECURITY hives.')    
    return True

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseGUID(bData):
    return reverseByte(bData[:4]).hex() + '-' + reverseByte(bData[4:6]).hex() + '-' + reverseByte(bData[6:8]).hex() + '-' + bData[8:10].hex() + '-' + bData[10:].hex()

def parseTimestamp(bData):
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def getSchemaType(sGUID):
    if sGUID.lower() == '3e0e35be-1b77-43e7-b873-aed901b6275b': return 'Domain Password Credential'
    elif sGUID.lower() == 'e69d7838-91b5-4fc9-89d5-230d4d4cc2bc': return 'Domain Certificate Credential'
    elif sGUID.lower() == '3c886ff3-2669-4aa2-a8fb-3f6759a77548': return 'Extended Credential'
    elif sGUID.lower() == 'b2e033f5-5fde-450d-a1bd-3791f465720c': return 'Pin Logon'
    elif sGUID.lower() == 'b4b8a12b-183d-4908-9559-bd8bce72b58a': return 'Picture Password'
    elif sGUID.lower() == 'fec87291-14f6-40b6-bd98-7ff245986b26': return 'Biometric'
    elif sGUID.lower() == '1d4350a3-330d-4af9-b3ff-a927a45998ac': return 'Next Generation Credential'
    elif sGUID.lower() == '3ccd5499-87a8-4b10-a215-608888dd3b55': return 'Web Password Credential'
    elif sGUID.lower() == '154e23d0-c644-4e6f-8ce6-5069272f999f': return 'Credential Picker Protector'
    elif sGUID.lower() == '4bf4c442-9b8a-41a0-b380-dd4a704ddb28': return 'Web Credentials'
    elif sGUID.lower() == '77bc582b-f0a6-4e15-4e80-61736b6f3b29': return 'Windows Credentials'
    return 'Unknown'

def decryptBlob(oMKP, oBlob):
    """Helper to decrypt blobs."""
    oMKS = oMKP.getMasterKeys(oBlob.mkguid.encode())
    if oMKS:
        for oMK in oMKS:
            if oMK.decrypted:
                oBlob.decrypt(oMK.get_key())
                if oBlob.decrypted: break
    else: print('[-] MasterKey not found for blob.', file=sys.stderr)

    if oBlob.decrypted: return oBlob.cleartext
    else: return None

def parsePolicy(bData, boolVerbose = False):
    bVersion = reverseByte(bData[:4])
    sPolGuid = parseGUID(bData[4:20])
    iPolDescrLen = int(reverseByte(bData[20:24]).hex(), 16)
    sPolDescr = bData[24:24+iPolDescrLen].decode('utf-16le').strip('\x00')
    iOffset = 24 + iPolDescrLen + 4 + 4 + 4 ## Unk1, Unk2 & Unk3 contain Unknown bytes, usually 0x0 or 0x1
    bRemainder = bData[iOffset:] ## start of vpol_store(s)
    if boolVerbose:
        print('--- Policy MetaData ---')
        print('[+] GUID        : ' + sPolGuid)
        print('[+] Description : ' + sPolDescr)
    i = 0
    while len(bRemainder) >= 4:
        i += 1
        iStoreLen = int(reverseByte(bRemainder[:4]).hex(), 16)
        bRemainder = bRemainder[4:]
        if iStoreLen == 0: 
            bRemainder = ''
            continue
        else:
            sStoreGuid = parseGUID(bRemainder[:16])
            sStoreGuid2 = parseGUID(bRemainder[16:32])
            iBlobLen = int(reverseByte(bRemainder[32:36]).hex(), 16)
            bStoreBlob = blob.DPAPIBlob(bRemainder[36:36+iBlobLen])
            bRemainder = bRemainder[36+iStoreLen:]
        if boolVerbose: 
            if boolVerbose: print('-- Policy Store ' + str(i) + ' --')
            print('[+] GUID   : ' + sStoreGuid)
            print(bStoreBlob)
    return bStoreBlob

def parsePolicyEntries(bData, boolVerbose = False):
    bRemainder = bData
    arrKeys = []
    i = 0
    while len(bRemainder) >= 4:
        i += 1
        iEntryLen = int(reverseByte(bRemainder[:4]).hex(), 16)
        sType = bRemainder[12:16].decode(errors='ignore') ## KDBM == Kerberos Data Base Manager
        iDataLen = int(reverseByte(bRemainder[20:24]).hex(), 16)
        bEntry = bRemainder[24:24+iDataLen]
        bRemainder = bRemainder[4+iEntryLen:]
        arrKeys.append(bEntry)
        if boolVerbose:
            print('-- Policy Entry {} --'.format(i))
            print('[+] Description : {}'.format(sType))
            print('[+] Actual Key  : {}'.format(bEntry.hex()))
    return arrKeys[0], arrKeys[1]

def parseVCRD(bData, boolVerbose = False):
    ## VCRD == Meta Data + Array of Attribute Headers + Attributes themselves
    ## 1: Parse Meta Data
    sSchemaGUID = parseGUID(bData[0:16])
    sSchemaType = getSchemaType(sSchemaGUID)
    ## Then 4 bytes unk (0x3)
    sLastUpdate = parseTimestamp(bData[20:28]) ## Then 8 bytes unk
    iDescrLen = int(reverseByte(bData[36:40]).hex(), 16)
    sDescription = bData[40:40+iDescrLen].decode('UTF-16LE').strip('\x00')
    bRemainder = bData[40+iDescrLen:]
    if boolVerbose:
        print('--- Vault MetaData ---')
        print('[+] Schema GUID  : {} ({})'.format(sSchemaGUID, sSchemaType))
        print('[+] Last Updated : {}'.format(sLastUpdate))
        print('[+] Description  : {}'.format(sDescription))
        if sSchemaType == 'Next Generation Credential': print('[+] NGC Vault detected, please run diana-ngcvaultdec.py')
    ## 2: Parse AttributeHeaders
    iAttrHeaderLen = int(reverseByte(bRemainder[:4]).hex(), 16)
    bHeaders = bRemainder[4:4+iAttrHeaderLen]
    arrAttrHeaders = []
    while len(bHeaders) > 0:
        iAttrID = int(reverseByte(bHeaders[:4]).hex(), 16)
        iAttrOffset = int(reverseByte(bHeaders[4:8]).hex(), 16)
        arrAttrHeaders.append((iAttrID, iAttrOffset))
        bHeaders = bHeaders[12:]
    #if boolVerbose:
    #    for x in arrAttrHeaders: print('[+] Attribute {} has VCRD offset {}'.format(x[0],x[1]))
    ## 3: Parse Attributes
    bRemainder = bRemainder[4+iAttrHeaderLen:] ## we should now be in bData[arrAttrHeaders[0][1]:] (offset from the first attribute)
    bData = bIV = b''
    for x in range(0,len(arrAttrHeaders)):
        iAttrID = int(reverseByte(bRemainder[:4]).hex(), 16) ## Followed by 12 bytes of unk1, unk2 and unk3
        bRemainder = bRemainder[4+4+4+4:]
        ## Dirty: there could be 6 bytes of b'\x00' padding here
        if bRemainder[:6] == 6*b'\x00': bRemainder = bRemainder[6:]
        ## Dirty: if iAttrID > 100, then we have 4 more unk bytes (unk4)
        if iAttrID >= 100: bRemainder = bRemainder[4:]
        iFullSize = int(reverseByte(bRemainder[:4]).hex(), 16)
        bRemainder = bRemainder[4:]
        if bRemainder[:1] == b'\x01': ## Has_IV
            iIVLen = int(reverseByte(bRemainder[1:5]).hex(), 16)
            bIV = bRemainder[5:5+iIVLen]
            iDataLen = iFullSize-1-4-iIVLen
            bData = bRemainder[5+iIVLen:5+iIVLen+iDataLen]
            iFullSize+=2
        else:
            bData = bRemainder[1:1+iFullSize-1]
        if len(bData)<50: print('[+] Attribute ID {} has data : {}'.format(iAttrID, bData.hex()))
        else: print('[+] Attribute ID {} : '.format(iAttrID))
        bRemainder = bRemainder[iFullSize:]
    if boolVerbose and sSchemaType == 'Next Generation Credential':
        print('[+] IV   : {}'.format(bIV.hex()))
        print('[+] Data : {}'.format(bData.hex()))
    return (bIV, bData, sSchemaType) ## This assumes there is only one IV + Data per vault

def parseContainers(bData, boolVerbose = False):
    iVersion = int(reverseByte(bData[:4]).hex(), 16)
    iNumberOfContainers = int(reverseByte(bData[4:8]).hex(), 16) ## Then 4 bytes unk (0x1)
    bRemainder = bData[12:]
    dicContainers = {}
    for x in range(0,iNumberOfContainers):
        iID = int(reverseByte(bRemainder[:4]).hex(), 16)
        iSize = int(reverseByte(bRemainder[4:8]).hex(), 16)
        bData = bRemainder[8:8+iSize]
        dicContainers[iID] = bData
        bRemainder = bRemainder[8+iSize:]
        if boolVerbose:
            print('[+]     Container ID   : {}'.format(iID))
            try: print('[+]     Container Data : {}'.format(bData.decode('UTF-16LE')))
            except: print('[+]     Container Data : {}'.format(bData.hex()))
    return dicContainers

def parseSID(bData):
    sResult = 'S-'
    sResult += str(bData[0]) + '-'
    sResult += str(bData[1]) + '-'
    sResult += str(bData[8]) + '-'
    sResult += str(int(reverseByte(bData[12:16]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[16:20]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[20:24]).hex(), 16)) + '-'
    sResult += str(int(reverseByte(bData[24:28]).hex(), 16))
    return sResult

def parseFinalData(bData, boolVerbose = False):
    sType = reverseByte(bData[:4])
    iEncDataLen = int(reverseByte(bData[4:8]).hex(),16)
    iIVLen = int(reverseByte(bData[8:12]).hex(), 16)
    iEncPwdLen = int(reverseByte(bData[12:16]).hex(), 16)
    iLastLen = int(reverseByte(bData[16:20]).hex(), 16)
    iOffset = 20
    sEncData = bData[iOffset:iOffset + iEncDataLen].hex()
    iOffset += iEncDataLen
    sIV = bData[iOffset:iOffset + iIVLen].hex()
    iOffset += iIVLen
    sEncPwd = bData[iOffset:iOffset + iEncPwdLen].hex()
    iOffset += iEncPwdLen
    sLast = bData[iOffset:iOffset + iLastLen].hex()
    if boolVerbose:
        print('[+] EncData     : ' + sEncData)
        print('[+] IV          : ' + sIV)
        print('[+] EncPassword : ' + sEncPwd)
    return (sEncData, sIV, sEncPwd)

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] Vault Directory\n\n'
        'It tries to decrypt Vault VCRD files.\n'
        'E.g.: Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Vault\\<GUID>\n'
        'or  : %ProgramData%\\Microsoft\\Vault\\<GUID>\n'
        'or  : %localappdata%\\Microsoft\\Vault\\<GUID>\n'
        '# Provide system MK data for system credentials:\n'
        '\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User\n'
        'or user MK data for user credentials:\n'
        '%appdata%\\Microsoft\\Protect\\<SID>')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--masterkey', metavar='DIRECTORY', dest='masterkeydir')
    parser.add_option('--credhist', metavar='FILE', dest='credhist')
    parser.add_option('--sid', metavar='SID', dest='sid')
    parser.add_option('--password', metavar='PASSWORD', dest='password')
    parser.add_option('--pwdhash', metavar='HASH', dest='pwdhash', help='Example for empth hash: da39a3ee5e6b4b0d3255bfef95601890afd80709')
    parser.add_option('--pvk', '-k', help='Optional: Depending on MK; domain RSA PVK keyfile')
    parser.add_option('--system', metavar='HIVE', dest='system', default=os.path.join('Windows','System32','config','SYSTEM'))
    parser.add_option('--security', metavar='HIVE', dest='security', default=os.path.join('Windows','System32','config','SECURITY'))
    parser.add_option('--clearmasterkey', metavar='HEX', dest='mkclearhex', help='Provide manually decrypted DPAPI key here')

    (options, args) = parser.parse_args()

    boolDecrypt = checkParameters(options, args)

    ## Step 1: prepare DPAPI data
    oMKP = masterkey.MasterKeyPool()
    oMKP.loadDirectory(options.masterkeydir)

    if options.security and options.system:
        oReg = registry.Regedit()
        oSecrets = oReg.get_lsa_secrets(options.security, options.system)
        oSystemKey = oSecrets.get('DPAPI_SYSTEM')['CurrVal']
        oMKP.addSystemCredential(oSystemKey)
        oMKP.try_credential_hash(None, None)
    else:
        if options.credhist: oMKP.addCredhistFile(options.sid, options.credhist)
        if options.pvk: oMKP.try_domain(options.pvk)
        if options.password: oMKP.try_credential(options.sid, options.password)
        elif options.pwdhash: oMKP.try_credential_hash(options.sid, bytes.fromhex(options.pwdhash))

    ## Step 2: Parse and DPAPI decrypt Policy.vpol
    sVpol = os.path.join(args[0], 'Policy.vpol')
    if os.path.exists(sVpol):
        with open(sVpol, 'rb') as f: oVpolBlob = parsePolicy(f.read())
        if boolDecrypt: 
            bVpolCleartext = decryptBlob(oMKP, oVpolBlob)
            if not bVpolCleartext: exit('[-] Unable to decrypt Policy.vpol')
            bKeyAES128, bKeyAES256 = parsePolicyEntries(bVpolCleartext)
            print('[+] Decrypted vpol file, AES key {}'.format(bKeyAES256.hex()))
        else: print('[+] Found vpol file, to decrypt, we need masterkey with GUID: {}'.format(oVpolBlob.mkguid))
        
    ## Step 3: Parse and AES decrypt VCRD
    sUsername = ''
    iCount = 0
    for sFile in os.listdir(args[0]):
        if sFile.lower().endswith('.vcrd'):
            sFilepath = os.path.join(args[0], sFile)
            print('---- Working on ' + sFile + ' ----')
            with open(sFilepath, 'rb') as oVcrdfile:
                iCount += 1
                bIV, bData, sSchemaType = parseVCRD(oVcrdfile.read(), not boolDecrypt) ## parseVCRD verifies the vault type (GUIDs at the top of this file)
                #bIV, bData, sSchemaType = parseVCRD(oVcrdfile.read(), True) ## parseVCRD verifies the vault type (GUIDs at the top of this file)
                if boolDecrypt and bKeyAES256 and bData:
                    cipher = AES.new(bKeyAES256, AES.MODE_CBC, iv = bIV)
                    bDecrypted = cipher.decrypt(bData)
                    dicContainers = parseContainers(bDecrypted) ## dicContainers[ContainerID] = bData
                    if dicContainers[1].startswith('NGC'.encode('UTF-16LE')): ## Should be "NGC Local Accoount Logon Vault Resource" in utf-16le
                        sSID = parseSID(dicContainers[2])
                        print('[+] Schema Type : {}'.format(sSchemaType))
                        print('[+] User SID    : {}'.format(sSID))
                        parseFinalData(dicContainers[3], True)
                    else:
                        print('[+] Decryption successful')
                        print('    Schema Type     : {}'.format(sSchemaType))
                        for sCont in dicContainers:
                            print('     Container ID   : {}'.format(sCont))
                            try: print('     Container Data : {}'.format(dicContainers[sCont].decode('UTF-16LE')))
                            except: print('     Container Data : {}'.format(dicContainers[sCont].hex()))
            print('#'*70)
    if iCount == 0: print('[-] No Vault VCRD files were found')
