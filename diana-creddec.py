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
"""DECRYPTING WINDOWS CREDENTIAL FILES """

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
    if not args: sys.exit('Please specify a Cred Directory.')
    if not options.masterkeydir and not options.mkclearhex: 
        options.security = options.system = None
        print('[!] No decryption details provided, just parsing the credential files')
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
    else: print('[-] MasterKey with GUID {} not found for blob.'.format(oBlob.mkguid), file=sys.stderr)

    if oBlob.decrypted: return oBlob.cleartext
    else: return None

def parseCRED(bData, boolVerbose = True):
    bRemainder = bData[4:] ## First 4 bytes are UNK
    iBlobSize = int(reverseByte(bRemainder[:4]).hex(), 16)
    bRemainder = bRemainder[4+4:] ## After the size, another 4 bytes UNK
    bBlob = bRemainder[:iBlobSize]
    oBlob = blob.DPAPIBlob(bBlob)
    if boolVerbose:
        print('[+] Credential Description  : {}'.format(oBlob.description.strip(b'\x00').strip().decode(errors='ignore')))
        print('[+] Required Masterkey GUID : {}'.format(oBlob.mkguid))
    return oBlob

def parseDecrCred(bDecryptedCRED, boolVerbose = True):
    def eatString(bData):
        iDataLen = int(reverseByte(bData[:4]).hex(), 16)
        sData = bData[4:4+iDataLen].decode('UTF-16LE')
        return sData, bData[4+iDataLen:]
    def parseHeader(bHeader):
        iFullSize = int(reverseByte(bHeader[:4]).hex(), 16) ## After size, 3 x 4 bytes UNK
        sLastUpdate = parseTimestamp(bHeader[4+12:4+12+8]) ## After update, 4 bytes UNK
        iType = int(reverseByte(bHeader[4+12+8+4:4+12+8+4+4]).hex(), 16)
        iNrOfContainers = int(reverseByte(bHeader[4+12+8+8:4+12+8+8+4]).hex(), 16)
        return (iFullSize, sLastUpdate, iType, iNrOfContainers)
    def parseMain(bMainData):
        sDomain, bRemainder = eatString(bMainData)
        sUnk1, bRemainder = eatString(bRemainder)
        sUnk2, bRemainder = eatString(bRemainder)
        sUnk3, bRemainder = eatString(bRemainder)
        sUsername, bRemainder = eatString(bRemainder)
        sPassword, bRemainder = eatString(bRemainder)
        return (sDomain, sUnk1, sUnk2, sUnk3, sUsername, sPassword), bRemainder
    def parseContainers(bContData, iAmount):
        bRemainder = bContData
        lstContainers = []
        bContainerBlob = b''
        for i in range(iAmount):
            bRemainder = bRemainder[4:]
            sName, bRemainder = eatString(bRemainder)
            iSize = int(reverseByte(bRemainder[:4]).hex(), 16)
            bRemainder = bRemainder[4:]
            bData = bRemainder[:iSize]
            bRemainder = bRemainder[iSize:]
            bContainerBlob += bData
            lstContainers.append((sName,bData))
        return lstContainers, bContainerBlob
    iHeaderLen = int(reverseByte(bDecryptedCRED[:4]).hex(), 16) ## This lenght includes the 4 bytes of the headerlength
    bHeader = bDecryptedCRED[4:iHeaderLen]
    lstHeader = parseHeader(bHeader) ## FullDatasize, LastUpdate, Type, NrOfContainers
    print('[+] Last Update : {}'.format(lstHeader[1]))
    bRemainder = bDecryptedCRED[iHeaderLen:]
    print('[+] Main Data')
    lstMain, bRemainder = parseMain(bRemainder)
    print('    Domain   : {}'.format(lstMain[0]))
    print('    Data1    : {}'.format(lstMain[1]))
    print('    Data2    : {}'.format(lstMain[2]))
    print('    Data3    : {}'.format(lstMain[3]))
    print('    Username : {}'.format(lstMain[4]))
    print('    Password : {}'.format(lstMain[5]))
    bContainerBlob = None
    if lstHeader[2] == 2:
        lstContainers, bContainerBlob = parseContainers(bRemainder, lstHeader[3]) ## (sName, bData)
    return (lstHeader, lstMain, bContainerBlob)

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog [options] credential1 credential2 ...\n\n'
        'It tries to decrypt user/system credential files.\n'
        '%appdata%\\Microsoft\\Credentials\\* or \n'
        '%localappdata%\\Microsoft\\Credentials\\* or \n'
        '\\Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Credentials\\* or \n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Credentials\\*\n'
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

    ## Step 2: parse CRED files
    for sCredPath in args:
        for sCredFile in os.listdir(sCredPath.replace('*','')):
            print('-------- Working on file ' + sCredFile + ' --------')
            bCredData = open(os.path.join(sCredPath,sCredFile),'rb').read()
            oBlob = parseCRED(bCredData, not boolDecrypt)
            if boolDecrypt: 
                bDecryptedCRED = decryptBlob(oMKP, oBlob)
                (lstHeader, lstMain, bContainerBlob) = parseDecrCred(bDecryptedCRED)
                if lstHeader[2] == 2 and bContainerBlob: ## Data is DPAPI encrypted
                    try: 
                        oBlob2 = blob.DPAPIBlob(bContainerBlob)
                        print('[+] Found another DPAPI blob, decrypting now')
                        bDecrytedData = decryptBlob(oMKP, oBlob2)
                        if oBlob2.decrypted: print(bDecrytedData.decode())
                        else:
                            print('     Writing to {}.blob for manual decryption later'.format(oBlob2.mkguid))
                            open('{}.blob'.format(oBlob2.mkguid),'wb').write(bContainerBlob)
                    except: pass
            print('#'*70)
            
