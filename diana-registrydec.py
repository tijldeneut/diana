#!/usr/bin/python3
# vim:ts=4:expandtab:sw=4
# -*- coding: utf-8 -*-
#
# Copyright 2025, Tijl "Photubias" Deneut <@tijldeneut>
# 
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at 
#
# http://www.apache.org/licenses/LICENSE-2.0
#
## Source (Domain Cache Dump):   https://github.com/CiscoCXSecurity/creddump7
## Source (Product Key Decoder): https://github.com/mrpeardotnet/WinProdKeyFinder
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

## TODO: dpapi_machinekey & dpapi_userkey
##        Scheduled Task Credentials (seems to not be stored decryptable?)
'''
##        There might be an LSA secret called RasCredentials!{SID}#0, which contains dial-up connection passwords when enabled (source: https://www.exploit-db.com/exploits/19196)
##        There might be an LSA secret called RasDialParams!{SID}#0, which contains dial-up connection passwords when NOT enabled (source: https://www.exploit-db.com/exploits/19196)
##             --> This {SID} can also just be "S-1-5-18" when it's system enabled
'''
'''
Decrypting and parsing some interesting and General Windows Information.
Offline and based on certain files and/or registry dumps
Specifically to find general system info (users, computername, versions)
 but also to retrieve/decrypt all kinds of User Credentials
'''

from hashlib import md5
from hashlib import new as hashlibnew
import os, time, optparse, datetime
import dpapick3.registry as dpareg ## python3 -m pip install --upgrade dpapick3
from Registry.Registry import Registry ## python3 -m pip install --upgrade python-registry (required for dpapick3)
from Crypto.Cipher import AES, ARC4, DES ## python3 -m pip install --upgrade pycryptodome (required for dpapick3)

## Source: https://docs.microsoft.com/en-us/troubleshoot/windows-server/identity/security-identifiers-in-windows
dictNormalGroups = {'S-1-0-0':'Nobody', 'S-1-1':'World Authority', 'S-1-1-0':'Everyone', 'S-1-2':'Local Authority', 'S-1-2-0':'Local', 'S-1-2-1':'Console Logon', 'S-1-3':'Creator Authority', 'S-1-3-0':'Creator Owner', 'S-1-3-1':'Creator Group', 'S-1-3-2':'Creator Owner Server', 'S-1-3-3':'Creator Group Server', 'S-1-3-4':'Owner Rights', 'S-1-4':'Non-unique Authority', 'S-1-5':'NT Authority', 'S-1-5-1':'Dialup', 'S-1-5-10':'Principal Self', 'S-1-5-11':'Authenticated Users', 'S-1-5-12':'Restricted Code', 'S-1-5-13':'Terminal Server Users', 'S-1-5-14':'Remote Interactive Logon', 'S-1-5-15':'This Organization', 'S-1-5-17':'This Organization', 'S-1-5-18':'Local System', 'S-1-5-19':'NT Authority', 'S-1-5-2':'Network', 'S-1-5-20':'NT Authority', 'S-1-5-3':'Batch', 'S-1-5-4':'Interactive', 'S-1-5-6':'Service', 'S-1-5-7':'Anonymous', 'S-1-5-8':'Proxy', 'S-1-5-9':'Enterprise Domain Controllers'}
dictDomainGroups = {'496':'COMPOUNDED_AUTHENTICATION', '497':'CLAIMS_VALID', '498':'Enterprise Read-only Domain Controllers', '500':'Administrator', '501':'Guest', '502':'KRBTGT', '512':'Domain Admins', '513':'Domain Users', '514':'Domain Guests', '515':'Domain Computers', '516':'Domain Controllers', '517':'Cert Publishers', '518':'Schema Admins', '519':'Enterprise Admins', '520':'Group Policy Creator Owners', '521':'Read-only Domain Controllers', '522':'Cloneable Domain Controllers', '525':'PROTECTED_USERS', '526':'Key Admins', '527':'Enterprise Key Admins', '553':'RAS and IAS Servers', '571':'Allowed RODC Password Replication Group', '572':'Denied RODC Password Replication Group'}
dictBuiltinGroups = {'S-1-15-2-1':'ALL_APP_PACKAGES', 'S-1-16-0':'Untrusted Mandatory Level', 'S-1-16-12288':'High Mandatory Level', 'S-1-16-16384':'System Mandatory Level', 'S-1-16-20480':'Protected Process Mandatory Level', 'S-1-16-28672':'Secure Process Mandatory Level', 'S-1-16-4096':'Low Mandatory Level', 'S-1-16-8192':'Medium Mandatory Level', 'S-1-16-8448':'Medium Plus Mandatory Level', 'S-1-18-1':'AUTHENTICATION_AUTHORITY_ASSERTED_IDENTITY', 'S-1-18-2':'SERVICE_ASSERTED_IDENTITY', 'S-1-18-3':'FRESH_PUBLIC_KEY_IDENTITY', 'S-1-18-4':'KEY_TRUST_IDENTITY', 'S-1-18-5':'KEY_PROPERTY_MFA', 'S-1-18-6':'KEY_PROPERTY_ATTESTATION', 'S-1-5-1000':'OTHER_ORGANIZATION', 'S-1-5-113':'LOCAL_ACCOUNT', 'S-1-5-114':'LOCAL_ACCOUNT_AND_MEMBER_OF_ADMINISTRATORS_GROUP', 'S-1-5-32-544':'Administrators', 'S-1-5-32-545':'Users', 'S-1-5-32-546':'Guests', 'S-1-5-32-547':'Power Users', 'S-1-5-32-548':'Account Operators', 'S-1-5-32-549':'Server Operators', 'S-1-5-32-550':'Print Operators', 'S-1-5-32-551':'Backup Operators', 'S-1-5-32-552':'Replicators', 'S-1-5-32-554':r'Builtin\Pre-Windows 2000 Compatible Access', 'S-1-5-32-555':r'Builtin\Remote Desktop Users', 'S-1-5-32-556':r'Builtin\Network Configuration Operators', 'S-1-5-32-557':r'Builtin\Incoming Forest Trust Builders', 'S-1-5-32-558':r'Builtin\Performance Monitor Users', 'S-1-5-32-559':r'Builtin\Performance Log Users', 'S-1-5-32-560':r'Builtin\Windows Authorization Access Group', 'S-1-5-32-561':r'Builtin\Terminal Server License Servers', 'S-1-5-32-562':r'Builtin\Distributed COM Users', 'S-1-5-32-568':'IIS_IUSRS', 'S-1-5-32-569':r'Builtin\Cryptographic Operators', 'S-1-5-32-573':r'Builtin\Event Log Readers', 'S-1-5-32-574':r'Builtin\Certificate Service DCOM Access', 'S-1-5-32-575':r'Builtin\RDS Remote Access Servers', 'S-1-5-32-576':r'Builtin\RDS Endpoint Servers', 'S-1-5-32-577':r'Builtin\RDS Management Servers', 'S-1-5-32-578':r'Builtin\Hyper-V Administrators', 'S-1-5-32-579':r'Builtin\Access Control Assistance Operators', 'S-1-5-32-580':r'Builtin\Remote Management Users', 'S-1-5-32-582':'Storage Replica Administrators', 'S-1-5-33':'WRITE_RESTRICTED_CODE', 'S-1-5-64-10':'NTLM Authentication', 'S-1-5-64-14':'SChannel Authentication', 'S-1-5-64-21':'Digest Authentication', 'S-1-5-65-1':'THIS_ORGANIZATION_CERTIFICATE', 'S-1-5-80':'NT Service', 'S-1-5-80-0':r'NT Services\All Services', 'S-1-5-80-0':'All Services', 'S-1-5-83-0':r'NT Virtual Machine\Virtual Machines', 'S-1-5-84-0-0-0-0-0':'USER_MODE_DRIVERS', 'S-1-5-90-0':r'Windows Manager\Windows Manager Group'}
dictAllGroups = {**dictNormalGroups, **dictDomainGroups, **dictBuiltinGroups}
## There are also "meta group id's": https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-dtyp/81d92bba-d22b-4a8c-908a-554ab29148ab

def checkParameters(options, args):
    if options.live:
        for x in ['SYSTEM', 'SECURITY', 'SOFTWARE', 'SAM']: os.system(r'REG.EXE SAVE HKLM\{} {} /Y >nul 2>&1'.format(x,x))
        sSOFTWAREhive = 'SOFTWARE'
        sSECURITYhive = 'SECURITY'
        sSYSTEMhive = 'SYSTEM'
        sSAMhive = 'SAM'
    elif len(args) == 4:
        sSOFTWAREhive = args[0]
        sSECURITYhive = args[1]
        sSYSTEMhive = args[2]
        sSAMhive = args[3]
    else:
        sSOFTWAREhive = os.path.join('Windows','System32','config','SOFTWARE')
        sSECURITYhive = os.path.join('Windows','System32','config','SECURITY')
        sSYSTEMhive = os.path.join('Windows','System32','config','SYSTEM')
        sSAMhive = os.path.join('Windows','System32','config','SAM')

    for x in [sSOFTWAREhive, sSECURITYhive, sSYSTEMhive, sSAMhive]: 
        if not os.path.exists(x): exit(f'Error finding file "{x}"')

    return (sSOFTWAREhive, sSECURITYhive, sSYSTEMhive, sSAMhive)

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def getLsaSecretVal(sValue, sSYSTEMhive, sSECURITYhive):
    oDpaReg = dpareg.Regedit()
    return oDpaReg.get_lsa_secrets(sSECURITYhive, sSYSTEMhive).get(sValue)

def getBootKey(sSYSTEMhive):
    ## Permutation matrix for boot key
    mP = [8, 5, 4, 2, 11, 9, 13, 3, 0, 6, 1, 12, 14, 10, 15, 7]
    oSysReg = Registry(sSYSTEMhive)
    sSource = ''
    for x in ['JD', 'Skew1', 'GBG', 'Data']: sSource += oSysReg.open(f'ControlSet001\\Control\\Lsa\\{x}')._nkrecord.classname()
    bSource = bytes.fromhex(sSource)
    sBootKey = ''
    for i in range(len(bSource)): sBootKey += hex(bSource[mP[i]])[2:].zfill(2)
    return bytes.fromhex(sBootKey)

def getNLKM(sSYSTEMhive, sSECURITYhive, boolVerbose = True): ## Can be used to determine install date
    try: bNLKM = getLsaSecretVal('NL$KM', sSYSTEMhive, sSECURITYhive)['CurrVal']
    except TypeError: return
    sInstallDateTime = datetime.datetime.fromtimestamp(int(getLsaSecretVal('NL$KM', sSYSTEMhive, sSECURITYhive)['OupdTime']))
    if boolVerbose: print('[+] System installed : {}'.format(sInstallDateTime))
    ## This is commented out untill I know of an external use for this beyond decrypting domain hashes
    #if boolVerbose: print('[+] NL$KM : {}'.format(bNLKM.hex()))
    return

def getMachineAccHash(sSYSTEMhive, sSECURITYhive, boolVerbose = True): ## Can be used to determine domain join date
    try: 
        sDomainJoinDateTime = datetime.datetime.fromtimestamp(int(getLsaSecretVal('$MACHINE.ACC', sSYSTEMhive, sSECURITYhive)['OupdTime']))
        bClearPass = getLsaSecretVal('$MACHINE.ACC', sSYSTEMhive, sSECURITYhive)['CurrVal']
        sNTHash = hashlibnew('md4',bClearPass).hexdigest()
        if boolVerbose: print('    $MACHINE.ACC     : aad3b435b51404eeaad3b435b51404ee:{}'.format(sNTHash))
        return sNTHash
    except: 
        return None

def getDPAPISecrets(sSYSTEMhive, sSECURITYhive, boolVerbose = True):
    bDPAPIFull = getLsaSecretVal('DPAPI_SYSTEM', sSYSTEMhive, sSECURITYhive)['CurrVal']
    sMachineKey = bDPAPIFull[4:4+20].hex()
    sUserKey = bDPAPIFull[24:24+20].hex()
    if boolVerbose: 
        print('[+] DPAPI keys found:')
        print('    Machine Key : {}'.format(sMachineKey))
        print('    User Key    : {}'.format(sUserKey))
    return

def getDomainHashes(sSYSTEMhive, sSECURITYhive, boolVerbose = True):
    def parseRegValue(bRegValue):
        iLengthUname = int(reverseByte(bRegValue[:2]).hex(), 16)
        iLengthDomain = int(reverseByte(bRegValue[2:4]).hex(), 16)
        iLengthDomainName = int(reverseByte(bRegValue[60:60+2]).hex(), 16)
        bIV = bRegValue[64:64+16]
        bEncrCache = bRegValue[96:] + ((16-len(bRegValue[96:])%16) * b'\x00') ## Add padding to have a plural of 16 bytes
        return (iLengthUname, iLengthDomain, iLengthDomainName, bIV, bEncrCache)
    def parseDomHash(bClearData):
        sClearHash = bClearData[:16].hex()
        sUsername = bClearData[72:72+iLengthUname].decode('UTF-16LE')
        iOffsetDomain = 72+iLengthUname + (72+iLengthUname)%4
        sDomain = bClearData[iOffsetDomain:iOffsetDomain+iLengthDomain].decode('UTF-16LE')
        iOffsetDomainName = iOffsetDomain+iLengthDomain + (iOffsetDomain+iLengthDomain)%4
        sDomainName = bClearData[iOffsetDomainName:iOffsetDomainName+iLengthDomainName].decode('UTF-16LE')
        return (sClearHash, sUsername, sDomain, sDomainName)
    try: bNLKMKey = getLsaSecretVal('NL$KM', sSYSTEMhive, sSECURITYhive)['CurrVal']
    except TypeError: return []
    oReg = Registry(sSECURITYhive)
    oKey = oReg.open(r'Cache')
    lstDomHashes = []
    for oValue in oKey.values():
        if oValue.name() == 'NL$Control': continue
        if len(oValue.value()) == 0: continue
        if b'\x00\x04\x00\x01' in oValue.value(): continue
        (iLengthUname, iLengthDomain, iLengthDomainName, bIV, bEncrCache) = parseRegValue(oValue.value())
        oCipher = AES.new(bNLKMKey[:16], AES.MODE_CBC, bIV)
        bDecrData = b''
        for i in range(0, len(bEncrCache), 16): bDecrData += oCipher.decrypt(bEncrCache[i:i+16])
        lstDomHashes.append(parseDomHash(bDecrData))
    if boolVerbose and len(lstDomHashes) > 0: print('[+] Listing {} domain users'.format(len(lstDomHashes)))
    elif boolVerbose: print('[-] None were found')
    if boolVerbose: 
        for lstDomHash in lstDomHashes: ## sHash, sUsername, sDomain, sDomainName
            ## Hashcat format: $DCC2$10240#administrator#ca1d9556a194e25e31c431238dea264b
            print('    Domain {}  : $DCC2$10240#{}#{}'.format(lstDomHash[3].lower(), lstDomHash[1].lower(), lstDomHash[0].lower()))

    return lstDomHashes

def doTBALDecrypt(sSECURITYhive, sSYSTEMhive, boolVerbose = False):
    def parseLocalTBAL(bData):
        bRemainder = bData[4:] ## First 4 bytes UNK
        iFullDataLen = int(reverseByte(bRemainder[:4]).hex(), 16)
        if not iFullDataLen == len(bData): print('    Probably not a correct TBAL entry')
        sFlags = reverseByte(bRemainder[4:4+4]) ## Followed by 4 bytes UNK
        bRemainder = bRemainder[12:]
        bNTLM = bRemainder[:16]
        bLM = bRemainder[16:16+16]
        bSHA1 = bRemainder[16+16:16+16+20]
        bDPAPI = bRemainder[16+16+20:16+16+20+20]
        bRemainder = bRemainder[16+16+20+20:]
        iDomainPtr = int(reverseByte(bRemainder[:4]).hex(), 16)
        iDomainLength = int(reverseByte(bRemainder[4:4+2]).hex(), 16)
        iDomainBuffersize = int(reverseByte(bRemainder[4+2:4+2+2]).hex(), 16)
        bRemainder = bRemainder[4+2+2:]
        iUserPtr = int(reverseByte(bRemainder[:4]).hex(), 16)
        iUserLength = int(reverseByte(bRemainder[4:4+2]).hex(), 16)
        iUserBuffersize = int(reverseByte(bRemainder[4+2:4+2+2]).hex(), 16)
        sDomain = bData[iDomainPtr:iDomainPtr+iDomainLength].decode('UTF-16LE')
        sUser = bData[iUserPtr:iUserPtr+iUserLength].decode('UTF-16LE')
        print(r'[+] User {}\{} has NT hash : {} and SHA1 hash : {}'.format(sDomain, sUser, bNTLM.hex(), bSHA1.hex()))
        return
    oDpaReg = dpareg.Regedit()
    lstSecrets = oDpaReg.get_lsa_secrets(sSECURITYhive, sSYSTEMhive)
    for lstSecret in lstSecrets:
        if 'TBAL' in lstSecret:
            if 'MSV1' in lstSecret: 
                parseLocalTBAL(lstSecrets[lstSecret]['CurrVal'])
            else:
                print('    {}'.format(lstSecret))
                print('    {}'.format(lstSecrets[lstSecret]['CurrVal'].hex()))
    ## TODO: lstSecret can be "M$_MSV1_0_TBAL_PRIMARY_{22BE8E5B-58B3-4A87-BA71-41B0ECF3A9EA}" which is a local account and holds SHA1 & NT password hash (example: 0300ffff9a00000005000000000000003dbde697d71690a769204beb12283678000000000000000000000000000000000d5399508427ce79556cda71918020c1e8d15b53000000000000000000000000000000000000000070000000020020009000000008000a009a000000000000002e000000000000004e746c6d4372656449736f496e50726f633a3a4973474d5355007300650072000000)
    ##        or it can be "M$_CLOUDAP_TBAL_{8283D8D4-55B6-466F-B7D7-17A1352D9CAB}_<UID>" (Win10 <b1607) where <UID> is the SHA256 hash of the User ID and holds 96 byte DPAPI key
    ##        or it can be "M$_CLOUDAP_TBAL_{4416F0BD-3A59-4590-9579-DA6E08AF19B3}_<UID>" (Win10 >=b1703) where <UID> is the SHA256 hash of the User ID and holds 96 byte DPAPI key
    return

def getAutoLoginCreds(sSOFTWAREhive, sSYSTEMhive, sSECURITYhive, boolVerbose = True):
    oReg = Registry(sSOFTWAREhive)
    oKey = oReg.open(r'Microsoft\Windows NT\CurrentVersion\Winlogon')
    sUsername = sDomain = sPassword = sSetDate = None
    for oValue in oKey.values():
        sUsername = oValue.value() if oValue.name().lower() == 'defaultusername' else sUsername
        sDomain = oValue.value() if oValue.name().lower() == 'defaultdomainname' else sDomain
        sPassword = oValue.value() if oValue.name().lower() == 'defaultpassword' else sPassword
    if sUsername: 
        if not sPassword:
            try: 
                sPassword = getLsaSecretVal('DefaultPassword', sSYSTEMhive, sSECURITYhive)['CurrVal'].decode('UTF-16LE')
                sSetDate = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(getLsaSecretVal('DefaultPassword', sSYSTEMhive, sSECURITYhive)['CupdTime']))
            except: print('[-] No decryptable password found, try checking lsasecrets manually')
        if sPassword:
            print('[+] Windows autologin found')
            print(f'    Username : {sUsername}')
            print(f'    Domain   : {sDomain}') if sDomain else None
            print(f'    Password : {sPassword}') if sPassword else None
            print(f'    Set on   : {sSetDate}') if sSetDate else None
            if 'TBAL' in sPassword: 
                print('[!] Warning: Automatic Restart Sign-On (ARSO) detected, running additional decryption:')
                doTBALDecrypt(sSECURITYhive, sSYSTEMhive, boolVerbose)
        else: print('[-] No credentials found')
    else: print('[-] No credentials found')
    return

def getServiceCreds(sSOFTWAREhive, sSYSTEMhive, sSECURITYhive, sRegService = True, boolVerbose = False):
    def getServiceDetails(sSystem, sName):
        oSysReg = Registry(sSystem)
        sBinary = oSysReg.open(rf'ControlSet001\Services\{sName}').value('ImagePath').value()
        sDisplayname = oSysReg.open(rf'ControlSet001\Services\{sName}').value('DisplayName').value()
        sUsername = oSysReg.open(rf'ControlSet001\Services\{sName}').value('ObjectName').value()
        print(f'    Name     : {sDisplayname} ({sBinary})')
        print(f'    User     : {sUsername}')
        return
    def getComServiceDetails(sSoftware, sServiceID):
        oSoftReg = Registry(sSoftware)
        sDisplayname = oSoftReg.open(rf'Classes\AppID\{sServiceID}').values()[0].value()
        sUsername = oSoftReg.open(rf'Classes\AppID\{sServiceID}').value('RunAs').value()
        print(f'    Name     : {sDisplayname}')
        print(f'    User     : {sUsername}')
        return
    oSecReg = Registry(sSECURITYhive)
    oKey = oSecReg.open(r'Policy\Secrets')
    sKeyname = None
    iCount = 0
    for oSubkey in oKey.subkeys():
        if sRegService and oSubkey.name()[:4] == '_SC_': 
            iCount += 1
            print(f'[+] Found Service credential ({iCount})')
            sKeyname = oSubkey.name()[4:]
            sPassword = getLsaSecretVal(oSubkey.name(), sSYSTEMhive, sSECURITYhive)['CurrVal'].decode('UTF-16LE')
            sSetDate = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(getLsaSecretVal(oSubkey.name(), sSYSTEMhive, sSECURITYhive)['CupdTime']))
            print(f'    Service  : {sKeyname}')
            print(f'    Set on   : {sSetDate}')
            try: getServiceDetails(sSYSTEMhive, sKeyname)
            except: pass
            print(f'    Password : {sPassword}')
        if not sRegService and oSubkey.name()[:5] == 'SCM:{': 
            iCount += 1
            print(f'[+] Found Component Service credential ({iCount})')
            sServiceID = oSubkey.name()[4:]
            sPassword = getLsaSecretVal(oSubkey.name(), sSYSTEMhive, sSECURITYhive)['CurrVal'].decode('UTF-16LE')
            sSetDate = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(getLsaSecretVal(oSubkey.name(), sSYSTEMhive, sSECURITYhive)['CupdTime']))
            print(f'    Service  : {sServiceID}')
            print(f'    Set on   : {sSetDate}')
            try: getComServiceDetails(sSOFTWAREhive, sServiceID)
            except: pass
            print(f'    Password : {sPassword}')
    if iCount == 0: print('[-] None were found')
    return

def getHostname(sSYSTEM, boolVerbose = False):
    oSysReg = Registry(sSYSTEM)
    ## Alternative: sHostname = oSoftReg.open(r'Microsoft\Windows\CurrentVersion\Group Policy\DataStore\Machine\0').value('szTargetName').value()
    sHostname = oSysReg.open(r'ControlSet001\Control\ComputerName\ComputerName').value('ComputerName').value()
    if boolVerbose: print(f'[+] Hostname         : {sHostname}')
    return sHostname

def getSystemDetails(sSOFTWAREhive, boolVerbose = False):
    oSoftReg = Registry(sSOFTWAREhive)
    sProductName = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('ProductName').value()
    sBuildName = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('BuildLab').value()
    sBuildNr = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('CurrentBuild').value()
    try: sOSVersion = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('DisplayVersion').value()
    except: sOSVersion = ''
    sOwner = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('RegisteredOwner').value()
    try: 
        sOrg = oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('RegisteredOrganization').value()
        sFeatureUpdateInstallDate = datetime.datetime.fromtimestamp(int(oSoftReg.open(r'Microsoft\Windows NT\CurrentVersion').value('InstallDate').value()))
    except: pass
    if boolVerbose: 
        print(f'[+] OS Details       : {sProductName}; v{sOSVersion}; {sBuildName} (Build {sBuildNr})')
        print(f'                       Owner: {sOwner}')
    return

def getLocalUsers(sSOFTWARE, sSAM, boolMembership = True, boolVerbose = False):
    if boolVerbose: print('[+] Listing Local users')
    def getLocalGroupMembership(sSOFTWARE, sSID, sDomainSID, boolVerbose = False):
        oReg = Registry(sSOFTWARE)
        lstGroups = []
        try: oKey = oReg.open(rf'Microsoft\Windows\CurrentVersion\Group Policy\{sSID}')
        except: return lstGroups
        for oValue in oKey.subkey('GroupMembership').values():
            if oValue.name() == 'Count': continue
            sGroupID = oValue.value()
            if sGroupID[:8] == 'S-1-5-21': sGroupID = sGroupID.split('-')[len(sGroupID.split('-'))-1]
            try: sGroup = dictAllGroups[sGroupID]
            except: sGroup = oValue.value()
            lstGroups.append((oValue.value(),sGroup))
            if boolVerbose: print(f'      Member of: {sGroup}')
        return lstGroups
    oSamReg = Registry(sSAM)
    sSystemSID = ''
    lstUsers = []
    for oSubKey in oSamReg.open(r'SAM\Domains\Builtin\Aliases\Members').subkeys(): 
        if oSubKey.name().startswith('S-1-5-21'): 
            sSystemSID = oSubKey.name()
            break
    sDomainSID = '-'.join((sSystemSID.split('-')[4], sSystemSID.split('-')[5], sSystemSID.split('-')[6]))
    for oSubKey in oSamReg.open(r'SAM\Domains\Account\Users\Names').subkeys(): 
        iRID = int(oSubKey.value('(default)').value_type())
        sSID = f'{sSystemSID}-{iRID}'
        sUsername = oSubKey.name()
        sHexUserID = hex(iRID)[2:].zfill(8).upper()
        bEncrHash = oSamReg.open(rf'SAM\Domains\Account\Users\{sHexUserID}').value('V').value()
        if boolVerbose: print('    {0:25}  SID: {1:50}'.format(sUsername, sSID))
        if boolMembership and iRID <= 1000:
            lstGroups = getLocalGroupMembership(sSOFTWARE, sSID, sDomainSID, boolVerbose)
            lstUsers.append((sSID, sUsername, bEncrHash, lstGroups))
        else:
            lstUsers.append((sSID, sUsername, bEncrHash))
    return lstUsers

def getRASCreds(sSYSTEMhive, sSECURITYhive, boolVerbose = False):
    oDpaReg = dpareg.Regedit()
    lstSecrets = oDpaReg.get_lsa_secrets(sSECURITYhive, sSYSTEMhive)
    lstRASObjects = []
    for lstSecret in lstSecrets:
        if 'Ras' in lstSecret:
            try: lstRASVals = lstSecrets[lstSecret]['CurrVal'].decode('UTF-16LE').split('\x00')
            except: continue
            if len(lstRASVals) == 11: 
                lstRASObjects.append(lstRASVals)
                if boolVerbose: 
                    print('[+]  Found some RAS Dial-Up data ( {} )'.format(lstSecret))
                    print('     {}'.format(lstRASVals))
    ## TODO, found examples to perfect the parsing, currently: lstRASVals seems to be UNK1, UNK2, UNK3 (probably type), UNK4 (probably domain name), UNK5, Account Name, DialUp Password, UNK6, UNK7, UNK8
    return lstRASObjects

def getMSAccounts(sSOFTWAREhive, boolVerbose = True):
    lstMSLiveAccounts = []
    oReg = Registry(sSOFTWAREhive)
    try: oKey = oReg.open(r'Microsoft\IdentityStore\LogonCache\D7F9888F-E3FC-49b0-9EA6-A85B5F392A4F\Name2Sid')
    except: 
        print('[-] None were found')
        return lstMSLiveAccounts
    for oSubKey in oKey.subkeys():
        sName = oSubKey.name()
        try: sDisplayName = oSubKey.value('DisplayName').value()
        except: sDisplayName = ''
        sIdentityName = oSubKey.value('IdentityName').value()
        sSID = oSubKey.value('Sid').value()
        lstMSLiveAccounts.append((sName, sDisplayName, sIdentityName, sSID))
    if len(lstMSLiveAccounts) > 0 and boolVerbose:
        print('[+] Live Account(s) found, use the Name below to get the DPAPI data from\n    Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAPCache\\MicrosoftAccount\\<ID>\\Cache')
    if boolVerbose:
        for user in lstMSLiveAccounts: print(f'    User     : Account {user[2]} ({user[1]}, {user[0]})')
    return lstMSLiveAccounts

def getAADAccounts(sSOFTWAREhive, boolVerbose = True):
    lstAADAccounts = []
    oReg = Registry(sSOFTWAREhive)
    try: oKey = oReg.open(r'Microsoft\IdentityStore\LogonCache\B16898C6-A148-4967-9171-64D755DA8520\Name2Sid')
    except: 
        print('[-] None were found')
        return lstAADAccounts
    for oSubKey in oKey.subkeys():
        sName = oSubKey.name()
        sDisplayName = oSubKey.value('DisplayName').value()
        sIdentityName = oSubKey.value('IdentityName').value()
        sSID = oSubKey.value('Sid').value()
        lstAADAccounts.append((sName, sDisplayName, sIdentityName, sSID))
    if len(lstAADAccounts) > 0 and boolVerbose:
        print('[+] Azure AD Account(s) found, use the Name below to get the DPAPI data from\n    Windows\\System32\\config\\systemprofile\\AppData\\Local\\Microsoft\\Windows\\CloudAPCache\\AzureAD\\<ID>\\Cache')
    if boolVerbose:
        for user in lstAADAccounts: print(f'    User     : {user[1]} with account {user[2]} has ID {user[0]}')
    if len(lstAADAccounts) == 0 and boolVerbose: print('[-] None were found')
    return lstAADAccounts

def getProductKeys(sSOFTWAREhive, boolVerbose = True):
    ## TODO: Get exact Windows version using a conversion of "PID Checker"
    ## Search for extra locations by running this on a live system: reg query HKLM /s /v "DigitalProductId"
    lstLocations = [
        r'Microsoft\Windows NT\CurrentVersion',
        r'Microsoft\Windows NT\CurrentVersion\DefaultProductKey',
        r'Microsoft\Windows NT\CurrentVersion\DefaultProductKey2',
        r'WOW6432Node\Cisco\Cisco AnyConnect Secure Mobility Client\DeviceDetails',
        r'Microsoft\Internet Explorer\Registration']

    def decodeProductKey(bSource):
        sKeymap = 'BCDFGHJKMPQRTVWXY2346789'
        bNewValue = (bSource[66] // 6) & 1 # Remove most significant byte from byte 66 div 6 (ignore remainder)
        bSource = bSource[:66] + bytes.fromhex(str(((bSource[66] & 0xF7) | ((bNewValue & 2) * 4))).zfill(2)) + bSource[67:] # Clearing 4th bit based on the bNewValue
        lstSource = []
        for i in range(52,67): lstSource.append(bSource[i]) ## Converting to array of integers, we only need 14 bytes at offset 52

        sKey = ''
        for i in range(24,-1,-1):
            iOffset = 0
            for j in range(14,-1,-1):
                iOffset = (iOffset * 256)
                iOffset = iOffset + lstSource[j]
                lstSource[j] = iOffset // 24
                iOffset %= 24
            sKey = sKeymap[iOffset] + sKey

        if bNewValue == 1: ## If this is new type of ProductKey, we need to add 'N' after 1+offset characters of the key
            sKey = sKey[:1+iOffset]+'N'+sKey[1+iOffset:]
            sKey = sKey[1:] ## And remove the first character (to get to 25 chars)
            if len(sKey) == 24: sKey = 'N' + sKey ## if we only have 24 chars, add 'N' to the beginning

        return sKey[:5] + "-" + sKey[5:10] + "-" + sKey[10:15] + "-" + sKey[15:20] + "-" + sKey[20:]
    
    def getKeyData(sLocation, lstProdKeys):
        oKey = oReg.open(sLocation)
        sProdKey = (decodeProductKey(oKey.value('DigitalProductId').value()), sLocation)
        if 'BBBBB-BBBBB-BBBBB-BBBBB-BBBBB' in sProdKey: return lstProdKeys
        if not any(sProdKey[0] in x for x in lstProdKeys): lstProdKeys.append(sProdKey)
        return lstProdKeys
    lstProdKeys = []
    oReg = Registry(sSOFTWAREhive)
    for sLocation in lstLocations:
        try: lstProdKeys = getKeyData(sLocation, lstProdKeys)
        except: pass
    if boolVerbose:
        for lstProdKey in lstProdKeys: print(r'    Key     : {} found at HKLM\SOFTWARE\{}'.format(lstProdKey[0], lstProdKey[1]))
    if len(lstProdKeys) == 0 and boolVerbose: print('[-] None were found in the default locations')
    elif boolVerbose: print(f'    Details : https://softcomputers.org/en/blog/online-pid-checker-microsoft-keys-at-valid-and-legality/')
    return lstProdKeys

def getSecretQuestions(sSAMhive, boolVerbose = False):
    if boolVerbose: print('[+] Finding Secret Questions')
    oReg = Registry(sSAMhive)
    oKey = oReg.open(r'SAM\Domains\Account\Users')
    dictUsers = {}
    for oSubKey in oKey.subkey('Names').subkeys():
        sName = oSubKey.name()
        sRID = str(oSubKey.value('(default)').value_type())
        dictUsers[sRID] = sName
        #if boolVerbose: print(f'[+] User {sName} has RID {sRID}')
    lstQuestions = None
    for oSubKey in oKey.subkeys():
        if oSubKey.name() == 'Names': continue
        sRID = str(int(oSubKey.name(), 16))
        try:
            bSecretData = oSubKey.value('ResetData').value()
            sUsername = dictUsers[sRID]
            if len(bSecretData) == 56: continue ## This user has no secret questions
            else:
                bJsonQuestions = bSecretData.decode('UTF-16LE')
                lstQuestionTemp = bJsonQuestions.split('"question":"')
                lstAnswerTemp = bJsonQuestions.split('"answer":"')
                lstQuestions = []
                for i in range (1,len(lstQuestionTemp)):
                    sQuestion = lstQuestionTemp[i].split('"')[0]
                    sAnswer = lstAnswerTemp[i].split('"')[0]
                    lstQuestions.append((sQuestion, sAnswer))
                    if boolVerbose: print(f'    User {sUsername}; question {i}: {sQuestion}  -  {sAnswer}')
        except: continue
    if lstQuestions is None: print('[-] None were found')
    return

def getLocalHashes(sSYSTEMhive, sSAMhive, lstUsers, boolVerbose = True):
    def getDESKeys(bUserSID):
        def doDesBitCals(bDesSrc):
            mBitCalc = [1, 3, 7, 15, 31, 63]
            bDesDst = []
            bDesDst.append(bDesSrc[0]>>1)
            for i in range(len(mBitCalc)): bDesDst.append(((bDesSrc[i] & mBitCalc[i]) << (6-i)) | bDesSrc[1+i] >> (2+i))
            bDesDst.append(bDesSrc[6]&0x7F)
            sResult = ''
            for x in bDesDst: 
                sBinary = bin(x*2)[2:].zfill(8)
                if sBinary.count('1')%2 == 0: sResult += hex((x * 2) ^ 1)[2:].zfill(2)
                else: sResult += hex(x * 2)[2:].zfill(2)
            return sResult
        ## Permutation matrix for des keys
        mDes1 = [0, 1, 2, 3, 0, 1, 2]
        mDes2 = [3, 0, 1, 2, 3, 0, 1]
        sDesSource1 = sDesSource2 = ''
        for i in range(len(mDes1)): sDesSource1 += hex(bUserSID[mDes1[i]])[2:].zfill(2)
        for i in range(len(mDes2)): sDesSource2 += hex(bUserSID[mDes2[i]])[2:].zfill(2)
        bDesSrc1 = bytes.fromhex(sDesSource1)
        bDesSrc2 = bytes.fromhex(sDesSource2)
        bDesKey1 = bytes.fromhex(doDesBitCals(bDesSrc1))
        bDesKey2 = bytes.fromhex(doDesBitCals(bDesSrc2))
        return bDesKey1, bDesKey2
    bBootKey = getBootKey(sSYSTEMhive)
    if boolVerbose: print(f'[+] Bootkey  : {bBootKey.hex()}')
    oSysReg = Registry(sSAMhive)
    ## Decrypt SysKey using the BootKey
    bRegSys = oSysReg.open(r'SAM\Domains\Account').value('F').value()
    if bRegSys[0] == 3: ## v03 means AES encrypted
        bIV = bRegSys[0x78:0x78+16]
        bEncSysKey = bRegSys[0x88:0x88+16]
        bSysKey = AES.new(bBootKey, AES.MODE_CBC, bIV).decrypt(bEncSysKey)
    else: 
        bEncSysKey = bRegSys[0x80:0x80+16]
        bPart1 = bRegSys[0x70:0x70+16]
        bQwerty = b'!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00'
        bDigits = b'0123456789012345678901234567890123456789\x00'
        bRC4Key = md5(bPart1 + bQwerty + bBootKey + bDigits).digest()
        bSysKey = ARC4.new(bRC4Key).decrypt(bEncSysKey)
    if boolVerbose: print('[+] Listing {} users with hashes'.format(len(lstUsers)))
    ## Decrypt hashes, based on the present users
    for lstUser in lstUsers:
        ## Precalc on Registry V value
        sSID = hex(int(lstUser[0].split('-')[-1]))[2:].zfill(8)
        sUserSID = ''.join(map(str.__add__, sSID[-2::-2], sSID[-1::-2]))  ## sUserSID == f4010000
        bDesKey1, bDesKey2 = getDESKeys(bytes.fromhex(sUserSID))
        ## Works, but not always (e.g. DefaultAccount does not work)
        # sUsername = bRegVHash[0xCC+bRegVHash[0xc]:0xCC+bRegVHash[0xc]+bRegVHash[0x10]].decode('UTF-16LE')
        sUsername = lstUser[1]
        bRegVHash = lstUser[2]
        sEmptyLM = 'aad3b435b51404eeaad3b435b51404ee'
        sEmptyNTLM = '31d6cfe0d16ae931b73c59d7e0c089c0'
        ## Note: method aided by https://github.com/MrMcX/diana
        dctResultHashes = {}
        for sHashName, iHashOffsetMult in {'LM': 13, 'NTLM': 14, 'LM_hist': 15, 'NTLM_hist': 16}.items():
            iHashOffset = iHashOffsetMult*0x0c
            bOffset = bRegVHash[iHashOffset:iHashOffset+4]
            sOffset = ''.join(map(str.__add__, bOffset.hex()[-2::-2], bOffset.hex()[-1::-2])) ## Convert endianness
            iOffset = 0xCC + int(sOffset, 16)
            bLength = bRegVHash[iHashOffset+4:iHashOffset+8]
            sLength = ''.join(map(str.__add__, bLength.hex()[-2::-2], bLength.hex()[-1::-2]))
            iLength = int(sLength, 16)  ## Length 0x38 == AES, Length 0x14 == RC4, anything else is "no password"
            ## Decrypt double encrypted hash (AES or RC4)
            if iLength == 0x38: ## AES encryption
                bDoubleEncHash = bRegVHash[24+iOffset:24+iOffset+16]
                bIV = bRegVHash[8+iOffset:8+iOffset+16]
                bEncHash = AES.new(bSysKey, AES.MODE_CBC, bIV).decrypt(bDoubleEncHash)
            elif iLength == 0x14: ## RC4 encryption
                bDoubleEncHash = bRegVHash[4+iOffset:4+iOffset+16]
                bHashRC4Key = md5(bSysKey+bytes.fromhex(sUserSID)+b'NTPASSWORD\x00').digest()
                bEncHash = ARC4.new(bHashRC4Key).decrypt(bDoubleEncHash)
            else: bEncHash = b'' ## User has no password
            ## Decrypt encrypted hash (in all cases DES encryption)
            if not bEncHash: sNTHash = sEmptyNTLM if 'NT' in sHashName else sEmptyLM
            else: sNTHash = DES.new(bDesKey1, DES.MODE_ECB).decrypt(bEncHash[:8]).hex() + DES.new(bDesKey2, DES.MODE_ECB).decrypt(bEncHash[8:]).hex()
            dctResultHashes[sHashName] = sNTHash
        print(f'     {sUsername} : {dctResultHashes["LM"]}:{dctResultHashes["NTLM"]}')
        if dctResultHashes['LM_hist'] != sEmptyLM or dctResultHashes['NTLM_hist'] != sEmptyNTLM:
            print(f'      PREVIOUS HASH : {dctResultHashes["LM_hist"]}:{dctResultHashes["NTLM_hist"]}')
    return

if __name__ == '__main__':
    sUsage = (
        'usage: %prog [SOFTWARE] [SECURITY] [SYSTEM] [SAM]\n\n'
        'Parsing and printing out secrets from the system registry hives.\n'
        '  Without parameters, the script assumes to be in the root of the backup\n')

    parser = optparse.OptionParser(usage=sUsage)
    parser.add_option('--live', action = 'store_true', default = False, dest='live', help='Perform REG SAVE to local folder first, run as Administrator')
    parser.add_option('--membership', action = 'store_true', default = False, help='List Local User Membership, default disabled')
    
    (options, args) = parser.parse_args()

    (sSOFTWAREhive, sSECURITYhive, sSYSTEMhive, sSAMhive) = checkParameters(options, args)

    print(r'--## This script requires the files Windows\System32\config\{SAM|SOFTWARE\SYSTEM|SECURITY} ##--')
    print('                              Built upon DPAPick3\n')

    print('---- [00] General Information ----')
    getHostname(sSYSTEMhive, True)
    getSystemDetails(sSOFTWAREhive, True)
    try: getNLKM(sSYSTEMhive, sSECURITYhive, True) ## Added try-catch for Windows7
    except: pass
    getMachineAccHash(sSYSTEMhive, sSECURITYhive, True)
    lstUsers = getLocalUsers(sSOFTWAREhive, sSAMhive, options.membership, True)
    getSecretQuestions(sSAMhive, True)
    #getDPAPISecrets(sSYSTEMhive, sSECURITYhive, True)

    print('\n---- [01] Dump Local User Hashes ----')
    getLocalHashes(sSYSTEMhive, sSAMhive, lstUsers)

    print('\n---- [02] Dump Domain Cached Hashes (if any) ----')
    try: getDomainHashes(sSYSTEMhive, sSECURITYhive, boolVerbose = True) ## Added try-catch for Windows7
    except: pass

    print('\n---- [03] List MS Live Accounts (if any) ----')
    getMSAccounts(sSOFTWAREhive)

    print('\n---- [04] List Azure AD Accounts (if any) ----')
    getAADAccounts(sSOFTWAREhive)
    
    print('\n---- [05] Default Windows Login (if any) ----')
    getAutoLoginCreds(sSOFTWAREhive, sSYSTEMhive, sSECURITYhive)
    
    print('\n---- [06] Regular Service Creds (if any) ----')
    getServiceCreds(sSOFTWAREhive, sSYSTEMhive, sSECURITYhive, True, True)
    
    print('\n---- [07] Component Service Creds (if any) ----')
    getServiceCreds(sSOFTWAREhive, sSYSTEMhive, sSECURITYhive, False, True)

    print('\n---- [08] Some distinct product keys ----')
    getProductKeys(sSOFTWAREhive, boolVerbose = True)

    #print('\n--- Extra\'s')
    #getRASCreds(sSYSTEMhive, sSECURITYhive, True)

    #if options.live: os.system('DEL SOFTWARE SECURITY SYSTEM SAM')
