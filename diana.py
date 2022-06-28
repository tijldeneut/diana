#!/usr/bin/python3
# -*- coding: utf-8 -*-
#
# Copyright 2022, Tijl "Photubias" Deneut @tijldeneut
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
sVersion = '1.0.0'
sBanner = (''' _______   ______   ______   __    __   ______  
/       \ /      | /      \ /  \  /  | /      \ 
$$$$$$$  |$$$$$$/ /$$$$$$  |$$  \ $$ |/$$$$$$  |
$$ |  $$ |  $$ |  $$ |__$$ |$$$  \$$ |$$ |__$$ |
$$ |  $$ |  $$ |  $$    $$ |$$$$  $$ |$$    $$ |
$$ |  $$ |  $$ |  $$$$$$$$ |$$ $$ $$ |$$$$$$$$ |
$$ |__$$ | _$$ |_ $$ |  $$ |$$ |$$$$ |$$ |  $$ |
$$    $$/ / $$   |$$ |  $$ |$$ | $$$ |$$ |  $$ |
$$$$$$$/  $$$$$$/ $$/   $$/ $$/   $$/ $$/   $$/''')
## DPAPI Investigation And Necessary Artifacts

lstGeneralScripts = [
    ['registrydec','GENERAL Registry Information Parser and decrypt'],
    ['cookieinjector','INJECT decrypted cookies (browserdec) into a temporary Firefox profile']
]

lstDPAPILabScripts = [
    ['dpapimkdec','Decrypt DPAPI MasterKeys, both SYSTEM and USER based'],
    ['dpapiblobdec','Decrypt DPAPI blob files, both SYSTEM and USER based'],
    ['credhistdec','Decrypt DPAPI USER CREDHIST files']
]

lstDPAPIAppScripts = [
    ['creddec','Decrypt credentials in CREDENTIAL files, both SYSTEM and USER based'],
    ['vaultdec','Decrypt secrets in VAULT vcrd files, both SYSTEM and USER based'],
    ['browserdec','Decrypt passwords and cookies from all Chromium based browsers (Chrome, Edge, Opera ...)'],
    ['keepassdec','Decrypt Keepass ProtectedUserKey.bin key, use key with CQDPAPIKeePassDBDecryptor.exe to decrypt some KDBX files'],
    ['mobaxtermdec','Decrypt MobaXterm sessions, without needing the master password'],
    ['msoutlookdec','Decrypt MS Outlook accounts from registry, IMAP accounts only'],
    ['msrdcmandec','Decrypt Microsoft Remote Desktop Connection Manager sessions'],
    ['openvpndec','Decrypt OpenVPN saved Private Key passphrases'],
    ['rsadec','Decrypt Encrypted RSA certificates, e.g. for reading EFS volumes'],
    ['wifidec','Decrypt Windows Wi-Fi profiles, including passwords, SYSTEM based'],
    ['wifipeapdec','Decrypt Windows Wi-Fi Enterprise profiles, requires SYSTEM & USER data'],
    ['workstationdec','Decrypt VMware Workstation vSphere login credentials']
]

lstDPAPINGScripts = [
    ['ngcparse','Parse the NGC folder, general starting point'],
    ['ngccryptokeysdec','Decrypt RSA private keys behind Windows HELLO PIN. Includes Brute Forcing the PIN'],
    ['ngcvaultdec','Decrypt the NGC specific data from VAULT vcrd files'],
    ['ngcpinpassdec','Meta-script to call other DPAPI-NG scripts and perform automatic PIN and password decryption'],
    ['ngcregistryparse','Parse the NGC data from registry instead of NGC folder, if present']
]

lstCloudScripts = [
    ['cloudprtdec','Decrypt Azure AD Request Tokens for re-use on other systems (e.g. ROADtools)'],
    ['msaccountdec','Decrypt MS Account CacheData to get DPAPI password, requires cleartext password']
]

lstAppScripts = [
    ['devrdmdec','Decrypt Devolutions Remote Desktop Manager DB files'],
    ['mremotedec','Decrypt passwords from mRemote confCons.xml file, requires master password if any'],
    ['winscpdec','Decrypt WinSCP stored sessions from NTUSER registry']
]

if __name__ == '__main__':
    print(f'{sBanner}\nBy Photubias (@tijldeneut)\nVersion: {sVersion}')
    print('###### DIANA SCRIPT LIBRARY OVERVIEW ######')
    
    print('\n----- GENERAL SCRIPTS -----')
    for lstScript in lstGeneralScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))

    print('\n----- DPAPI LAB SCRIPTS -----')
    for lstScript in lstDPAPILabScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))

    print('\n----- DPAPI APP SCRIPTS -----')
    for lstScript in lstDPAPIAppScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))

    print('\n----- DPAPI-NG SCRIPTS -----')
    for lstScript in lstDPAPINGScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))

    print('\n----- DPAPI CLOUD SCRIPTS -----')
    for lstScript in lstCloudScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))

    print('\n----- Other APP SCRIPTS -----')
    for lstScript in lstAppScripts: print('* diana-{0:30} : {1:50}'.format(lstScript[0]+'.py',lstScript[1]))
