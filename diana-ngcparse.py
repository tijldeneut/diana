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

import optparse, os, sys, time

def check_parameters(options, args):
    if not args or len(args) != 1:
        sys.exit('You must provide an NGC folder.')

def reverseByte(bByteInput):
    sReversed = ''
    sHexInput = bByteInput.hex()
    for x in range(-1, -len(str(sHexInput)), -2): sReversed += sHexInput[x-1] + sHexInput[x]
    return bytes.fromhex(sReversed)

def parseTimestamp(bData):
    iTimestamp = int(reverseByte(bData).hex(), 16)
    return time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(iTimestamp / 10000000 - 11644473600))

def parseProtectors(sPath, boolVerbose = False):
    arrProtectors = []
    for protector in os.listdir(sPath):
        ## name, provider, keyname, timestamp, data
        arrProtector = []
        arrProtector.append(protector)
        with open(os.path.join(sPath, protector, '1.dat'), 'rb') as f: arrProtector.append(f.read().decode('utf16').strip('\x00'))
        try:
            with open(os.path.join(sPath, protector, '2.dat'), 'rb') as f: arrProtector.append(f.read().decode('utf16').strip('\x00'))
        except:
            arrProtector.append('')
            print('[-] Protector "' + protector + '" is probably being stored in the TPM chip.')
        with open(os.path.join(sPath, protector, '9.dat'), 'rb') as f: arrProtector.append(parseTimestamp(f.read()))
        with open(os.path.join(sPath, protector, '15.dat'), 'rb') as f: arrProtector.append(f.read())
        arrProtectors.append(arrProtector)
        if boolVerbose:
            print('= ' + arrProtector[0] + ' =')
            print('[+] Provider  : {}'.format(arrProtector[1]))
            print('[+] Key Name  : {} (Probably PIN GUID)'.format(arrProtector[2]))
            print('[+] Timestamp : {}'.format(arrProtector[3]))
            print('[+] Data Size : {} byte(s)\n'.format(len(arrProtector[4])))
    return arrProtectors

def parseItems(sPath, boolVerbose = False):
    arrHeadItems = []
    for sFolder in os.listdir(sPath):
        if not sFolder.startswith('{'): continue
        if len(os.listdir(os.path.join(sPath, sFolder))) <= 1: continue
        arrHeadItems.append(sFolder)
        if boolVerbose: print('= ' + sFolder + ' =')
        for sSubFolder in os.listdir(os.path.join(sPath, sFolder)):
            if sSubFolder.startswith('{'): continue
            ## filename, name, provider, keyname
            arrSubItems = []
            arrSubItems.append(sSubFolder)
            with open(os.path.join(sPath, sFolder, sSubFolder, '1.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '2.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            with open(os.path.join(sPath, sFolder, sSubFolder, '3.dat'), 'rb') as f: arrSubItems.append(f.read().decode('utf16').strip('\x00'))
            arrHeadItems.append(arrSubItems)
            if boolVerbose:
                print('* ' + arrSubItems[0])
                print('[+] Name     : {}'.format(arrSubItems[1]))
                if '9DDC52DB-DC02-4A8C-B892-38DEF4FA748' in arrSubItems[1]: print('[+] Provider : {} (Probably Secundary GUID)'.format(arrSubItems[2]))
                else:  print('[+] Provider : {}'.format(arrSubItems[2]))
                print('[+] Key Name : {}\n'.format(arrSubItems[3]))
    return arrHeadItems

def main(sNGCFolder, boolOutput = True):
    arrGUIDs = os.listdir(sNGCFolder)
    arrResults = []
    for sGUID in arrGUIDs:
        with open(os.path.join(sNGCFolder, sGUID, '1.dat'), 'rb') as f: sUserSID = f.read().decode('UTF16').strip('\x00')
        try: 
            with open(os.path.join(sNGCFolder, sGUID, '7.dat'), 'rb') as f: sMainProvider = f.read().decode('UTF16').strip('\x00')
        except: 
            exit('[-] Failed, are you running as System? (not Admin)')
        
        if boolOutput:
            print('[+] NGC GUID      : ' + sGUID)
            print('[+] User SID      : ' + sUserSID)
            print('[+] Main Provider : ' + sMainProvider)
        
            print('\n== Protectors ==')
        
        arrNGCData = (sGUID, sUserSID, sMainProvider)
        arrProtectors = parseProtectors(os.path.join(sNGCFolder, sGUID, 'Protectors'), boolOutput)

        if boolOutput: print('== Items ==')
        arrItems = parseItems(os.path.join(sNGCFolder, sGUID), boolOutput)
        arrResults.append((arrNGCData, arrProtectors, arrItems))
        if boolOutput: print('=' * 50)
    
    ## Optionally print stuff needed for NGC Windows Hello PIN DECRYPT
    if boolOutput: 
        for arrResult in arrResults:
            sGUID1 = ''
            sRID = ''
            bInputData = b''
            for arrProtector in arrResult[1]:
                if arrProtector[1] == 'Microsoft Software Key Storage Provider' or 'Microsoft Platform Crypto Provider': 
                    sGUID1 = arrProtector[2]
                    bInputData = arrProtector[4]
            sRID = arrResult[0][1].split('-')[len(arrResult[0][1].split('-'))-1]
            if sGUID1 == '': print('[+] MS Platform Crypto Provider detected, PIN is in TPM chip')
            else: print('[+] PIN GUID for user with SID {} : {}'.format(arrResult[0][1], sGUID1))
        print('[!] Hint: run ngccryptokeysdec to decrypt the password and/or bruteforce the Windows HELLO PIN')
        
    return arrResults

if __name__ == '__main__':
    """Utility core."""
    usage = (
        'usage: %prog ngc_folder\n\n'
        'It tries to parse a system NGC Folder.\n'
        '\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\Ngc\n'
        'Watch out: Folder path above requires SYSTEM privileges')

    parser = optparse.OptionParser(usage=usage)
    
    (options, args) = parser.parse_args()
    check_parameters(options, args)
   
    main(args[0])
    
