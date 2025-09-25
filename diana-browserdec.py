#!/usr/bin/python3
# -*- coding: utf-8 -*-
r'''
Copyright 2025, Tijl "Photubias" Deneut <@tijldeneut>
This script provides offline decryption of Chromium based browser user data: Google Chrome, Edge Chromium and Opera

Credentials (and cookies) are encrypted using a Browser Master Encryption key.
This BME key is encrypted using DPAPI in the file "Local State", mostly located at
%localappdata%\{Google/Microsoft}\{Chrome/Edge}\User Data
or %appdata%\Opera Software\Opera Stable
This BME key can then be used to decrypt (AES GCM) the login data and cookies, mostly located at
%localappdata%\{Google/Microsoft}\{Chrome/Edge}\User Data\Default\
or %appdata%\Opera Software\Opera Stable\

DPAPI decrypting the BME key is the hard part. It uses the user DPAPI Masterkey secret from a DPAPI Masterkey file (MK file). 
To identify which DPAPI Masterkey file, the browser "Local State" file contains the cleartext GUID, which is the filename of the MK file
Usually this DPAPI MK file is located at
%appdata%\Microsoft\Protect\<SID>\<GUID>
This DPAPI Masterkey secret is 64bytes in length and can be found either encrypted in lsass memory or encrypted inside the above MK file
The secret within the MK file can be decrypted either via Local AD Domain RSA Key or using local user details
- Local User Details are user SID + SHA1 password hash or sometimes user SID + NTLM password hash (on AzureAD only systems there are no local details and lsass is the only way for now)
- AD Domain RSA Key is the PVK export containing details to construct a private/public RSA encryption certificate, having this and the user MK file can decrypt all domain members

## Generating a list of decrypted MK's can be done with mkudec.py:
e.g. mkudec.py %appdata%\Roaming\Microsoft\Protect\<SID>\* -a <hash> | findstr Secret > masterkeylist.txt
#> and remove all strings '    Secret:'

UPDATE 2024-07-23: Since Chrome v127 a new encryption layer ('v20') was introduced called "Application Bound Encryption (ABE)", System DPAPI data required
UPDATE 2025-02-04: Since Chrome v133 the encryption algorithm changed from AES-GCM to ChaCha20-Poly1305
'''

import argparse, os, json, base64, sqlite3, time, warnings, re, struct
from Crypto.Cipher import AES, ChaCha20_Poly1305
warnings.filterwarnings('ignore')
try:
    from dpapick3 import blob, masterkey, registry
except ImportError:
    raise ImportError('Missing dpapick3, please install via pip install dpapick3')

def parseArgs():
    print('[!] Welcome. To decrypt, one of four combo\'s is required: \n'
          'Decrypted Masterkey / file containing decrypted Masterkeys / MK file, SID and User Pwd or Hash / MK file and Domain PVK\n'
          'Browser data can be found here:\n'
          '%localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Local State\n'
          'Passwords in subfolder Default\\Login Data\n'
          'Cookies in subfolder Default\\Network\\Cookies\n')
    oParser = argparse.ArgumentParser()
    oParser.add_argument('--statefile', '-t', metavar='FILE', help='Browser Local State file', default='Local State')
    oParser.add_argument('--loginfile', '-l', metavar='FILE', help='Browser Login Data file (optional)')
    oParser.add_argument('--cookies', '-c', metavar='FILE', help='Browser Cookies file (optional)')
    oParser.add_argument('--masterkey', '-k', metavar='HEX', help='Masterkey, 128 HEX Characters or in SHA1 format (optional)')
    oParser.add_argument('--systemmasterkey', '-y', metavar='FOLDER', default=os.path.join('Windows','System32','Microsoft','Protect','S-1-5-18','User'), help=r'System Masterkey folder')
    oParser.add_argument('--masterkeylist', '-f', metavar='FILE', help='File containing one or more masterkeys for mass decryption (optional)')
    oParser.add_argument('--mkfile', '-m', metavar='FILE', help='GUID file or folder to get Masterkey(s) from (optional)')
    oParser.add_argument('--sid', '-s', metavar='SID', help='User SID (optional)')
    oParser.add_argument('--system', '-e', metavar='HIVE', default=os.path.join('Windows','System32','config','SYSTEM'), help='System Registry file (optional)')
    oParser.add_argument('--security', '-u', metavar='HIVE', default=os.path.join('Windows','System32','config','SECURITY'), help='Security Registry file (optional)')
    oParser.add_argument('--pwdhash', '-a', metavar='HASH', help='User password SHA1 hash (optional)')
    oParser.add_argument('--password', '-p', metavar='PASS', help='User password (optional)')
    oParser.add_argument('--pvk', '-r', metavar='FILE', help='AD RSA cert in PVK format (optional)')
    oParser.add_argument('--export', '-o', metavar='FILE', help='CSV file to export credentials to (optional)')
    oParser.add_argument('--verbose', '-v', action = 'store_true', default = False, help='Print decrypted creds/cookies to console (optional)')
    oArgs = oParser.parse_args()

    if not os.path.isfile(oArgs.statefile): exit('[-] Error: Please provide Local State file')
    if oArgs.loginfile and not os.path.isfile(oArgs.loginfile): exit('[-] Error: File not found: ' + oArgs.loginfile)
    if oArgs.cookies and not os.path.isfile(oArgs.cookies): exit('[-] Error: File not found: ' + oArgs.cookies)
    if oArgs.masterkeylist and not os.path.isfile(oArgs.masterkeylist): exit('[-] Error: File not found: ' + oArgs.masterkeylist)
    if oArgs.pvk and not os.path.isfile(oArgs.pvk): exit('[-] Error: File not found: ' + oArgs.pvk)
    if oArgs.mkfile: oArgs.mkfile = oArgs.mkfile.replace('*','')
    if oArgs.mkfile and not os.path.isfile(oArgs.mkfile) and not os.path.isdir(oArgs.mkfile): exit('[-] Error: File/folder not found: ' + oArgs.mkfile)
    if not os.path.isfile(oArgs.system): oArgs.system = None
    if not os.path.isfile(oArgs.security): oArgs.security = None
    if not os.path.isdir(oArgs.systemmasterkey): oArgs.systemmasterkey = None
    if oArgs.mkfile and not oArgs.sid: 
        try:
            oArgs.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", oArgs.mkfile)[0]
            print('[+] Detected SID: ' + oArgs.sid)
        except: pass
    if oArgs.mkfile and oArgs.sid and not oArgs.password and not oArgs.pwdhash: 
        oArgs.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: oArgs.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
        print('[+] No password data provided, using empty hash')
    if oArgs.pwdhash: oArgs.pwdhash = bytes.fromhex(oArgs.pwdhash)
    return oArgs

def parseLocalState(sLocalStateFile):
    oABESystemBlob = sVersion = None
    try:
        with open(sLocalStateFile, 'r') as oFile: jsonLocalState = json.loads(oFile.read())
        oFile.close()
        bDPAPIBlob = base64.b64decode(jsonLocalState['os_crypt']['encrypted_key'])[5:]
        if 'app_bound_encrypted_key' in jsonLocalState['os_crypt']:
            bABESystemData = base64.b64decode(jsonLocalState['os_crypt']['app_bound_encrypted_key']).strip(b'\x00')
            if bABESystemData[:4] == b'APPB': oABESystemBlob = blob.DPAPIBlob(bABESystemData[4:])
        if 'variations_permanent_consistency_country' in jsonLocalState: sVersion = jsonLocalState['variations_permanent_consistency_country'][0]
    except Exception as e:
        print(f'[-] Error: file {sLocalStateFile} not a (correct) State file')
        print(e)
        return False, oABESystemBlob, sVersion

    oBlob = blob.DPAPIBlob(bDPAPIBlob)
    return oBlob, oABESystemBlob, sVersion

def parseLoginFile(sLoginFile, lstGUIDs):
    lstLogins = []
    oConn = sqlite3.connect(sLoginFile)
    oConn.text_factory = bytes
    oCursor = oConn.cursor()
    try:
        oCursor.execute('SELECT logins.origin_url, logins.username_value, logins.password_value, password_notes.value FROM logins LEFT JOIN password_notes ON logins.id = password_notes.parent_id')
        for lstData in oCursor.fetchall():
            if lstData[2][:4] == b'\x01\x00\x00\x00': 
                oBlob = blob.DPAPIBlob(lstData[2])
                if not oBlob.mkguid in lstGUIDs: lstGUIDs.append(oBlob.mkguid)
            if lstData[3] and lstData[3][:4] == b'\x01\x00\x00\x00': 
                oBlob = blob.DPAPIBlob(lstData[3])
                if not oBlob.mkguid in lstGUIDs: lstGUIDs.append(oBlob.mkguid)
            lstLogins.append((lstData[0].decode(), lstData[1].decode(), lstData[2], lstData[3]))
    except Exception as e:
        print('[-] Error reading Login Data file, make sure it is not in use.')
        print(e)
    oCursor.close()
    oConn.close()

    return lstLogins, lstGUIDs ## lstLogins = list of lists (url, username, blob, noteblob)

def parseCookieFile(sCookieFile, lstGUIDs):
    lstCookies = []
    try: oConn = sqlite3.connect(sCookieFile)
    except Exception as e: 
        print(f'[-] Error parsing cookie file {sCookieFile}, file may be locked, please close the browser process.')
        print(e)
        exit()
    oCursor = oConn.cursor()
    try:
        oCursor.execute('SELECT name, CAST(encrypted_value AS BLOB), host_key, path, is_secure, is_httponly, creation_utc, expires_utc FROM cookies ORDER BY host_key')
        for lstData in oCursor.fetchall():
            if lstData[1][:4] == b'\x01\x00\x00\x00': 
                oBlob = blob.DPAPIBlob(lstData[1])
                if not oBlob.mkguid in lstGUIDs: lstGUIDs.append(oBlob.mkguid)
            lstCookies.append((lstData[0], lstData[1], lstData[2], lstData[3], lstData[4], lstData[5], lstData[6], lstData[7]))
    except Exception as e:
        print('[-] Error reading Cookies file, make sure it is not in use.')
        print(e)
        exit()
    oCursor.close()
    oConn.close()
    
    return lstCookies, lstGUIDs ## lstCookies = list of lists (name, blob, domain, path, secureconnection, httponly, created, expires)

def tryDPAPIDecrypt(oBlob, bMasterkey):
    try: 
        if oBlob.decrypt(bMasterkey): return oBlob.cleartext
    except: pass
    return None

def decryptChromeString(bData, bBMEKey, lstMasterkeys, boolVerbose = False):
    if bData[:4] == b'\x01\x00\x00\x00':
        oBlob = blob.DPAPIBlob(bData)
        for bMK in lstMasterkeys:
            oBlob.decrypt(bMK)
            if oBlob.decrypted: return oBlob.cleartext
    elif bData[:3] == b'v20' or bData[:3] == 'v20': ## Version|IV|ciphertext|tag, 3|12|<var>|16 bytes
        ## New Encryption Scheme, bBMEKey should now contain the ABE key
        bIV = bData[3:3+12]
        bEncrypted = bData[15:-16]
        bTag = bData[-16:]
        oCipher = AES.new(bBMEKey, AES.MODE_GCM, bIV)
        bDecrypted = oCipher.decrypt_and_verify(bEncrypted, bTag)
        #return bDecrypted[32:] ## v20 cookies have offset, v20 passwords do not
        return bDecrypted
    else: ## Version|IV|ciphertext, 4|12|<var>
        try:
            bIV = bData[3:3+12]
            bEncrypted = bData[15:]
            oCipher = AES.new(bBMEKey, AES.MODE_GCM, bIV)
            bDecrypted = oCipher.decrypt(bEncrypted)
            return bDecrypted
            #return bDecrypted[32:-16] ## for passwords
            #return bDecrypted[:-16] ## for cookies
        except: 
            if boolVerbose: print('[-] Error decrypting, maybe Browser Engine < v80')
            pass
    return None

def decryptLogins(lstLogins, bBrowserBMEKey, bBrowserABEKey=None, lstMasterkeys=[], sCSVFile = None, boolVerbose = False):
    iDecrypted = 0
    if sCSVFile: 
        oFile = open('logins_' + sCSVFile, 'a')
        oFile.write('URL;Username;Password;Note\n')
    boolv20 = False
    for lstLogin in lstLogins: ## URL|Username|Password|Note
        bDecrypted = bDecryptedNote = None
        if lstLogin[3] and lstLogin[3] == b'v20' and bBrowserABEKey: 
            bDecryptedNote = decryptChromeString(lstLogin[3], bBrowserABEKey, lstMasterkeys)
        elif lstLogin[3]: 
            bDecryptedNote = decryptChromeString(lstLogin[3], bBrowserBMEKey, lstMasterkeys)
            if bDecryptedNote and len(bDecryptedNote)>=16: bDecryptedNote = bDecryptedNote[:-16]
        if bDecryptedNote: sDecryptedNote = bDecryptedNote.decode()
        else: sDecryptedNote = None

        if not lstLogin[2]: bDecrypted = b''
        elif lstLogin[2][:3] == b'v20' or lstLogin[2][:3] == 'v20': 
            if not bBrowserABEKey: boolv20 = True
            else: bDecrypted = decryptChromeString(lstLogin[2], bBrowserABEKey, lstMasterkeys)
        else: 
            bDecrypted = decryptChromeString(lstLogin[2], bBrowserBMEKey, lstMasterkeys)
            if bDecrypted and len(bDecrypted) >= 16: bDecrypted = bDecrypted[:-16]
        if bDecrypted: sDecrypted = bDecrypted.decode()
        else: sDecrypted = None
        if sDecrypted != None: iDecrypted += 1

        if boolVerbose: 
            print('URL:       {}'.format(lstLogin[0]))
            print('User Name: {}'.format(lstLogin[1]))
            if sDecrypted: print('Password:  {}'.format(sDecrypted))
            if sDecryptedNote: print('Note:      {}'.format(sDecryptedNote))
            print('*' * 50)
        
        if not sDecrypted: sDecrypted = ''
        if not sDecryptedNote: sDecryptedNote = ''
        if sCSVFile: oFile.write('{};{};{};{}\n'.format(lstLogin[0], lstLogin[1], sDecrypted, sDecryptedNote))
    if sCSVFile: oFile.close()
    if boolv20: print('[-] Encryption type "v20" detected, SYSTEM DPAPI details required to decrypt App-Bound-Encryption data')
    return iDecrypted

def decryptCookies(lstCookies, bBrowserBMEKey, bBrowserABEKey=None, lstMasterkeys=[], sCSVFile = None, boolVerbose = False):
    iDecrypted = 0
    if sCSVFile: 
        oFile = open('cookies_' + sCSVFile, 'a')
        oFile.write('name;value;host_key;path;is_secure;is_httponly;creation_utc;expires_utc\n')
    boolv20 = False
    for lstCookie in lstCookies:
        bDecrypted = None
        try: 
            if not lstCookie[1]: bDecrypted = b''
            elif lstCookie[1][:3] == b'v20' or lstCookie[1][:3] == 'v20': 
                if not bBrowserABEKey: boolv20 = True
                else: bDecrypted = decryptChromeString(lstCookie[1], bBrowserABEKey, lstMasterkeys)
                if bDecrypted and len(bDecrypted) >= 32: bDecrypted = bDecrypted[32:]
            else: 
                bDecrypted = decryptChromeString(lstCookie[1], bBrowserBMEKey, lstMasterkeys)
                if len(bDecrypted) >= 48: bDecrypted = bDecrypted[32:-16]
        except: continue
        if bDecrypted: sDecrypted = bDecrypted.decode()
        else: sDecrypted = None
        ## Chrome timestamp is "amount of microseconds since 01-01-1601", so we need math
        sCreated = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lstCookie[6] / 1000000 - 11644473600))
        if lstCookie[7] == 0: sExpires = 'No Expiry'
        else: sExpires = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(lstCookie[7] / 1000000 - 11644473600))
        if boolVerbose: 
                print('Name:      {}'.format(lstCookie[0]))
                print('Content:   {}'.format(sDecrypted))
                print('Domain:    {}'.format(lstCookie[2]))
                print('Path:      {}'.format(lstCookie[3]))
                if lstCookie[4] == 1: print('Send for:  Secure connections only')
                else: print('Send for:  Any kind of connection')
                if lstCookie[5] == 1: print('HttpOnly:  Yes')
                else: print('HttpOnly:  No (Accessible to scripts)')
                print('Created:   {}'.format(sCreated))
                print('Expires:   {}'.format(sExpires))
                print('*' * 50)
        if not sDecrypted == None: iDecrypted += 1
        if sCSVFile: oFile.write('{};{};{};{};{};{};{};{}\n'.format(lstCookie[0], sDecrypted, lstCookie[2], lstCookie[3], lstCookie[4], lstCookie[5], lstCookie[6], lstCookie[7]))
    if sCSVFile: oFile.close()
    if boolv20: print('[-] Encryption type "v20" detected, SYSTEM DPAPI details required to decrypt App-Bound-Encryption data')
    return iDecrypted

def parseABEBlob(bABEData):
    dctABEData = {}
    iHeaderLen = struct.unpack('<I', bABEData[:4])[0]
    dctABEData['header'] = bABEData[4:4+iHeaderLen].strip(b'\x02').decode(errors='ignore')
    iContentLen = struct.unpack('<I', bABEData[4+iHeaderLen:4+iHeaderLen+4])[0]
    bContent = bABEData[8+iHeaderLen:8+iHeaderLen+iContentLen]

    if iContentLen==32: return {'data':bContent} ## No versioning here (some versions of Edge do this)

    dctABEData['version'] = int(bContent[0])
    bContent = bContent[1:]
    if dctABEData['version'] <= 2: ## Versions 1 and 2
        ## Version|IV|ciphertext|tag, 1|12|32|16 bytes
        dctABEData['iv'] = bContent[:12]
        dctABEData['cipherdata'] = bContent[12:12+32]
        dctABEData['tag'] = bContent[12+32:12+32+16]
    else: ## Version 3
        ## Version|encAES|IV|ciphertext|tag, 1|32|12|32|16 bytes
        dctABEData['encrAES'] = bContent[:32]
        dctABEData['iv'] = bContent[32:32+12]
        dctABEData['cipherdata'] = bContent[32+12:32+12+32]
        dctABEData['tag'] = bContent[32+12+32:32+12+32+16]
    return dctABEData

def deriveABEKey(dctABEData):
    if dctABEData['version'] == 1:
        oCipher = AES.new(bytes.fromhex('B31C6E241AC846728DA9C1FAC4936651CFFB944D143AB816276BCC6DA0284787'), AES.MODE_GCM, nonce=dctABEData['iv'])
    elif dctABEData['version'] == 2:
        oCipher = ChaCha20_Poly1305.new(key=bytes.fromhex('E98F37D7F4E1FA433D19304DC2258042090E2D1D7EEA7670D41F738D08729660'), nonce=dctABEData['iv'])
    elif dctABEData['version'] == 3:
        bXORKey = bytes.fromhex('CCF8A1CEC56605B8517552BA1A2D061C03A29E90274FB2FCF59BA4B75C392390')
        print('[-] Error: found ABE encryption version 3, not yet implemented. I need some coffee :-)')
        return None
        ## TODO: Decrypt the Encrypted AES Key here, todo via CNG
        #bAESKey = xor-decrypted-aes-with-bXORKey
        #oCipher = AES.new(bAESKey, AES.MODE_GCM, nonce=dctABEData['iv'])

    return oCipher.decrypt_and_verify(dctABEData['cipherdata'], dctABEData['tag'])
    
if __name__ == '__main__':
    oArgs = parseArgs()
    lstGUIDs, lstLogins, lstCookies, lstMasterkeys, lstSystemMasterkeys = [], [], [], [], []
    bBrowserBMEKey = bMasterkey = oMKP = oABESystemBlob = oABEUserBlob = bABEData = bBrowserABEKey = bABEMasterkey = None
    
    ## List required GUID from Local State
    oStateBlob, oABESystemBlob, sVersion = parseLocalState(oArgs.statefile)
    print(f'[+] Browser State File encrypted with Masterkey GUID: {oStateBlob.mkguid}')
    lstGUIDs.append(oStateBlob.mkguid)
    if oABESystemBlob: print(f'    And also the ABE-Key requires the SYSTEM Masterkey with GUID: {oABESystemBlob.mkguid}')
    if sVersion: print(f'    > Detected Browser version: {sVersion}')

    ## Get Logins, if any
    if oArgs.loginfile: 
        lstLogins, lstGUIDs = parseLoginFile(oArgs.loginfile, lstGUIDs)
        print('[!] Found {} credential(s).'.format(str(len(lstLogins))))
    
    ## Get Cookies, if any
    if oArgs.cookies: 
        lstCookies, lstGUIDs = parseCookieFile(oArgs.cookies, lstGUIDs)
        print('[!] Found {} cookie(s).'.format(str(len(lstCookies))))

    ## Decrypting ABE Blob phase 1: SYSTEM DPAPI
    if oArgs.system and oArgs.security and oArgs.systemmasterkey and oABESystemBlob:
        print('[+] Found SYSTEM & SECURITY hives, trying first-stage ABE Key decrypting using SYSTEM keys')
        oReg = registry.Regedit()
        oSecrets = oReg.get_lsa_secrets(oArgs.security, oArgs.system)
        bDPAPI_SYSTEM = oSecrets.get('DPAPI_SYSTEM')['CurrVal']
        oMKP1 = masterkey.MasterKeyPool()
        ''' ## This loads all Master Keys, better but slower
        oMKP1.loadDirectory(oArgs.systemmasterkey)
        oMKP1.addSystemCredential(bDPAPI_SYSTEM)
        oMKP1.try_credential_hash(None, None)
        for lstMKL in oMKP1.keys.values():
            for oMK in lstMKL:
                bABEUserData = tryDPAPIDecrypt(oABESystemBlob, oMK.get_key()) 
                if bABEUserData:
                    oABEUserBlob = blob.DPAPIBlob(bABEUserData)
                    print(f'[+] Decrypted first-stage of ABE-Key, needed for second-stage is USER Masterkey with GUID: {oABEUserBlob.mkguid}')
                    lstGUIDs.append(oABEUserBlob.mkguid)
                    break
        '''
        for sFile in os.listdir(oArgs.systemmasterkey):
            if sFile == oABESystemBlob.mkguid:
                oMKP1.addMasterKey(open(os.path.join(oArgs.systemmasterkey,sFile),'rb').read())
                oMKP1.addSystemCredential(bDPAPI_SYSTEM)
                oMKP1.try_credential_hash(None, None)
                bABEUserData = tryDPAPIDecrypt(oABESystemBlob, list(oMKP1.keys.values())[0][0].get_key())
                if bABEUserData:
                    oABEUserBlob = blob.DPAPIBlob(bABEUserData)
                    print(f'[+] Decrypted first-stage of ABE-Key, needed for second-stage is USER Masterkey with GUID: {oABEUserBlob.mkguid}')
                    lstGUIDs.append(oABEUserBlob.mkguid)
                    break
    
    ## If no decryption details are provided, feed some results back
    if oABESystemBlob and (not oArgs.system or not oArgs.security or not oArgs.systemmasterkey):
        print(f'[-] Unable to decrypt ABE key details, please specify System & Security hives and Masterkey with GUID {oABESystemBlob.mkguid}')
    if not oArgs.masterkey and not oArgs.masterkeylist and not oArgs.mkfile: 
        if(len(lstGUIDs) > 1):
            lstGUIDs.sort()
            print('[!] Required for full decryption are {} different Masterkeys, their GUIDs:'.format(str(len(lstGUIDs))))
            for sGUID in lstGUIDs: print(f'    {sGUID}')
        print('[!] Go and find these files and accompanying decryption details')
        exit(0)
    
    print('\n ----- Getting Browser (& ABE) Master Encryption Key -----')
    ## Option 1 for getting BME Key: the 64byte DPAPI masterkey is provided (either directly or via a list)
    if oArgs.masterkey: 
        print('[!] Trying direct masterkey')
        bMasterkey = bytes.fromhex(oArgs.masterkey)
    elif oArgs.masterkeylist:
        print('[!] Trying list of masterkeys')
        for sMasterkey in open(oArgs.masterkeylist,'r').read().splitlines(): 
            if len(sMasterkey.strip()) == 128 or len(sMasterkey.strip()) == 40: lstMasterkeys.append(bytes.fromhex(sMasterkey.strip()))
        for bMK in lstMasterkeys:
            bBrowserBMEKey = tryDPAPIDecrypt(oStateBlob, bMK)
            if oABEUserBlob: bABEData = tryDPAPIDecrypt(oABEUserBlob, bMK)
    ##  All other options require one or more MK files, using MK Pool
    if oArgs.mkfile:
        oMKP = masterkey.MasterKeyPool()
        if os.path.isfile(oArgs.mkfile): oMKP.addMasterKey(open(oArgs.mkfile,'rb').read())
        else: 
            oMKP.loadDirectory(oArgs.mkfile)
            if oArgs.verbose: print('[!] Imported {} keys'.format(str(len(list(oMKP.keys)))))
    
    ## Option 2 for getting BME Key: the PVK domain key to decrypt the MK key
    if oMKP and oArgs.pvk:
        print('[!] Try MK decryption with the PVK domain key')
        if oMKP.try_domain(oArgs.pvk) > 0:
            for bMKGUID in list(oMKP.keys):
                oMK = oMKP.getMasterKeys(bMKGUID)[0]
                if oMK.decrypted: 
                    if not oMK.get_key() in lstMasterkeys: lstMasterkeys.append(oMK.get_key())
                    if bMKGUID.decode(errors='ignore') == oStateBlob.mkguid: 
                        bMasterkey = oMK.get_key()
                        print('[+] Success, user masterkey decrypted: ' + bMasterkey.hex())

    ## Option 3 for getting BME Key: User SID + password (hash)
    if oArgs.mkfile and oArgs.sid and (oArgs.password or oArgs.pwdhash): 
        print('[!] Try MK decryption with user details, might take some time')
        if oArgs.password: oMKP.try_credential(oArgs.sid, oArgs.password)
        else: oMKP.try_credential_hash(oArgs.sid, oArgs.pwdhash)
        oMKP.try_credential_hash(oArgs.sid, bytes.fromhex('da39a3ee5e6b4b0d3255bfef95601890afd80709')) ## SHA1 hash for empty password, just for fun 
        for bMKGUID in list(oMKP.keys):
            oMK = oMKP.getMasterKeys(bMKGUID)[0]
            if oMK.decrypted: 
                if not oMK.get_key() in lstMasterkeys: lstMasterkeys.append(oMK.get_key())
                if oABEUserBlob and bMKGUID.decode(errors='ignore') == oABEUserBlob.mkguid:
                    bABEMasterkey = oMK.get_key()
                    if oArgs.verbose: print('[+] Success, ABE masterkey decrypted: {}'.format(bABEMasterkey.hex()))
                if bMKGUID.decode(errors='ignore') == oStateBlob.mkguid: 
                    bMasterkey = oMK.get_key()
                    if oArgs.verbose: print('[+] Success, Browser masterkey decrypted: {}'.format(bMasterkey.hex()))
    if not bABEData:
        bABEData = tryDPAPIDecrypt(oABEUserBlob, bABEMasterkey)
        #if bABEMasterkey not in lstMasterkeys: lstMasterkeys.append(bABEMasterkey)
    if bABEData:
        dctABEData = parseABEBlob(bABEData)
        if 'version' in dctABEData: bBrowserABEKey = deriveABEKey(dctABEData)
        else: bBrowserABEKey = dctABEData['data'] ## This might a simplification, but it seems to work
        if bBrowserABEKey: print(f'\n[+] Got ABE Encryption Key: {bBrowserABEKey.hex()}')
    if not bBrowserBMEKey: 
        bBrowserBMEKey = tryDPAPIDecrypt(oStateBlob, bMasterkey)
        #if bMasterkey not in lstMasterkeys: lstMasterkeys.append(bMasterkey)
    if bBrowserBMEKey: print(f'[+] Got Browser Master Encryption Key: {bBrowserBMEKey.hex()}\n')
    else: 
        print('[-] Too bad, no dice, not enough or wrong information')
        exit(0)

    if oArgs.loginfile or oArgs.cookies: print('\n ----- Decrypting logins/cookies -----')
    ## Decrypting logins
    if bBrowserBMEKey and lstLogins:
        iDecrypted = decryptLogins(lstLogins, bBrowserBMEKey, bBrowserABEKey, lstMasterkeys, oArgs.export, oArgs.verbose)
        print(f'[!] Decrypted {iDecrypted} / {len(lstLogins)} credentials')

    ## Decrypting cookies
    if bBrowserBMEKey and lstCookies:
        iDecrypted = decryptCookies(lstCookies, bBrowserBMEKey, bBrowserABEKey, lstMasterkeys, oArgs.export, oArgs.verbose)
        print(f'[!] Decrypted {iDecrypted} / {len(lstCookies)} cookies')
    
    if not oArgs.verbose and bBrowserBMEKey: print('[!] To print the results to terminal, rerun with "-v"')
