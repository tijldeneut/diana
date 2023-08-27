#!/usr/bin/env python3
# -*- coding: utf-8 -*-
r'''
Copyright 2022, Tijl "Photubias" Deneut <@tijldeneut>
Copyright 2023, Banaanhangwagen <@banaanhangwagen>
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
'''
import argparse
import os
import json
import base64
import sqlite3
import time
import warnings
import re
import sys

from Crypto.Cipher import AES
from termcolor import colored

warnings.filterwarnings("ignore")

try:
    from dpapick3 import blob, masterkey
except ImportError:
    raise ImportError("Missing dpapick3, please install via `pip install dpapick3`")


def parse_args():
    print(colored('[INFO] Welcome. To decrypt, one of four combo\'s is required:', 'yellow'))
    print(
        "\t(1) Decrypted Masterkey\n\t(2) File containing decrypted Masterkeys\n\t(3) Masterkey-file, SID and User-Pwd (or Hash)\n\t(4) Masterkey-file and Domain PVK")
    print(colored("[INFO] Needed files can be found here:", 'yellow'))
    print("\tLocal State: %localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Local State\n"
        "\tPasswords: %localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Login Data\n"
        "\tCookies: %localappdata%\\{Google/Microsoft}\\{Chrome/Edge}\\User Data\\Default\\Login Data\\Network\\Cookies\n"
        "\tMasterkey(s): %appdata%\\Microsoft\\Protect\\S-1-5-21...-folder\n")

    o_parser = argparse.ArgumentParser()

    o_parser.add_argument(
        '--statefile', '-t',
        metavar='FILE',
        help='Browser "Local State"-file',
        default='Local State'
    )
    o_parser.add_argument(
        '--loginfile', '-l',
        metavar='FILE',
        help='Browser "Login Data"-file (optional)'
    )
    o_parser.add_argument(
        '--cookies', '-c',
        metavar='FILE',
        help='Browser Cookies-file (optional)'
    )
    o_parser.add_argument(
        '--masterkey', '-k',
        metavar='HEX',
        help='Masterkey, 128 HEX Characters or in SHA1 format (optional)'
    )
    o_parser.add_argument(
        '--masterkeylist', '-f',
        metavar='FILE',
        help='File containing one or more masterkeys for mass decryption (optional)'
    )
    o_parser.add_argument(
        '--mkfile', '-m',
        metavar='FILE',
        help='GUID file or folder to get Masterkey(s) from (optional)'
    )
    o_parser.add_argument(
        '--sid', '-s',
        metavar='SID',
        help='User SID (optional)'
    )
    o_parser.add_argument(
        '--pwdhash', '-a',
        metavar='HASH',
        help='User password SHA1 hash (optional)'
    )
    o_parser.add_argument(
        '--password', '-p',
        metavar='PASS',
        help='User password (optional)'
    )
    o_parser.add_argument(
        '--pvk', '-r',
        metavar='FILE',
        help='AD RSA cert in PVK format (optional)'
    )
    o_parser.add_argument(
        '--export', '-o',
        metavar='FILE',
        help='CSV file to export credentials to (optional)'
    )
    o_parser.add_argument(
        '--verbose', '-v',
        action='store_true',
        default=True,
        help='Print decrypted creds/cookies to console (optional)'
    )

    o_args = o_parser.parse_args()

    if not os.path.isfile(o_args.statefile):
        sys.exit('[-] Error: Please provide a correct \"Local State\"-file')
    if o_args.loginfile and not os.path.isfile(o_args.loginfile):
        sys.exit('[-] Error: File not found: ' + o_args.loginfile)
    if o_args.cookies and not os.path.isfile(o_args.cookies):
        sys.exit('[-] Error: File not found: ' + o_args.cookies)
    if o_args.masterkeylist and not os.path.isfile(o_args.masterkeylist):
        sys.exit('[-] Error: File not found: ' + o_args.masterkeylist)
    if o_args.pvk and not os.path.isfile(o_args.pvk):
        sys.exit('[-] Error: File not found: ' + o_args.pvk)

    # Process mkfile argument
    if o_args.mkfile:
        o_args.mkfile = o_args.mkfile.replace('*', '')
        if not os.path.isfile(o_args.mkfile) and not os.path.isdir(o_args.mkfile):
            sys.exit('[-] Error: File/folder not found: ' + o_args.mkfile)
        if not o_args.sid:
            try:
                o_args.sid = re.findall(r"S-1-\d+-\d+-\d+-\d+-\d+-\d+", o_args.mkfile)[0]
                print(colored('[+] Detected SID: ' + o_args.sid, 'green'))
            except:
                pass
    if o_args.mkfile and o_args.sid and not o_args.password and not o_args.pwdhash:
        o_args.pwdhash = 'da39a3ee5e6b4b0d3255bfef95601890afd80709'
        # On older systems: o_args.pwdhash = '31d6cfe0d16ae931b73c59d7e0c089c0'
        print('[+] No password data provided, using empty hash')
    if o_args.pwdhash:
        o_args.pwdhash = bytes.fromhex(o_args.pwdhash)

    return o_args


def parse_local_state(local_state_file):
    try:
        with open(local_state_file, "r") as file:
            local_state = json.load(file)
            dpapi_blob = base64.b64decode(local_state["os_crypt"]["encrypted_key"])[5:]
    except Exception as e:
        print(colored(f"[-] Error reading \"Local State\"-file: {e}", 'red'))
        print(colored("[INFO] Exiting...", 'red'))
        sys.exit()
    parsed_blob = blob.DPAPIBlob(dpapi_blob)
    return parsed_blob


def parse_login_file(sLoginFile, lstGUIDs):
    lstLogins = []
    try:
        with sqlite3.connect(sLoginFile) as oConn:
            oCursor = oConn.cursor()
            oCursor.execute('SELECT origin_url, username_value, password_value, id FROM logins')

        for lstData in oCursor.fetchall():
            if lstData[0][:4] == b'\x01\x00\x00\x00':
                parsed_blob = blob.DPAPIBlob(lstData[0])
                if parsed_blob.mkguid not in lstGUIDs:
                    lstGUIDs.append(parsed_blob.mkguid)

            lstLogins.append((lstData[0], lstData[1], lstData[2], lstData[3]))

    except sqlite3.Error as e:
        print(colored(f"[-] Error reading \"Login Data\"-file: {e}", 'red'))
        # print("[INFO] Exiting...")
        # sys.exit()
        pass
    # lstLogins = list of lists (url, username, blob, id)
    return lstLogins, lstGUIDs


def parse_notes(sLoginFile, lstGUIDs):
    lstNotes = []
    try:
        with sqlite3.connect(sLoginFile) as oConn:
            oCursor = oConn.cursor()
            oConn.text_factory = bytes
            oCursor.execute('SELECT value FROM password_notes')

        for lstNoteData in oCursor.fetchall():
            if lstNoteData[0][:4] == b'\x01\x00\x00\x00':
                parsed_blob = blob.DPAPIBlob(lstNoteData[0])
                if parsed_blob.mkguid not in lstGUIDs:
                    lstGUIDs.append(parsed_blob.mkguid)
            lstNotes.append(lstNoteData[0])

    except sqlite3.Error as e:
        print(colored(f"[-] Error reading \"Login Data\"-file: {e}", 'red'))
        pass

    return lstNotes, lstGUIDs


def decryptBMEKey(parsed_blob, bMasterkey):
    try:
        if parsed_blob.decrypt(bMasterkey):
            return parsed_blob.cleartext
    except:
        pass
    return None


def decryptChromeString(bData, bBMEKey, lstMasterkeys, boolVerbose=False):
    if bData[:4] == b'\x01\x00\x00\x00':
        parsed_blob = blob.DPAPIBlob(bData)
        for bMK in lstMasterkeys:
            parsed_blob.decrypt(bMK)
            if parsed_blob.decrypted:
                return parsed_blob.cleartext.decode(errors='ignore')
    else:
        try:
            bIV = bData[3:15]
            bPayload = bData[15:]
            oCipher = AES.new(bBMEKey, AES.MODE_GCM, bIV)
            bDecrypted = oCipher.decrypt(bPayload)
            return bDecrypted[:-16].decode(errors='ignore')
        except Exception:
            if boolVerbose:
                print(colored("[-] Error decrypting, maybe Browser Engine < v80", 'red'))
            pass
    return None


def decryptLogins(lstLogins, bBrowserBMEKey, lstMasterkeys, sCSVFile=None, boolVerbose=False):
    iDecrypted = 0
    if sCSVFile:
        with open('logins_' + sCSVFile, 'a') as oFile:
            oFile.write('ID;URL;Username;Password\n')
    for lstLogin in lstLogins:
        sDecrypted = decryptChromeString(lstLogin[2], bBrowserBMEKey, lstMasterkeys)
        if boolVerbose:
            print('ID:        {}'.format(lstLogin[3]))
            print('URL:       {}'.format(lstLogin[0]))
            print('User Name: {}'.format(lstLogin[1]))
            print('Password:  {}'.format(sDecrypted))
            print('*' * 50)
        if sDecrypted is not None:
            iDecrypted += 1
        if sCSVFile:
            with open('logins_' + sCSVFile, 'a') as oFile:
                oFile.write('{};{};{};{}\n'.format(lstLogin[3], lstLogin[0], lstLogin[1], sDecrypted))
    return iDecrypted


def decryptNotes(lstNotes, bBrowserBMEKey, lstMasterkeys, lstGUIDs, sCSVFile=None, boolVerbose=False):
    iDecrypted = 0
    if sCSVFile:
        with open('notes_' + sCSVFile, 'a') as oFile:
            oFile.write('Note\n')
    for lstNote in lstNotes:
        note_decrypted = decryptChromeString(lstNote, bBrowserBMEKey, lstMasterkeys)
        if boolVerbose:
            print('Note:  {}'.format(note_decrypted))
            print('*' * 50)
        if note_decrypted is not None:
            iDecrypted += 1
        if sCSVFile:
            with open('notes_' + sCSVFile, 'a') as oFile:
                oFile.write('{}\n'.format(note_decrypted))
    return iDecrypted


if __name__ == '__main__':
    oArgs = parse_args()
    lstGUIDs, lstLogins, lstCookies, lstMasterkeys = [], [], [], []
    bBrowserBMEKey = bMasterkey = oMKP = None

    ## List required GUID from Local State
    oStateBlob = parse_local_state(oArgs.statefile)
    print(colored('[+] Local State-file encrypted with Masterkey GUID: ' + oStateBlob.mkguid, 'green'))
    lstGUIDs.append(oStateBlob.mkguid)

    ## Get Logins, if any
    if oArgs.loginfile:
        lstLogins, lstGUIDs = parse_login_file(oArgs.loginfile, lstGUIDs)
        print('[!] Found {} credential(s).'.format(len(lstLogins)))
    else:
        print(colored('[-] Error: No \"Login Data\"-file provided. Exiting...', 'red'))
        exit()

    ## Get Notes, if any
    if oArgs.loginfile:
        lstNotes, lstGUIDs = parse_notes(oArgs.loginfile, lstGUIDs)
        print('[!] Found {} note(s).'.format(len(lstNotes)))

    ## If no decryption details are provided, feed some results back
    if not oArgs.masterkey and not oArgs.masterkeylist and not oArgs.mkfile:
        if (len(lstGUIDs) > 1):
            lstGUIDs.sort()
            print('[!] Found {} different Masterkeys, required for decrypting all logins and/or cookies:'.format(
                str(len(lstGUIDs))))
            for sGUID in lstGUIDs: print('    ' + sGUID)
        print('[!] Input the MK-files and accompanying decryption details to continue decrypting')
        exit(0)

    print(colored('\n[INFO] Getting Browser Master Encryption Key', 'yellow'))
    # Option 1 for getting BME Key: the 64byte DPAPI masterkey is provided (either directly or via a list)
    if oArgs.masterkey:
        print('[!] Trying direct masterkey')
        bMasterkey = bytes.fromhex(oArgs.masterkey)
    elif oArgs.masterkeylist:
        print('[!] Trying list of masterkeys')
        for sMasterkey in open(oArgs.masterkeylist, 'r').read().splitlines():
            if len(sMasterkey.strip()) == 128 or len(sMasterkey.strip()) == 40: lstMasterkeys.append(
                bytes.fromhex(sMasterkey.strip()))
        for bMK in lstMasterkeys:
            bBrowserBMEKey = decryptBMEKey(oStateBlob, bMK)
            if bBrowserBMEKey:
                break
    #  All other options require one or more MK files, using MK-pool
    if oArgs.mkfile:
        oMKP = masterkey.MasterKeyPool()
        if os.path.isfile(oArgs.mkfile):
            oMKP.addMasterKey(open(oArgs.mkfile, 'rb').read())
        else:
            oMKP.loadDirectory(oArgs.mkfile)
            if oArgs.verbose:
                print('[!] Imported {} keys'.format(str(len(list(oMKP.keys)))))

    # Option 2 for getting BME Key: the PVK domain key to decrypt the MK key
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
        print('[!] Trying MasterKey decryption with user details, might take some time...')
        if oArgs.password:
            oMKP.try_credential(oArgs.sid, oArgs.password)
        else:
            oMKP.try_credential_hash(oArgs.sid, oArgs.pwdhash)
        for bMKGUID in list(oMKP.keys):
            oMK = oMKP.getMasterKeys(bMKGUID)[0]
            if oMK.decrypted:
                if not oMK.get_key() in lstMasterkeys: lstMasterkeys.append(oMK.get_key())
                if bMKGUID.decode(errors='ignore') == oStateBlob.mkguid:
                    bMasterkey = oMK.get_key()
                    print(colored('[+] Success!', 'green'))
                    print(colored('[+] Decrypted User MasterKey: ' + bMasterkey.hex(), 'green'))

    if not bBrowserBMEKey:
        bBrowserBMEKey = decryptBMEKey(oStateBlob, bMasterkey)
        if bMasterkey not in lstMasterkeys: lstMasterkeys.append(bMasterkey)
    if bBrowserBMEKey:
        print(colored('[+] Got Browser Master Encryption Key: {}\n'.format(bBrowserBMEKey.hex()), 'green'))
    else:
        print(colored('[-] Too bad, no dice, not enough or wrong information', 'red'))
        exit(0)

    if oArgs.loginfile or oArgs.cookies:

    # Decrypting logins
        print(colored('[INFO] Decrypting logins....\n', 'yellow'))
        print('*' * 50)
    if bBrowserBMEKey and lstLogins:
        iDecrypted = decryptLogins(lstLogins, bBrowserBMEKey, lstMasterkeys, oArgs.export, oArgs.verbose)
        print('Decrypted {} / {} credentials\n'.format(str(iDecrypted), str(len(lstLogins))))

    # Decrypting Notes
    print(colored('[INFO] Decrypting notes....\n', 'yellow'))
    print('*' * 50)
    if bBrowserBMEKey and lstNotes:
        iDecrypted = decryptNotes(lstNotes, bBrowserBMEKey, lstMasterkeys, lstGUIDs, oArgs.export, oArgs.verbose)
        print('Decrypted {} / {} notes\n'.format(str(iDecrypted), str(len(lstNotes))))

    if not oArgs.verbose and bBrowserBMEKey:
        print('[!] To print the results to terminal, rerun with "-v"')

    database = sqlite3.connect(oArgs.loginfile)
    with database:
        for values in database.execute('SELECT origin_domain, username_value FROM stats'):
            print(colored("[BONUS-DELETED LOGIN]: ", 'yellow'))
            print(values[0], "\t", values[1])
