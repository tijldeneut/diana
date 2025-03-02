#!/usr/bin/python3
# -*- coding: utf-8 -*-
r'''
    Copyright 2024, Tijl "Photubias" Deneut <@tijldeneut>
    
    Licensed under the Apache License, Version 2.0 (the "License");
    you may not use this file except in compliance with the License.
    You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

    Unless required by applicable law or agreed to in writing, software
    distributed under the License is distributed on an "AS IS" BASIS,
    WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
    See the License for the specific language governing permissions and
    limitations under the License.
    
    This script converts a csv output from cookie-browserdec into a SQlite3 cookie database for use in Firefox
       Can be used in Firefox (portable) or a custom profile to access websites
       
    In Linux just run:
    diana-cookieinjector.py -c cookieexport.csv -s firefox
    For Windows, specify the fill Firefox path
'''

import sqlite3, random, string, time, os, optparse, sys

def check_parameters(options):
    if not os.path.exists(options.cookiefile):
        sys.exit('Please specify a source file containing exported cookies.')

def newConnection(sFilename, boolOldfirefox):
    oConn = None
    boolNewfile = True
    if os.path.exists(sFilename): boolNewfile = False
    try: oConn = sqlite3.connect(sFilename)
    except sqlite3.Error as e: exit(e)
    oCur = oConn.cursor()
    if boolNewfile:
        ##  Format for Firefox 51.0 (32-bit) Portable (pre 67)
        if boolOldfirefox: oCur.execute('CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, baseDomain TEXT, originAttributes TEXT NOT NULL DEFAULT "", name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, appId INTEGER DEFAULT 0, inBrowserElement INTEGER DEFAULT 0, CONSTRAINT moz_uniqueid UNIQUE (name, host, path, originAttributes));')
        ## Format for Firefox 100.0 (64-bit) (post 67), updated for Firefox 128 (new column)
        else: oCur.execute('CREATE TABLE moz_cookies (id INTEGER PRIMARY KEY, originAttributes TEXT NOT NULL DEFAULT "", name TEXT, value TEXT, host TEXT, path TEXT, expiry INTEGER, lastAccessed INTEGER, creationTime INTEGER, isSecure INTEGER, isHttpOnly INTEGER, inBrowserElement INTEGER DEFAULT 0, sameSite INTEGER DEFAULT 0, rawSameSite INTEGER DEFAULT 0, schemeMap INTEGER DEFAULT 0, isPartitionedAttributeSet INTEGER DEFAULT 0);')
    return oCur, oConn

def addCookieFromChrome(oCur, boolOldfirefox, iID, sName, sValue, sDomain, sPath, iCreation, iExpiry, iSecure, iHTTPOnly):
    ## Expiry and creation timestamps for Chrome/Edge: {timeStamp} / 1000000 - 11644473600 in seconds
    ##  Expiry, LastAccessed and Creation timestamps for Firefox (destination): epoch in seconds, epoch micros and epoch in micros
    #if not iExpiry: iExpiry = int(time.time() + 31582861) ## Now + 1 Year, in seconds
    iCreationTime = int(int(iCreation) / 1000000 - 11644473600)*1000000
    iLastAccessed = iCreationTime
    iExpiry = int(time.time() + 31582861) ## Now + 1 Year, in seconds
    sBaseDomain = sDomain.split('.')[-2] + '.' + sDomain.split('.')[-1]
    ##  Format for Firefox 51.0 (32-bit) Portable (pre 67)
    ## id, baseDomain, '', name, value, host, path, expiry, lastaccessed, creation, secure, httponly, 0, 0
    if boolOldfirefox: oCur.execute('INSERT INTO moz_cookies VALUES({},\'{}\',"",\'{}\',\'{}\',\'{}\',\'{}\',{},{},{},{},{},0,0);'.format(iID, sBaseDomain, sName.replace('\'','"'), sValue.replace('\'','"'), sDomain, sPath, iExpiry, iLastAccessed, iCreationTime, iSecure, iHTTPOnly))
    ## Format for Firefox 100.0 (64-bit) (post 67)
    ## id, '', name, value, host, path, expiry, lastaccessed, creation, secure, httponly, 0, 0, 0, 0
    else: oCur.execute('INSERT INTO moz_cookies VALUES({},"",\'{}\',\'{}\',\'{}\',\'{}\',{},{},{},{},{},0,0,0,0,0);'.format(iID, sName.replace('\'','"'), sValue.replace('\'','"'), sDomain, sPath, iExpiry, iLastAccessed, iCreationTime, iSecure, iHTTPOnly))
    return

def printCookies(oCur, sDomain = None):
    if sDomain: oCur.execute('SELECT * FROM moz_cookies WHERE host=?', (sDomain,))
    else: oCur.execute('SELECT * FROM moz_cookies')
    print('id, baseDomain, originAttributes, name, value, host, path, expiry, lastAccessed, creationTime, isSecure, isHttpOnly, appId, inBrowserElement')
    for sData in oCur.fetchall(): print(sData)
    return

if __name__ == '__main__':
    usage = (
        'This script parses Chrome/Edge/Opera exported cookies and turns them into a Firefox \'cookies.lite\' file\n'
        'It suffices to put cookies.lite in its own folder and start \'firefox -new-instance -profile "folder"\'')
    
    parser = optparse.OptionParser(usage=usage)
    parser.add_option('--cookiefile', '-c', metavar='FILE', dest='cookiefile', default='cookie-import.txt', help='File containing exported cookies')
    parser.add_option('--oldfirefox', dest='oldfirefox', default=False, action='store_true', help='Specify if destination Firefox version predates v67')
    parser.add_option('--newfile', '-n', metavar='FILE', dest='newfile', help='Specify new filename, default=random filename')
    parser.add_option('--startbrowser', '-s', metavar='BINARY', dest='startbrowser', help='When specified, specified Firefox is started with new cookie file. (Just type \'firefox\' on Unix)')
    
    (options, args) = parser.parse_args()

    check_parameters(options)

    boolOldfirefox = True if options.oldfirefox else False

    if options.newfile: sFilename = options.newfile
    else: sFilename = ''.join(random.choice(string.ascii_lowercase) for i in range(8)) + '.sqlite'

    print('[+] Creating new SQLite database: {}'.format(sFilename))
    oCur, oConn = newConnection(sFilename, boolOldfirefox)

    print('[+] Using Chrome/Edge/Opera source file: {}'.format(options.cookiefile))
    ## print('name|value|host_key|path|is_secure|is_httponly|creation_utc|expires_utc')
    iCount = 1
    for sLine in open(options.cookiefile).readlines():
        if sLine.startswith('name;value'): continue
        lstData = sLine.split(';')
        ## oCur, boolOldfirefox, iID, sName, sValue, sDomain, sPath, iCreation, iExpiry, iSecure, iHTTPOnly
        addCookieFromChrome(oCur, boolOldfirefox, iCount, lstData[0], lstData[1], lstData[2], lstData[3], lstData[6], 0, lstData[4], lstData[5])
        iCount += 1
    print('[+] Converted {} cookies'.format(iCount))
    ## printCookies(oCur)
    oConn.commit()
    oConn.close()

    if not options.startbrowser:
        print('[+] File {} created, now go forth and close Firefox'.format(sFilename))
        print('     place it inside Firefox > Data > profile > \'cookies.sqlite\' and relaunch Firefox')
    else:
        sNewProfile = ''.join(random.choice(string.ascii_lowercase) for i in range(8)) + '-Profile'
        print('[+] Creating profile folder {}'.format(sNewProfile))
        os.mkdir(sNewProfile)
        ## On Linux/Kali the cookies file can be copied before first boot
        if os.name =='nt': os.system('copy {} {}\\cookies.sqlite 2> null'.format(sFilename, sNewProfile))
        else: os.system('cp {} {}/cookies.sqlite'.format(sFilename, sNewProfile))
        print('[+] Launching "{}" -new-instance -profile {}'.format(options.startbrowser, sNewProfile))
        os.system('"{}" -new-instance -profile {}'.format(options.startbrowser, sNewProfile))
