# DIANA Windows Credential Toolkit

It's a Work-In-Progress, so feel free to create some issues  
Please see "How to Use" and ask questions.  

Background: https://www.insecurity.be/blog/2020/12/24/dpapi-in-depth-with-tooling-standalone-dpapi/

## How to install
Prerequisites:  
```
sudo apt update && sudo apt install -y python3-pip git  
python3 -m pip install dpapick3 jwt termcolor
```

The DPAPI bulk of the work is done by DPAPICK3 (https://pypi.org/project/dpapick3/)

Installing permanently (Linux):  
```
git clone https://github.com/tijldeneut/diana  
cd diana  
sudo python3 -m pip install -r requirements.txt --break-system-packages
sudo cp -rp *.py /usr/bin/
```

Oneliner for Linux:  
```
git clone https://github.com/tijldeneut/diana && cd diana && sudo python3 -m pip install -r requirements.txt --break-system-packages && sudo cp -rp *.py /usr/bin/ && cd .. && sudo rm -rf diana
```

Installation (Windows):  
First install the latest version of Python3.  
```
powershell iwr https://github.com/tijldeneut/diana/archive/refs/heads/main.zip -O diana.zip  
powershell expand-archive diana.zip  
cd diana\diana-main  
python -m pip install -r requirements.txt
```

Feel free to add the current path to the Windows Path environment variable for global use.

## How to use

Just run **diana.py** for a quick overview of the scripts and what they do.
Please consider that this is a *work-in-progress*, so don't expect that everything
will work: there is some messy stuff here.  

In any case feel free to open a bug or a request. Any contribution is much 
appreciated.  

- **diana-dpapimkdec.py**: Works on DPAPI MasterKeys: parsing, exports Hashcat hashes and decrypts them when provided with right details
- **diana-dpapiblobdec.py**: Works on *system* or *user* DPAPI BLOB files: parsing and/or decrypting using decrypted MasterKey or files
- **diana-vaultdec.py**: Decrypt secrets in VAULT vcrd files, both SYSTEM and USER based
- **diana-creddec.py**: Decrypt credentials in CREDENTIAL files, both SYSTEM and USER based
- **diana-browserdec.py**: Decrypt passwords and cookies from all Chromium based browsers (Chrome, Edge, Opera ...)
- **diana-browserdec-ng.py**: Decrypt passwords and cookies from all Chromium based browsers (Chrome, Edge, Opera ...), extra features: color, decrypting Notes and listing deleted Logins
- **diana-wifidec.py**: Decrypt Windows Wi-Fi profiles, including passwords, SYSTEM based
- **diana-wifipeapdec.py**: Decrypt Windows Wi-Fi Enterprise profiles, requires SYSTEM & USER data
- **diana-openvpndec.py**: Decrypt OpenVPN saved Private Key passphrases
- **diana-mobaxtermdec.py**: Decrypt MobaXterm sessions (confCons.xml), without needing the master password
- **diana-msoutlookdec.py**: Decrypt MS Outlook accounts from registry, IMAP accounts only
- **diana-msrdcmandec.py**: Decrypt Microsoft Remote Desktop Connection Manager sessions
- **diana-keepassdec.py**: Decrypt Keepass ProtectedUserKey.bin key, use with [CQDPAPIKeePassDBDecryptor.exe](https://cqureacademy.com/blog/windows-internals/black-hat) to decrypt some KDBX files
- **diana-workstationdec.py**: Decrypt VMware Workstation vSphere/ESXi login credentials

## NGC Usage

- **diana-ngcparse.py**: parses the Windows Ngc folder and files:  
  ``\Windows\ServiceProfiles\LocalService\AppData\Local\Microsoft\Ngc``  
  On a live system, this requires SYSTEM privileges
- **diana-ngcvaultdec.py**: similar to ***vaultdec.py*** but adds a parsing layer for NGC specific data
- **diana-ngcregistrydec.py**: parses the ``SOFTWARE`` to parse the NgcPin data, same result as ngcvaultdec  
Successful output is ***EncData***, ***IV*** and ***EncPassword***
- **diana-ngccryptokeysdec.py**: parses and decrypts the RSA/ECDS keys in  
``\Windows\ServiceProfiles\LocalService\AppData\Roaming\Microsoft\Crypto\Keys``  
using the System MasterKey.  
Also implements ***ncrypt.dll*** functionality to decrypt the Private Keys using a PIN, brute force PINs or export their hash
- **diana-ngcpinpassdec.py**: Meta-script to call other NGC scripts and perform automatic PIN and password decryption

## Licensing and Copyright

Copyright 2023 Tijl "Photubias" Deneut. All Rights Reserved.

This program is free software; you can redistribute it and/or
modify it under the terms of the GNU General Public License
as published by the Free Software Foundation; either version 2
of the License, or (at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program; if not, write to the Free Software
Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
02111-1307, USA.

## Bugs and Support

There is no support provided with this software. There is NO
warranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

For any bug or enhancement please use this site facilities.
