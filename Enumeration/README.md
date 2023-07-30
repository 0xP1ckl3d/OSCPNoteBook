# Enumeration
This section of the OSCPNoteBook contains a collection of Enumeration techniques, and initial enumeration for various common services.

## Table of Contents

- [Scanning](#Scanning)
- [HTTP](#HTTP)
- [FTP](#FTP)
- [SMTP](#SMTP)
- [POP3](#POP3)
- [RPC](#RPC)
- [SMB](#SMB)
- [SNMP](#SNMP)
- [LDAP](#LDAP)

# Scanning
**AutoRecon**  
Auto recon (Run in background while doing other stuff. Auto-enumerates found services with other tools. Indexes all results into files)  
[AutoRecon GitHub](https://github.com/Tib3rius/AutoRecon)
```    
sudo autorecon --nmap-append -sS 192.168.126.44 --accessible -v`
```
**nmap**
**TCP**
* **Initial Scan** (top 1000 ports) + basic service, scripts and OS identification:
```
sudo nmap -sCSV -T4 10.11.1.220 -v -O`
```
* **Scan of all ports**:
```
 sudo nmap -sCSV -T4 10.11.1.220 -v -O -p-`
```
**UDP**:
** **Top Ports**:
```
sudo nmap -sU --top-ports=50 -sV 10.11.1.220 --open`
```
* **Full Scan**:
```
sudo unicornscan -r300 -mU 10.11.1.220`
```
**Script Scans**:

* **SMB (139/445)**:
```
nmap --script "smb-vuln*" 10.11.1.220 -p 139,445 >> nmap --script "smb-enum*" 10.11.1.220 -p 139,445`
```
* **SMTP (25,465,587)**:
```
nmap -p25 --script smtp-commands 10.10.10.10 >> nmap -p25 --script smtp-open-relay 10.10.10.10 -v`
```
**Banner Grabbing**:
```
nc -vn 10.11.1.220 25
```
**NMAP through Proxychains**:
* Load an nmap binary to the intermediary and perform quick, basic scans (no scripts or service) with:
```
./nmap -p- 10.11.1.220 -p-
```
* Once the open ports are identified, perform nmap through proxychains with:
```
sudo proxychains sudo nmap -sCTV -T4 10.11.1.220 -v -O -p 80,21,139,445`
```

# HTTP
* ports 80,443,8080,9090, etc.
* [Pentesting Web](https://book.hacktricks.xyz/network-services-pentesting/pentesting-web)
## Identify Web Technologies
```
whatweb -a 1 http://10.10.10.10 #Stealth 
whatweb -a 3 http://10.10.10.10 #Aggressive 
webtech -u http://10.10.10.10 
webanalyze -host http://10.10.10.10 -crawl 2
```
## Directory Busting
* **Wordlists**:
```
/usr/share/seclists/Discovery/Web-Content/raft-large-directories-lowercase.txt
/usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt
/usr/share/seclists/Discovery/Web-Content/RobotsDisallowed/top10000.txt
/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
/usr/share/wordlists/dirb/common.txt
/usr/share/wordlists/dirb/big.txt
/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt
```
* **Feroxbuster**:
```
feroxbuster -u http://10.10.10.10 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
        *   `-w` > wordlist
        *   `-u` > url
        *   `-s` > Status codes to include
        *   `-S` > Filter out messages of a particular size
        *   `-r` > follow redirects
        *   `-x` > search extensions
        *   `-E` > automatically collect extensions and add them to the extension list
        *   `--burp` > sets proxy for burp and disables TLS cert validation
        *   `-e` > extracts links from response body
        *   `-d` > max recursion depth (default 4)
        *   `-n` > no recursion
        *   `-t` > threads (default 50)
        *   `-g` > collect important words from responses and add them to wordlist
        *   `-I` > exclude collection of files
        *   `-o` > nominate a file to direct output
        *   `-H` > specify http headers to be used in request
        *   `-b` > cookies
        *   `--dont-scan` > identify directories not to recursively scan into

**Note** - If we cancel the scan with ctrl-c it will save the scans state to a file and can be continued by running:
```
feroxbuster --resume-from <state_file>
```
* **gobuster**:
```
gobuster dir -u http://10.11.1.234/ -t 40 -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt
```
* **wfuzz**:
```
wfuzz -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt https://domain.com/api/FUZZ
```
* **ffuf**:
```
ffuf -c -w /usr/share/wordlists/dirb/big.txt -u http://10.10.10.10/FUZZ
```
## Subdomain fuzzing
```
gobuster vhost -u http://10.10.10.10 -t 30 -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt
wfuzz -H "Host: FUZZ.10.10.10.10" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt --hh 290 --hc 302 http://10.10.10.10
ffuf -c -u http://10.10.10.10 -H "Host: FUZZ.10.10.10.10" -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -mc 200
```
## Vuln Scanning
```
nikto -host=http://10.10.10.10 >> whatweb -a 4 http://10.10.10.10 #Automaitc scanner`
```
## WordPress Scanning:
```
wpscan --api-token <INSERT_TOKEN> -e vp,vt,dbe -t 10 --url sandbox.local >> wpscan --url 10.10.10.10 -e vt,vp --api-token <INSERT_TOKEN>
```
## Password Spraying
```
hydra 10.1.1.68 http-form-post "/login:username=^USER^&password=^PASS^:Login was unsuccessful." -l "admin" -P /usr/share/wordlists/rockyou.txt -vV -fv -I
wpscan --url http://10.11.1.234/ --passwords /usr/share/wordlists/rockyou.txt --usernames admin,Core,backup
```
## Generate wordlist from webpage
```
cewl -m 4 -w cewlindex.txt 10.11.1.3
```
*   `-m` - minimum word length
**Expand wordlist by applying rules from john.conf**:
```
john --wordlist=cewlindex.txt --rules --stdout > cewlindexrules.txt
```
## Poking Around
*   Remember to check out the following extensions on web pages:
```
/robots.txt
/sitemap.xml
/crossdomain.xml
/clientaccesspolicy.xml
/.well-known/
```
*   Remember to view source code for comments or unusual hardcoded creds, etc.
*   When scripts are found, look for backups. for example:
```
file.php.bak
file.php.tmp
file.php.old
```
* Test input fields for injection vulns.

# FTP
* Ports 21, 2121
## Interacting with FTP
* **Download all recursively**:
```
wget -r ftp://user:pass@server.com/
```
* **When accessing an FTP server**:
```
ftp anonymous@<ip> -P 21 
ls 
put file.txt 
get file.txt
```
**Note**: if we get a response of entering passive mode, it can be disabled by starting the ftp connection again and sending the command:
```
ftp> passive
```
**Set FTP to binary** to ensure binary files transferred correctly:
```
ftp> binary
```
## Anonymous login
```
anonymous:anonymous
anonymous:
ftp:ftp
user:`
```
## Brute Force anonymous logins
```
nmap --script ftp-brute -p 21 10.10.10.10
hydra -l admin -P /usr/share/metasploit-framework/data/wordlists/unix_passwords.txt ftp://10.10.10.10 -V
```
*   In Hyra, use `-L` for users text file

# SMTP
Ports: 25,465,587
## Connect
ENUM 
```
nmap -p25 --script smtp-commands 10.10.10.10 >> nmap -p25 --script smtp-open-relay 10.10.10.10 -v
```
## NTLM Disclosure
```
nmap -p25 --script smtp-ntlm-info 10.10.10.10
```
## User ENUM 
```
smtp-user-enum -M <MODE> -u <USER> -t <IP>
```
Modes: VRFY, AUTH
```
nmap --script smtp-enum-users <IP>
``` 

## Send Email
```
sendEmail -t lhale@victim -f rmurray@victim -s 192.168.192.55 -u "job application" -m "http://192.168.119.192"
``` 
*   **More**: [Pentesting SMTP](https://book.hacktricks.xyz/network-services-pentesting/pentesting-smtp)
    
*   **Commands**:
```
HELO smtp.<ip>
EHLO
MAIL FROM
RCPT TO
SIZE
DATA
VRFY
TURN
AUTH
RSET
EXPN
HELP
QUIT
```

# POP3

* Ports 110, 995
## With known credentials:
* Interact with POP3:
```
telnet [target] 110
USER [username]
PASS [pass]
LIST # list all messages
RETR [message no.] # retrieve email
```

# RPC
* Ports 115, 135
## Enumerate RPC
```
impacket-rpcdump # map rpc endpoints
rpcinfo -p [target] # enum NFS shares 
showmount -e [ target IP ] # show mountable directories 
mount -t nfs [target IP]:/ /mnt -o nolock  # mount remote share to your local machine
df -k # show mounted file systems
```
## Interact with RPC:
```
rpcclient -U "" [target]  // null session 
rpcclient -U "" -N [target] 
rpcclient> srvinfo 
rpcclient> enumdomains 
rpcclient> querydominfo 
rpcclient> enumdomusers 
rpcclient> enumdomgroups 
rpcclient> getdompwinfo
```
## Follow up enum
```
rpcclient> querygroup 0x200
rpcclient> querygroupmem 0x200
rpcclient> queryuser 0x3601
rpcclient> getusrdompwinfo 0x3601
```

# SMB
* Ports 139, 445
## NMAP
```
nmap --script "smb-vuln*" -p 445,139 10.11.1.123
nmap --script "safe or smb-enum-*" -p 445,139 10.11.1.123
````
## Samba (LINUX SMB) \[139 TCP\]
* Check Samba service version:
  * Samba <2.2.8 versions are vulnerable to RCE.
  * Samba 3.5.11/3.6.3 versions are vulnerable to RCE.
## SMB (WINDOWS SMB) \[139, 445 TCP\]
**Fully Automated**
```
sudo apt install smbclient python3-ldap3 python3-yaml python3-impacket
```
Download [enum4linux-ng](https://github.com/cddmp/enum4linux-ng), place in `/usr/bin` and make executable:
```
enum4linux-ng 10.10.10.10
```
**Manual**:
```
nmblookup -A 10.10.10.10
smbclient -L //10.10.10.10  // null session
enum4linux 10.10.10.10  // null session
nbtscan 10.10.10.10
smbclient --no-pass -L //10.10.10.10  //list shares
smbclient --no-pass \\\\[target]\\[share]   //connect to a share
smbmap -u "guest" -R [share] -H 10.10.10.10  //recursively list files in a folder
smbget -R smb://10.10.10.10/share  //recursively get files from target share/dir
sudo nmap --script smb-vuln-* 10.10.10.10
```
## Eternal Blue
```
git clone https://github.com/REPTILEHAUS/Eternal-Blue.git
cd Eternal-Blue
wget https://raw.githubusercontent.com/worawit/MS17-010/master/mysmb.py
source ~/opt/impacket/impacket-venv/bin/activate
python2 checker.py 10.10.10.10
```
## SMB Brute Force
```
hydra -V -f -l [username] -P [/path/to/wordlist] smb # smb brute-force
```
## Crackmapexec
[Pentesting with Crackmapexec](https://cheatsheet.haax.fr/windows-systems/exploitation/crackmapexec/)
Identify computer users:
```
crackmapexec smb 10.1.1.68 -u "anonymous" -p "" --users
```
Brute Force
```
crackmapexec smb 10.1.1.68 -u "steph" -p /usr/share/wordlists/rockyou.txt
crackmapexec ssh 10.1.1.68 -u users.txt -p /usr/share/wordlists/rockyou.txt
```

# SNMP
* UDP Port 161
## Enumerate SNMP
```
onesixtyone 10.10.10.10 -c /usr/share/seclists/Discovery/SNMP/common-snmp-community-strings.txt
```
*   When SNMP is identified as active on a machine, use `snmpwalk` to enumerate SNMP:
```
snmpwalk -c public -v1 -t 10 10.10.10.10
```
## Enumerating Windows Users
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.4.1.77.1.2.25
```
## Enumerating Windows Processes
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.4.2.1.2
```
## Enumerating Open TCP Ports
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.6.13.1.3
```
## Enumerating Installed Software
```
snmpwalk -c public -v1 10.10.10.10 1.3.6.1.2.1.25.6.3.1.2`
```

# LDAP
* Ports 389, 636, 3268, 3269
## WindapSearch
[WindapSearch GitHub](https://github.com/ropnop/windapsearch)
Get computers
```
python3 windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --computers
```
Get groups 
```
python3 windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --groups 
```
Get users 
```
python3 windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --da
```
Get Domain Admins 
```
python3 windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --da
```
Get Privileged Users 
```
python3 windapsearch.py --dc-ip 10.10.10.10 -u john@domain.local -p password --privileged
```
## ldapsearch
```
ldapsearch -x -h 10.10.10.10 -p 389 -b "dc=domain,dc=local" -D "cn=john,cn=Users,dc=domain,dc=local" -w password  # With Credentials
ldapsearch -x -H ldap://10.10.10.10 -b "DC=xor,DC=com"  # No Credentials
#Extract all 
ldapsearch -x -H ldap://<IP> -D '<DOMAIN>\<username>' -w '<password>' -b "DC=<1_SUBDOMAIN>,DC=<TLD>"
```
`-x` Simple Authentication
`-H` LDAP Server
`-D` My User
`-w` My password
`-b` Base site, all data from here will be given
