# Assembly Golf Cheatsheet

## x86_64 Assembly Basics

### Registers
| Register | Purpose | Example |
|----------|---------|---------|
| rax | Syscall number / return value | `mov rax, 1` |
| rdi | 1st argument | `mov rdi, 1` |
| rsi | 2nd argument | `mov rsi, msg` |
| rdx | 3rd argument | `mov rdx, 2` |
| eax | 32-bit version of rax | `mov eax, 42` |

### Common Instructions
| Instruction | What it does | Example |
|-------------|--------------|---------|
| mov | Move data | `mov rax, 1` |
| ret | Return from function | `ret` |
| syscall | Make system call | `syscall` |
| lea | Load address | `lea rsi, [msg]` |
| xor | Exclusive OR (zeroing) | `xor edi, edi` |

### Common Syscalls
| Number | Name | Purpose |
|--------|------|---------|
| 0 | read | Read from file |
| 1 | write | Write to file/stdout |
| 2 | open | Open a file |
| 3 | close | Close a file |
| 60 | exit | Exit program |

### Quick Examples

**Return 42 (Level 1):**
```asm
mov eax, 42    ; Put 42 in eax
ret            ; Return
Print "hi" (Level 2):

asm
mov rax, 1     ; write syscall
mov rdi, 1     ; stdout
lea rsi, [msg] ; pointer to message
mov rdx, 2     ; length
syscall        ; make the call
mov eax, 60    ; exit syscall
xor edi, edi   ; exit code 0
syscall

section .data
msg: db 'hi'
Tips for Beginners
Start simple — Level 1 only needs 2 instructions

Copy the template — Don't try to write from scratch

Understand each line — Know what every instruction does

Use 'hint' — When stuck, ask for help

Check your work — Always verify the output

Why This Matters for Banking Security
Malware analysis — Understanding assembly helps identify malicious code

Exploit development — Know how attacks work to defend against them

Binary verification — Confirm executables do what they claim

Supply chain security — Spot tampered binaries
