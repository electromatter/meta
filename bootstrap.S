.text
.global fixture_bootstrap
fixture_bootstrap:
// Save page pointers
mov %rdi, %r12
mov %rsi, %r13
mov %rdx, %r14

// Sort page pointers
cmp %r12, %r13
ja 3f
xchg %r12, %r13
3: cmp %r12, %r14
ja 3f
xchg %r12, %r14
3: cmp %r13, %r14
ja 3f
xchg %r13, %r14

// Unmap [0, page0)
3: mov $11, %rax
xor %rdi, %rdi
mov %r12, %rsi
syscall
test %rax, %rax
jnz 1f

// Unmap (page0, page1)
mov $11, %rax
mov %r12, %rdi
add $4096, %rdi
mov %r13, %rsi
sub %rdi, %rsi
jz 3f
syscall
test %rax, %rax
jnz 1f

// Unmap (page1, page2)
3: mov $11, %rax
mov %r13, %rdi
add $4096, %rdi
mov %r14, %rsi
sub %rdi, %rsi
jz 3f
syscall
test %rax, %rax
jnz 1f

// Unmap (page2, hole)
3: mov $11,%rax
mov %r14, %rdi
add $0x1000, %rdi
mov $0x7ffffffff000, %rsi
sub %rdi, %rsi
syscall
test %rax, %rax
jnz 1f

// Enable seccomp
mov $157,%rax
mov $22,%rdi
mov $1,%rsi
xor %rdx,%rdx
xor %r10,%r10
xor %r9,%r9
syscall
test %rax,%rax
jnz 1f

// Trap
trap:
int3

// Abort
1: mov $39, %rax
syscall
mov %rax, %rdi
mov $62, %rax
mov $6, %rsi
syscall
2: ud2
jmp 2b
