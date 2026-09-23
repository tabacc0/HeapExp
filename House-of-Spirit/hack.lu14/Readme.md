Notes : 
- the _patched is generated with `pwninit` , the only difference is that it used the in-directory libc an not the system one.
- `libc.so.6` is `libc 2.23`
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- source code for the used libc version's malloc is in malloc.c 
- due to issues between pwntools and libc's buffering ,I had to tinker with I/O int he exploit (stdin=PIPE), due to that change, the shell might act weirdly at first , if that happends make sure to execute 'sh' first , that should make it usable
