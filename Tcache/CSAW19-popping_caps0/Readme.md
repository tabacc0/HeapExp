Notes : 
- the _patched is generated with `pwninit` , the only difference is that it used the in-directory libc an not the system one.
- `libc.so.6` is libc-2.27
- the program isn't stripped of symbols , so just load it in ida or the decompiter of your choice
- the ld here is not provided by the challenge , pwninit downloaded a compatible one
- source code for the used libc version's malloc is in `malloc.c`

