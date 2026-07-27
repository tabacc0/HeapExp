Notes : 
- the _patched is generated with `pwninit` , the only difference is that it used the in-directory libc an not the system one.
- `libc.so.6` is just a symlink to `libc.so` which is libc-2.29
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- the ld here is not provided by the challenge , i found a compatible one , shouldn't make a difference
- source code for the used libc version's malloc is in `malloc.c`

