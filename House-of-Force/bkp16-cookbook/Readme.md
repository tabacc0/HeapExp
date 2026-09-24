Notes : 
- the _patched is generated with `pwninit` , the only difference is that it used the in-directory libc an not the system one.
- `libc.so.6` is a symlink to `libc 2.24`
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- source code for the used libc version's malloc is in malloc.c 
- I ough to note that reversing this fully was the most fun part.
