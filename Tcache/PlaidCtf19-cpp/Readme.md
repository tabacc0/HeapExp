Notes : 
- the _patched is generated with `pwninit` , its rpath points to the current directory , 
- libgcc and libstdc++ both have patched rpath as well , the depend on libm and if not patched they use the system one
- they are configured for my system , use the setup.sh in this dir to set them up ,or use patchelf yourself, beware the binary won't work outside the directory .
- `libc.so.6` is just a symlink to `libc.so` which is libc-2.27
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- the ld here is not provided by the challenge , i found a compatible one , shouldn't make a difference
- source code for the used libc version's malloc is in `malloc.c`

