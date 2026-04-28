Notes : 
- the _patched is generated with `pwninit` , the only difference is that it used the in-directory libc an not the system one.
- `libc.so.6` is just a symlink to `libc-2.23.so`
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- source code for the used libc version's malloc is in `libc-2.23-source`

