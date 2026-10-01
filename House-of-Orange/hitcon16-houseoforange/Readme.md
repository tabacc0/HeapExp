Notes : 
- this challenge is not the original  , the _aaddaadd version is patched to cirmumvent hardened kernels restriction , see the exploit comments for more.
- the houseoforange binary is the original though not used by the exploit
- `libc.so.6` is `libc 2.23`
- feel free to take a look at the `.i64` for a reverse engineered version of the challenge.
- source code for the used libc version's malloc is in malloc.c 
- source code for the used libc version's file operations is in genops.c 
- the custom exploit should also work on non-hardened kernel , wich a higher success rate
- compile and run break_test to see if the program break in your kernel is aligned , it will print the initial break in each run , one non-alinged break is enough since in non-herdened the program break is ALWAYS page-aligned.
