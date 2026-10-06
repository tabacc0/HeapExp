# HeapExp
### a collection of my solution to various ctf heap challenges .
- currently most of the challenges are the ones listed in : https://github.com/shellphish/how2heap i also follow their technique classification.

## The premise
- The way I do these challenges is for each technique , I only read what mechanism in libc it targets and then I read the source code of malloc.c (or related) and I try to figure out the exploitation path myself , so the repo is a little bit slow paced , and the comments in the exploits may not always be super clear because I am usually figuring things out in the process of writing them.
## want to follow along ?
- Each challenge directory has all the necessary files to approach the challenge except libc symbol files for comfortable debugging , which i will be packagin soon enough , please approach the challenges and wrestle withthem as I usually assume familiarity with the challenge and the symbol names in the reverse engineered IDA files (.64) in case of stripped binaries in exploit comments , I also sometimes assume knowledge of some libc internals , but if you take the effort to learn general libc internals and tackle the program first , the exploits might be helpfull if you are figuring things out on your own  too , good luck !.

## Note
- Please know that while I try to keep things organized by attack type , challenges often require chaining multiple attacks together , such as house of Tangerine the includes a tcahe poisoning etc , so don't go into a directory expecting a challenge that is ONLY about the technique in the title , rather expect varying degrees of surprise and complexity , please enjoy and keep hacking !.

