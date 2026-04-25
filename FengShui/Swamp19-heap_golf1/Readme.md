
#Solution
- take a look at the decompilation and play with this before reading this solution , I only explain the strategy here
- this can be exploited manually , the idea is really simple :
    1. send 32 as the size of the first chunk
    2. free -2, now strarray[0] is the last chunk we allocated and the original `target` is unclaimed
    3. allocate 3 buffer of size larger than 0x20 so `target` remains unclaimed 
    4. finally allocate the fouth buffer with 32 as the size , you claim `target` , and the program writes 4 to it (since it is the fourth buffer) , the check succeeds and you get the flag
- so basically just send these values progressively to the program : 32 then -2 then 100 then 100 then 100 then 32 , easy.

