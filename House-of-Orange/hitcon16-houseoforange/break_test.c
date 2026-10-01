#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

int main(){
	void *initial_break = sbrk(0);
	printf("initial break = 0x%x\n",initial_break);
	exit(0);
}
