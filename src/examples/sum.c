#include <stdio.h>
#include <syscall.h>
#include<stdlib.h>
int
main (int argc, char *argv[])
{
	int a[4];
	a[0]=atoi(argv[1]);
	a[1]=atoi(argv[2]);
	a[2]=atoi(argv[3]);
	a[3]=atoi(argv[4]);
	printf("%d %d\n",pibonacci(a[0]),sum_of_four_integers(a[0],a[1],a[2],a[3]));
}
