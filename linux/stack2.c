#include <string.h>
#include <stdio.h>
#include <unistd.h>

int main (int argc, char **argv){

char buf [1024];
int r;
int z; 

z = 2;
r = read(0, buf, 2048);
printf("\nRead %d bytes. buf is %s\n", r, buf);
puts("Bypass ASLR godamn bitch id; suck love it;");

if(z<1) {

system("/bin/false");
}
}

