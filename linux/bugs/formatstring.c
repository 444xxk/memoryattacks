#include <stdio.h>
#include <unistd.h>
#include <stdlib.h> 

void f(char *buf) {
  printf(buf);
  exit(0);
}

int main() {
  char buf[1024];
  scanf("%1024s", buf);
  f(buf);
  return 0;
}



