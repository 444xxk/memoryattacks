#include <string.h>
#include <stdlib.h>
#include <stdio.h>

int main(int argc, char *argv[])
{
  char *buf1 = malloc(128);
  char *buf2 = malloc(256);

  read(fileno(stdin), buf1, 200);

  free(buf2);
  free(buf1);
}

