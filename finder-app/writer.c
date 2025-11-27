#include <stdio.h>
#include <string.h>
#include <syslog.h>

int main(int argc, char *argv[]) {
  openlog(NULL, 0, LOG_USER);
  if(argc != 3) {
    syslog(LOG_ERR, "Incorrect number of arguments %d", argc);
    printf("Incorrect number of arguments %d\n", argc);
    printf("writer <writefile> <writestr>\n");
    return 1;
  }

  FILE* f = fopen(argv[1], "w");
  if(f == NULL) {
    syslog(LOG_ERR, "Could not open file %s", argv[1]);
    perror("Could not open file");
    return 1;
  }

  if(fwrite(argv[2], sizeof(char), strlen(argv[2]), f) == 0) {
    syslog(LOG_ERR, "Could not write %s to file %s", argv[2], argv[1]);
    perror("Could not write file");
    fclose(f);
    return 1;
  }

  if(fclose(f) != 0) {
    syslog(LOG_ERR, "Could not close file %s", argv[1]);
    perror("Could not close file");
    return 1;
  }

  syslog(LOG_DEBUG, "Writing %s to %s", argv[2], argv[1]);
  return 0;
}


















//if [ $# -ne 2 ]; then
//  echo "Wrong args"
//  exit 1
//fi

//writefile=$1
//writestr=$2

//mkdir -p $(dirname ${writefile})
//echo "${writestr}" > ${writefile}

