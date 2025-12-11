#include <netdb.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <unistd.h>

#define RECV_BUFFER_CHUNK 100

int closeAppRequest = 0;

int createSocket(int* socketfd) {
  *socketfd = socket(AF_INET, SOCK_STREAM, 0);
  if(*socketfd == -1) {
    perror("Could not create socket");
    return -1;
  }

  const int enable = 1;
  if(setsockopt(*socketfd, SOL_SOCKET, SO_REUSEADDR, &enable, sizeof(int)) == -1) {
    perror("Could not configure socket");
    return -1;
  }

  struct addrinfo hints = { 0 };
  hints.ai_flags = AI_PASSIVE;
  hints.ai_family = AF_INET;
  hints.ai_socktype = SOCK_STREAM;

  struct addrinfo* addr;
  int ret = getaddrinfo(NULL, "9000", &hints, &addr);
  if(ret != 0) {
    printf("Could not get addr info %s\n", gai_strerror(ret));
    return -1;
  }

  ret = bind(*socketfd, addr->ai_addr, sizeof(struct sockaddr));
  freeaddrinfo(addr);
  if(ret != 0) {
    perror("Could not bind socket");
    return -1;
  }

  return 0;
}

int connectionPrepare(int sockfd) {
  int ret = listen(sockfd, 0);
  if(ret == -1) {
    perror("Listening socket failed");
    return -1;
  }

  return 0;
}

int connectionWait(int sockfd, struct sockaddr* addr) {
  socklen_t addrlen = 0;
  int acceptedfd = accept(sockfd, addr, &addrlen);
  if(acceptedfd == -1)
    perror("Accepting connection failed");
  else {
    char msg[128];
    int msglen = snprintf(msg, sizeof(msg), "Accepted connection from");
    for(int i = 0; i < sizeof(addr->sa_data); i++)
      msglen += snprintf(msg + msglen, sizeof(msg) - msglen, " %d", addr->sa_data[i]);
    syslog(LOG_DEBUG, "%s", msg);
  }
  return acceptedfd;
}

int receiveData(int socketfd, char** buf, size_t* datalen) {
  size_t buflen = RECV_BUFFER_CHUNK;
  *datalen = 0;
  *buf = calloc(buflen, sizeof(char));

  int ret = recv(socketfd, *buf, buflen, 0);
  if(ret < 0) {
    perror("Data reception failed");
    return -1;
  }
  *datalen += ret;
  while(ret == RECV_BUFFER_CHUNK && (*buf)[*datalen - 1] != '\n') {
    char* oldbuf = *buf;
    buflen += RECV_BUFFER_CHUNK;
    *buf = calloc(buflen, sizeof(char));
    memcpy(*buf, oldbuf, buflen - RECV_BUFFER_CHUNK);
    free(oldbuf);
    ret = recv(socketfd, (*buf) + buflen - RECV_BUFFER_CHUNK, RECV_BUFFER_CHUNK, 0);
    if(ret < 0) {
      perror("Data reception failed");
      return -1;
    }
    *datalen += ret;
  }

  return 0;
}

void deleteDataFile() {
  remove("/var/tmp/aesdsocketdata");
}

int saveData(char* data, size_t datalen) {
  FILE* f = fopen("/var/tmp/aesdsocketdata", "a");
  if(f == NULL) {
    perror("Could not open file");
    return -1;
  }

  if(fwrite(data, sizeof(char), datalen, f) == 0) {
    perror("Could not write file");
    fclose(f);
    return -1;
  }

  if(fclose(f) != 0) {
    perror("Could not close file");
    return -1;
  }

  return 0;
}

int returnData(int socketfd) {
  FILE* f = fopen("/var/tmp/aesdsocketdata", "r");
  if(f == NULL) {
    perror("Could not open file");
    return -1;
  }

  char data[RECV_BUFFER_CHUNK] = { 0 };
  int ret = 0;
  do {
    ret = fread(data, sizeof(char), RECV_BUFFER_CHUNK, f);
    if(ret > 0) {
      if(send(socketfd, data, ret, 0) == -1) {
        perror("Sending data failed");
        return -1;
      }
    }
  } while(ret == RECV_BUFFER_CHUNK);

  if(fclose(f) != 0) {
    perror("Could not close file");
    return -1;
  }

  return 0;
}
void signalHandler(int signum) {
  syslog(LOG_DEBUG, "Caught signal, exiting");
  closeAppRequest = 1;
}

int registerSignalHandler(void) {
  struct sigaction sa = { 0 };
  sa.sa_handler = signalHandler;

  if(sigaction(SIGINT, &sa, NULL) || sigaction(SIGTERM, &sa, NULL)) {
    perror("Registering signal handler failed");
    return -1;
  }

  return 0;
}

int main(int argc, char *argv[]) {

  int runAsDaemon = 0;
  if(argc == 2 && strcmp(argv[1], "-d") == 0) {
    runAsDaemon = 1;
    openlog(NULL, 0, LOG_DAEMON);
  } else if(argc != 1) {
    printf("Wrong param\n");
    printf("aesdsocket [-d]\n");
    return 1;
  } else {
    openlog(NULL, 0, LOG_USER);
  }

  int sockfd = -1;
  if(createSocket(&sockfd) == -1) {
    printf("Could not prepare socket\n");
    if(sockfd != -1)
      close(sockfd);
    fclose(stdin);
    fclose(stdout);
    fclose(stderr);
    closelog();
    return -1;
  }

  if(runAsDaemon) {
    int pid = fork();
    if(pid != 0) {
      exit(0);
   }
  }

  registerSignalHandler();

  connectionPrepare(sockfd);

  while(closeAppRequest == 0) {
    struct sockaddr addr = { 0 };
    int acceptedfd = connectionWait(sockfd, &addr);

    if(closeAppRequest) {
      break;
    }

    char* buf;
    size_t datalen = 0;
    if(receiveData(acceptedfd, &buf, &datalen) == -1) {
      close(acceptedfd);
      free(buf);
      break;
    }

    if(saveData(buf, datalen) == -1) {
      break;
    }

    if(returnData(acceptedfd) == -1) {
      free(buf);
      close(acceptedfd);
      break;
    }

    free(buf);
    close(acceptedfd);
    char msg[128];
    int msglen = snprintf(msg, sizeof(msg), "Closed connection from");
    for(int i = 0; i < sizeof(addr.sa_data); i++)
      msglen += snprintf(msg + msglen, sizeof(msg) - msglen, " %d", addr.sa_data[i]);
    syslog(LOG_DEBUG, "%s", msg);
  }

  close(sockfd);
  deleteDataFile();
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  closelog();
  return 0;
}
