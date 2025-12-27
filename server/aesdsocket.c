#include <netdb.h>
#include <pthread.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <syslog.h>
#include <time.h>
#include <unistd.h>

#define RECV_BUFFER_CHUNK 100

#ifndef USE_AESD_CHAR_DEVICE
#define USE_AESD_CHAR_DEVICE 1
#endif

#if USE_AESD_CHAR_DEVICE == 1
#define DATA_FILE "/dev/aesdchar"
#else
#define DATA_FILE "/var/tmp/aesdsocketdata"
#endif

int closeAppRequest = 0;

pthread_mutex_t fileMutex;

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
  int ret = listen(sockfd, 10);
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
  remove(DATA_FILE);
}

int saveData(char* data, size_t datalen) {
  FILE* f = fopen(DATA_FILE, "a");
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
  FILE* f = fopen(DATA_FILE, "r");
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

int saveAndReturnData(int socketfd, char* buf, size_t datalen) {
  if(saveData(buf, datalen) == -1) {
    return -1;
  }

  if(returnData(socketfd) == -1) {
    free(buf);
    close(socketfd);
    return -1;
  }

  free(buf);
  close(socketfd);

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

struct threadListData {
  pthread_t thread;
  int acceptedfd;
  struct sockaddr addr;
  bool finish;
  SLIST_ENTRY(threadListData) entries;
};

void* serverThread(void* arg) {
  struct threadListData* data = (struct threadListData*)arg;
  int acceptedfd = data->acceptedfd;
  char* buf;
  size_t datalen = 0;

  if(receiveData(acceptedfd, &buf, &datalen) == -1) {
    close(acceptedfd);
    free(buf);
    data->finish = true;
    return NULL;
  }

  if(pthread_mutex_lock(&fileMutex) == 0) {
    saveAndReturnData(acceptedfd, buf, datalen);
  } else {
    data->finish = true;
    return NULL;
  }
  pthread_mutex_unlock(&fileMutex);

  char msg[128];
  int msglen = snprintf(msg, sizeof(msg), "Closed connection from");
  for(int i = 0; i < sizeof(data->addr.sa_data); i++)
    msglen += snprintf(msg + msglen, sizeof(msg) - msglen, " %d", data->addr.sa_data[i]);
  syslog(LOG_DEBUG, "%s", msg);

  data->finish = true;
  return NULL;
}

void timerThread(union sigval arg) {
  char outstr[200];
  time_t t;
  struct tm *tmp;

  t = time(NULL);
  tmp = localtime(&t);
  if (tmp == NULL) {
    perror("localtime");
    return;
  }

  if (strftime(outstr, sizeof(outstr), "timestamp:%Y-%m-%d %H:%M:%S\n", tmp) == 0) {
    return;
  }

  if(pthread_mutex_lock(&fileMutex) == 0) {
    saveData(outstr, strlen(outstr));
  }
  pthread_mutex_unlock(&fileMutex);
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

  pthread_mutex_init(&fileMutex, NULL);

#if USE_AESD_CHAR_DEVICE != 1
  timer_t timerid;
  struct sigevent sigevt = { 0 };
  sigevt.sigev_notify = SIGEV_THREAD;
  sigevt.sigev_notify_function = timerThread;
  timer_create(CLOCK_MONOTONIC, &sigevt, &timerid);

  struct itimerspec its = { 0 };
  its.it_value.tv_sec = 10;
  its.it_interval.tv_sec = 10;
  timer_settime(timerid, 0, &its, NULL);
#endif

  SLIST_HEAD(threadListHead, threadListData) threadList;
  SLIST_INIT(&threadList);

  connectionPrepare(sockfd);

  while(closeAppRequest == 0) {
    struct sockaddr addr = { 0 };
    int acceptedfd = connectionWait(sockfd, &addr);

    struct threadListData* listMember;
    while(true) {
      bool foundDoneTherad = false;
      struct threadListData* doneMember = NULL;
      SLIST_FOREACH(listMember, &threadList, entries) {
        if(listMember->finish) {
          foundDoneTherad = true;
          doneMember = listMember;
        }
      }

      if(foundDoneTherad) {
        pthread_join(doneMember->thread, NULL);
        SLIST_REMOVE(&threadList, doneMember, threadListData, entries);
        free(doneMember);
      }
      else {
        break;
      }

    }

    if(closeAppRequest) {
      break;
    }

    listMember = calloc(1, sizeof(struct threadListData));
    listMember->acceptedfd = acceptedfd;
    listMember->addr = addr;

    pthread_create(&listMember->thread, NULL, serverThread, listMember);

    SLIST_INSERT_HEAD(&threadList, listMember, entries);
  }

#if USE_AESD_CHAR_DEVICE != 1
  timer_delete(timerid);
  deleteDataFile();
#endif
  close(sockfd);
  fclose(stdin);
  fclose(stdout);
  fclose(stderr);
  closelog();
  return 0;
}
