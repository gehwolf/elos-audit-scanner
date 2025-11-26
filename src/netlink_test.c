// SPDX-License-Identifier: MIT

#include "audit.h"

#include <endian.h>
#include <linux/audit.h>
#include <linux/netlink.h>
#include <poll.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/signalfd.h>
#include <sys/socket.h>
#include <unistd.h>


int main(void) {
  int sockfd;
  sigset_t mask;
  int result = -1;

  sigemptyset(&mask);
  sigaddset(&mask, SIGINT);
  sigaddset(&mask, SIGTERM);

  if (sigprocmask(SIG_BLOCK, &mask, NULL) < 0) {
    perror("sigprocmask");
    exit(1);
  }

  int signalFd = signalfd(-1, &mask, SFD_NONBLOCK);
  if (signalFd < 0) {
    perror("signalfd");
    exit(1);
  }

  sockfd = openAuditSocket();
  if (sockfd < 0) {
    fprintf(stderr, "failed to connect to audit kernel endpoint\n");
    exit(1);
  }

  result = auditRegisterAsDaemon(sockfd);
  if (result != 0) {
    fprintf(stderr, "failed to register as audit daemon\n");
    exit(1);
  }

  printf("registered as audit daemon\n");

  result = auditGetStatus(sockfd);
  if (result != 0) {
    fprintf(stderr, "failed to register as audit daemon\n");
    exit(1);
  }

  printf("Enable kernel audit\n");
  result = auditEnableKernelAudit(sockfd);
  if (result != 0) {
    fprintf(stderr, "failed to enable kernel audit\n");
    exit(1);
  }

  result = auditGetStatus(sockfd);
  if (result != 0) {
    fprintf(stderr, "failed to register as audit daemon\n");
    exit(1);
  }

  printf("Listening for audit messages...\n");

  enum {
    SIGNAL_FD = 0,
    AUDIT_FD,
    FD_ENUM_COUNT,
  };
  struct pollfd fds[FD_ENUM_COUNT];

  fds[SIGNAL_FD].fd = signalFd;
  fds[SIGNAL_FD].events = POLL_IN;

  fds[AUDIT_FD].fd = sockfd;
  fds[AUDIT_FD].events = POLL_IN;

  printf("Waiting for signal or netlink message...\n");
  while (1) {
    int ret = poll(fds, 2, -1);
    if (ret < 0) {
      perror("poll");
      continue;
    }

    if (fds[SIGNAL_FD].revents & POLL_IN) {
      struct signalfd_siginfo si;
      ssize_t n = read(signalFd, &si, sizeof(si));
      if (n != sizeof(si)) {
        perror("read signalfd");
        continue;
      }

      printf("Received signal %d, exiting...\n", si.ssi_signo);
      printf("Unregistered as audit daemon\n");
      result = auditUnregisterAsDaemon(sockfd);
      if (result != 0) {
        fprintf(stderr, "failed to unregister as audit daemon\n");
      }
      break;
    }

    if (fds[AUDIT_FD].revents & POLL_IN) {
      char *message = NULL;
      size_t message_size = 0;
      int result =
          receiveAuditMessage(sockfd, (void **)&message, &message_size);
      if (result != 0) {
        fprintf(stderr, "failed to receive audit message\n");
      } else {
        printf("new audit message: %.*s\n", (int)message_size, message);
      }

      free(message);
    }
  }

  close(signalFd);
  close(sockfd);
  return 0;
}
