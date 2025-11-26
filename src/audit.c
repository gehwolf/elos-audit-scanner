// SPDX-License-Identifier: MIT

#include "audit.h"

#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include <linux/audit.h>
#include <linux/netlink.h>

#include <safu/log.h>

int openAuditSocket(void) {
  int sockfd = socket(PF_NETLINK, SOCK_RAW, NETLINK_AUDIT);
  if (sockfd < 0) {
    safuLogErrErrno("socket fail");
  } else {
    struct sockaddr_nl addr = {
        .nl_family = AF_NETLINK,
        .nl_pid = getpid(),
    };

    if (bind(sockfd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
      safuLogErrErrno("bind fail");
      close(sockfd);
      sockfd = -1;
    }
  }

  return sockfd;
}

int sendAuthMessage(int socketFd, uint16_t msg_type,
                    struct audit_status *status) {
  static int sequence = 1;
  struct audit_message {
    struct nlmsghdr nlh;
    struct audit_status status;
  } request = {0};

  request.nlh.nlmsg_flags = NLM_F_REQUEST | NLM_F_ACK;
  request.nlh.nlmsg_type = msg_type;
  request.nlh.nlmsg_seq = sequence++;
  request.nlh.nlmsg_pid = 0;

  request.nlh.nlmsg_len = NLMSG_SPACE(sizeof(*status));
  if (status != NULL) {
    memcpy(&request.status, status, sizeof(*status));
  }

  struct sockaddr_nl kernelAddr = {
      .nl_family = AF_NETLINK,
      .nl_pid = 0,
      .nl_groups = 0,
  };
  if (sendto(socketFd, &request, request.nlh.nlmsg_len, 0,
             (struct sockaddr *)&kernelAddr, sizeof(kernelAddr)) < 0) {
    safuLogErrErrno("send AUDIT_SET_PID");
    return -1;
  }

  struct nlmsghdr nlHeader = {0};
  ssize_t len = recv(socketFd, &nlHeader, sizeof(nlHeader), MSG_PEEK);
  if (len < 0) {
    safuLogErrErrno("recv netlink");
    return -1;
  } else {
    safuLogDebugF("seq: %i type: %i pid: %i error: %.2x", nlHeader.nlmsg_seq,
                  nlHeader.nlmsg_type, nlHeader.nlmsg_pid,
                  nlHeader.nlmsg_flags);
  }
  return 0;
}

static const char *decodeType(int type) {
  switch (type) {
  case NLMSG_NOOP:
    return "NOOP";
  case NLMSG_ERROR:
    return "ERROR";
  case NLMSG_DONE:
    return "DONE";
  case NLMSG_OVERRUN:
    return "OVERRUN";
  case NLMSG_MIN_TYPE:
    return "Reserved min type";
  default:
    return "N/A";
  }
}

void printNetLinkHeader(struct _IO_FILE *fd, struct nlmsghdr const *const h) {
  fprintf(fd, "NLH{seq: %i, type: %s(%i), len: %i, pid: %i, flags: %x}\n",
          h->nlmsg_seq, decodeType(h->nlmsg_type), h->nlmsg_type, h->nlmsg_len,
          h->nlmsg_pid, h->nlmsg_flags);
}

/**
 * Parse a netlink message and return the payload.
 * If `message` is `NULL` a suitable buffer is allocated and the size is
 * returned in `message_size`. The caller takes ownership of the buffer.
 * If `message` is not `NULL` the it should point to a space with size at least
 * of `message_size`.
 *
 * If the payload is larger then `message_size` the payload will be truncated to
 * fit into the buffer pointed to by `message`.
 *
 * Param:
 *    sockfd: file descriptor to receive from
 *    message: must not be NULL and either pointer to a pointer of a buffer to
 *             store the payload or a pointer to a pointer to store the new
 *             allocated buffer.
 *    message_size: pointer to size of given `message` size buffer or pointer to
 *                  where to store size of allocated message buffer.
 * Return:
 *    0: on success
 *    -1: on any failure
 **/
int receiveAuditMessage(int sockfd, void **message, size_t *message_size) {
  char buf[4096];
  int result = -1;
  void *message_buffer = NULL;
  size_t message_buffer_size = 0;
  pid_t *pvnr = NULL;

  if (message != NULL && message_size != NULL) {
    ssize_t len = recv(sockfd, buf, sizeof(buf), 0);
    if (len < 0) {
      safuLogErrErrno("recv netlink");
    } else {
      struct nlmsghdr *h = (struct nlmsghdr *)buf;
      struct nlmsgerr *error_msg = NULL;

      printNetLinkHeader(stdout, h);

      for (; NLMSG_OK(h, len); h = NLMSG_NEXT(h, len)) {
        switch (h->nlmsg_type) {
        case NLMSG_DONE:
          safuLogDebug("done messsage");
          result = 0;
          break;
        case AUDIT_REPLACE:
          pvnr = NLMSG_DATA(h);
          safuLogDebugF("audit replaces: %i ", *pvnr);
          result = 0;
          break;
        case NLMSG_ERROR:
          error_msg = NLMSG_DATA(h);
          if (error_msg->error == 0) {
            safuLogDebugF("got ACK: %i ", error_msg->msg.nlmsg_pid);
            result = 0;
          } else {
            safuLogDebugF("error messsage : %i ", error_msg->error);

            result = 1;
          }
          break;
        default:
          message_buffer_size = NLMSG_PAYLOAD(h, 0);

          if (*message == NULL) {
            message_buffer = malloc(message_buffer_size);
            if (message_buffer == NULL) {
              safuLogErrErrno("failed to reallocate message_buffer");
              result = -1;
            }
            *message = message_buffer;
            *message_size = message_buffer_size;
          } else {
            if (*message_size < message_buffer_size) {
              safuLogErrF(
                  "Received message is larger then the provided buffer (%zu < "
                  "%zu), result truncated!!",
                  *message_size, message_buffer_size);
            }
          }
          memcpy(*message, NLMSG_DATA(h), *message_size);

          result = 0;
          break;
        }
      }
    }
  }

  return result;
}

int auditRegisterAsDaemon(int sockfd) {
  int result = -1;
  struct audit_status status = {
      .mask = AUDIT_STATUS_PID,
      .pid = getpid(),
  };
  size_t size = sizeof(status);

  if (sendAuthMessage(sockfd, AUDIT_SET, &status) != 0) {
    safuLogErr("failed to register as audit daemon");
  } else {
    result = receiveAuditMessage(sockfd, &(void *){&status}, &size);
    if (result != 0) {
      safuLogErr("failed to register as audit daemon");
    } else {
      result = 0;
    }
  }

  return result;
}

int auditUnregisterAsDaemon(int sockfd) {
  static const uint32_t PID_TO_UNREGISTER = 0;
  int result = -1;
  struct audit_status status = {
      .mask = AUDIT_STATUS_PID,
      .pid = PID_TO_UNREGISTER,
  };
  size_t size = sizeof(status);

  if (sendAuthMessage(sockfd, AUDIT_SET, &status) != 0) {
    safuLogErr("failed to unregister as audit daemon");
  } else {
    result = receiveAuditMessage(sockfd, &(void *){&status}, &size);
    if (result != 0) {
      safuLogErr("failed to unregister as audit daemon");
    } else {
      result = 0;
    }
  }
  return result;
}

int auditEnableKernelAudit(int sockfd) {
  int result = -1;
  struct audit_status status = {
      .mask = AUDIT_STATUS_ENABLED,
      .enabled = true,
  };
  size_t size = sizeof(status);

  if (sendAuthMessage(sockfd, AUDIT_SET, &status) != 0) {
    safuLogErr("failed to send message to enable kernel audit");
  } else {
    result = receiveAuditMessage(sockfd, &(void *){&status}, &size);
    if (result != 0) {
      safuLogErr("failed to receive message about enabling kernel audit");
    } else {
      result = 0;
    }
  }
  return result;
}

int auditGetStatus(int sockfd) {
  int result = -1;

  if (sendAuthMessage(sockfd, AUDIT_GET, NULL) != 0) {
    safuLogErr("failed to register as audit daemon");
  } else {
    struct audit_status status = {0};
    size_t size = sizeof(status);
    result = receiveAuditMessage(sockfd, &(void *){&status}, &size);
    if (result != 0) {
      safuLogErr("failed to register as audit daemon");
    } else {
      safuLogDebug("audit status:");
      safuLogDebugF("\tenabled: %s", status.enabled ? "true" : "false");
      safuLogDebugF("\tfailure: %s", status.failure ? "true" : "false");
      safuLogDebugF("\tpid: %u", status.pid);
      safuLogDebugF("\trate_limit: %u", status.rate_limit);
      safuLogDebugF("\tbacklog_limit: %u", status.backlog_limit);
      safuLogDebugF("\tlost: %u", status.lost);
      safuLogDebugF("\tbacklog: %u", status.backlog);
      safuLogDebugF("\tfeature_bitmap: %u", status.feature_bitmap);
      safuLogDebugF("\tbacklog_wait_time: %u", status.backlog_wait_time);
      safuLogDebugF("\tbacklog_wait_time_actual: %u",
                    status.backlog_wait_time_actual);
      result = 0;
    }
  }

  return result;
}
