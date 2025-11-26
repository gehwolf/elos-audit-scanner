// SPDX-License-Identifier: MIT

#include "audit.h"

#include <elos/event/event_classification.h>
#include <elos/event/event_severity.h>
#include <elos/event/event_types.h>
#include <elos/libelosplugin/libelosplugin.h>
#include <safu/common.h>
#include <safu/result.h>
#include <safu/log.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/poll.h>
#include <unistd.h>

safuResultE_t auditdStart(bool *running, int eventFd,
                          struct elosPublisher *publisher,
                          elosPlugin_t *plugin) {
  int sockfd = -1;
  int result = -1;

  sockfd = openAuditSocket();
  if (sockfd < 0) {
    safuLogErr("failed to connect to audit kernel endpoint");
    return SAFU_RESULT_FAILED;
  }

  safuLogDebug("registered as audit daemon");
  result = auditRegisterAsDaemon(sockfd);
  if (result != 0) {
    safuLogErr("failed to register as audit daemon");
    return SAFU_RESULT_FAILED;
  }

  result = auditGetStatus(sockfd);
  if (result != 0) {
    safuLogErr("failed to register as audit daemon");
    return SAFU_RESULT_FAILED;
  }

  safuLogDebug("Enable kernel audit");
  result = auditEnableKernelAudit(sockfd);
  if (result != 0) {
    safuLogErr("failed to enable kernel audit");
    return SAFU_RESULT_FAILED;
  }

  result = auditGetStatus(sockfd);
  if (result != 0) {
    safuLogErr("failed to register as audit daemon");
    return SAFU_RESULT_FAILED;
  }

  safuLogDebug("Listening for audit messages...");

  enum {
    AUDIT_FD = 0,
    EVENT_FD,
    FD_ENUM_COUNT,
  };
  struct pollfd fds[FD_ENUM_COUNT];

  fds[AUDIT_FD].fd = sockfd;
  fds[AUDIT_FD].events = POLL_IN;
  fds[EVENT_FD].fd = eventFd;
  fds[EVENT_FD].events = POLL_IN;

  safuLogInfo("Waiting for signal or netlink message...");
  uint64_t token = 0;
  uint64_t oldToken = 0;
  while (*running == true) {
    int ret = poll(fds, FD_ENUM_COUNT, -1);
    if (ret < 0) {
      perror("poll");
      continue;
    }

    if (fds[EVENT_FD].revents & POLL_IN) {
      read(fds[EVENT_FD].fd, &token, sizeof(token));
      if (token != oldToken) {
        safuLogDebugF("new token value is %li", token);
        oldToken = token;
      }
      continue;
    }
    if (fds[AUDIT_FD].revents & POLL_IN) {
      char *message = NULL;
      size_t message_size = 0;
      int result =
          receiveAuditMessage(sockfd, (void **)&message, &message_size);
      if (result != 0) {
        safuLogErr("failed to receive audit message");
      } else {

        safuLogDebugF("new audit message: %.*s", (int)message_size, message);
        elosEvent_t event = {
            .messageCode = 1001,
            .classification =
                ELOS_CLASSIFICATION_KERNEL | ELOS_CLASSIFICATION_SECURITY,
            .severity = ELOS_SEVERITY_INFO,
            .hardwareid = (char *)safuGetHardwareId(),
            .source.appName = plugin->config->key,
            .payload = message,
        };
        elosPluginPublish(plugin, publisher, &event);
      }

      free(message);
    }
  }

  safuLogInfo("Stopping auditd main thread");
  close(sockfd);
  return SAFU_RESULT_OK;
}
