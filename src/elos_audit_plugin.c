// SPDX-License-Identifier: MIT
#include <elos/libelosplugin/libelosplugin.h>
#include <elos/libelosplugin/types.h>
#include <safu/common.h>
#include <safu/log.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/eventfd.h>
#include <unistd.h>

#include "auditd.h"

typedef struct elosAudit {
  bool running;
  int eventFd;
  struct elosPublisher *publisher;
  elosPlugin_t* plugin;
} elosAudit_t;

static safuResultE_t _pluginLoad(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    if ((plugin->config == NULL) || (plugin->config->key == NULL)) {
      safuLogErr("Given configuration is NULL or has .key set to NULL");
    } else {
      plugin->data = malloc(sizeof(elosAudit_t));
      if (plugin->data != NULL) {
        memset(plugin->data, 0, sizeof(elosAudit_t));
        ((elosAudit_t*)plugin->data)->plugin = plugin;
        safuLogDebugF("Scanner Plugin '%s' has been loaded",
                      plugin->config->key);
        result = SAFU_RESULT_OK;
      }
    }
  }

  return result;
}

static safuResultE_t _pluginStart(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    elosAudit_t *audit = plugin->data;
    audit->running = true;
    audit->eventFd = eventfd(1, 0);
    result = elosPluginCreatePublisher(plugin, &audit->publisher);
    if (result == SAFU_RESULT_FAILED) {
      safuLogErr("create publisher failed");
    } else {
      safuLogDebugF("Scanner Plugin '%s' has been started",
                    plugin->config->key);
      result = elosPluginReportAsStarted(plugin);
      if (result == SAFU_RESULT_FAILED) {
        safuLogErr("elosPluginReportAsStarted failed");
      } else {
        auditdStart(&audit->running, audit->eventFd, audit->publisher, plugin);
        result = elosPluginStopTriggerWait(plugin);
        if (result == SAFU_RESULT_FAILED) {
          safuLogErr("elosPluginStopTriggerWait failed");
        }
      }
    }
  }

  return result;
}

static safuResultE_t _pluginStop(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    safuLogDebugF("Stopping Scanner Plugin '%s'", plugin->config->key);

    elosAudit_t *audit = plugin->data;
    if (audit != NULL) {
      audit->running = false;
      uint64_t token = 2;
      write(audit->eventFd, &token, sizeof(token));
    }
    result = elosPluginStopTriggerWrite(plugin);
    if (result == SAFU_RESULT_FAILED) {
      safuLogErr("elosPluginStopTriggerWrite failed");
    }
  }

  return result;
}

static safuResultE_t _pluginUnload(elosPlugin_t *plugin) {
  safuResultE_t result = SAFU_RESULT_FAILED;

  if (plugin == NULL) {
    safuLogErr("Null parameter given");
  } else {
    safuLogDebugF("Unloading Scanner Plugin '%s'", plugin->config->key);

    elosAudit_t *audit = plugin->data;
    if (audit != NULL) {
      close(audit->eventFd);
      elosPluginDeletePublisher(plugin, audit->publisher);
      free(audit);
    }
    result = SAFU_RESULT_OK;
  }

  return result;
}

elosPluginConfig_t elosPluginConfig = {
    .type = PLUGIN_TYPE_SCANNER,
    .load = _pluginLoad,
    .unload = _pluginUnload,
    .start = _pluginStart,
    .stop = _pluginStop,
};
