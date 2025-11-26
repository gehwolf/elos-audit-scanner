// SPDX-License-Identifier: MIT
#include <safu/result.h>
#include <stdbool.h>
#include <elos/libelosplugin/types.h>

safuResultE_t auditdStart(bool *running, int eventFd, struct elosPublisher * publisher, elosPlugin_t* plugin);
