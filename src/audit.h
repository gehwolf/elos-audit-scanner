// SPDX-License-Identifier: MIT

#include <stddef.h>
#include <stdint.h>
#include <linux/audit.h>

int openAuditSocket(void);
int sendAuthMessage(int socketFd, uint16_t msg_type,
                    struct audit_status *status);
/**
 * Parse a netlink message and return the payload.
 * If `message` is `NULL` a suiteable buffer is allocated and the size is
 * returned in `message_size`. The caller takes ownership of the buffer.
 * If `message` is not `NULL` the it should ponit to a space with size at least
 * of `message_size`.
 *
 * If the payload is larger then `message_size` the payload will be trunated to
 * fit into the buffer pointed to by `message`.
 *
 * Param:
 *    sockfd: file descriptor to receive from
 *    message: must not be NULL and either pointer to a pointer of a buffer to
 *             store the payload or a poniter to a pointer to store the new
 *             allocated buffer.
 *    message_size: pointer to size of given `message` size buffer or pointer to
 *                  where to store size of allocated message buffer.
 * Return:
 *    0: on success
 *    -1: on any failure
 **/
int receiveAuditMessage(int sockfd, void **message, size_t *message_size);
int auditRegisterAsDaemon(int sockfd);
int auditUnregisterAsDaemon(int sockfd);
int auditEnableKernelAudit(int sockfd);
int auditGetStatus(int sockfd);
