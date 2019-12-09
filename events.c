#include "events.h"
#include "logging.h"
#include "str.h"
#include "sysutil.h"
#include "tunables.h"
#include <string.h>
#include <stdio.h>
#include <errno.h>
#include "utility.h"

static void vsf_event_trigger(int* eventlog_fd,
                              enum EVSFEventType what,
                              const struct mystr* p_str);
static void vsf_event_clear(int* eventlog_fd);

void vsf_event_idle_start(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventIdleStart, &event_str);
  str_free(&event_str);
}

void vsf_event_idle_stop(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventIdleStop, &event_str);
  str_free(&event_str);
}

void vsf_event_login_successful(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventLoginSuccessful, &event_str);
  str_free(&event_str);
}

void vsf_event_login_failed(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventLoginFailed, &event_str);
  str_free(&event_str);
}

void vsf_event_session_closed(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventSessionClosed, &event_str);
  str_free(&event_str);
}

void vsf_event_idle_session_timeout(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventIdleSessionTimeout, &event_str);
  str_free(&event_str);
}

void vsf_event_data_connection_timeout(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventDataConnectionTimeout, &event_str);
  str_free(&event_str);
}

void vsf_event_max_clients_reached(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_ulong(&event_str, tunable_max_clients);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventMaxClientsReached, &event_str);
  str_free(&event_str);
}

void vsf_event_max_clients_cleared(int* eventlog_fd, unsigned int max_clients)
{
  int retval;
  const int max_ulong_str_size = 32;
  /* custom stack-based message allocation */
  struct {
    struct {
      unsigned int type;
      unsigned int length;
    } header;
    char payload[(max_ulong_str_size + 1)* 2];
    char end[0];
  } msg;
  char *payload;
  unsigned long sec;

  vsf_sysutil_memclr(&msg, sizeof(msg));
  msg.header.type = kVSFEventMaxClientsCleared;
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  payload = msg.payload;
  retval = snprintf(payload, max_ulong_str_size, "%lu", sec);
  payload += (retval > max_ulong_str_size)? max_ulong_str_size: retval;
  *(payload++) = ' ';
  payload += snprintf(payload, max_ulong_str_size, "%lu",
                      (unsigned long)max_clients);
  msg.header.length = payload - msg.payload;
  retval = vsf_sysutil_write(*eventlog_fd, &msg,
                             sizeof(msg.header) + msg.header.length + 1);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_event_clear(eventlog_fd);
  }
}

void vsf_event_max_clients_reject(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;
  unsigned short remote_port;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->user_str);
  str_append_text(&event_str, " ");
  str_append_ulong(&event_str, tunable_max_clients);
  str_append_text(&event_str, " ");
  str_append_str(&event_str, &p_sess->remote_ip_str);
  str_append_text(&event_str, " ");
  remote_port = vsf_sysutil_sockaddr_get_port(p_sess->p_remote_addr);
  str_append_ulong(&event_str, (unsigned long)remote_port);
  vsf_event_trigger(&p_sess->eventlog_fd, kVSFEventMaxClientsReject, &event_str);
  str_free(&event_str);
}

#define REMOTE_ADDR_MAX_CLIENTS_REACHED_BY_CONFIG "127.0.0.1 0"
#define SESSION_ID_MAX_CLIENTS_REACHED_BY_CONFIG 0

void vsf_event_max_clients_reached_by_config(int* eventlog_fd, unsigned int max_clients)
{
  int retval;
  const int max_ulong_str_size = 32;
  /* custom stack-based message allocation */
  struct {
    struct {
      unsigned int type;
      unsigned int length;
    } header;
    char payload[(max_ulong_str_size + 1)* 3 \
                 + sizeof(REMOTE_ADDR_MAX_CLIENTS_REACHED_BY_CONFIG)];
    char end[0];
  } msg;
  char *payload;
  unsigned long sec;

  vsf_sysutil_memclr(&msg, sizeof(msg));
  msg.header.type = kVSFEventMaxClientsReached;
  payload = msg.payload;
  /* session id */
  retval = snprintf(payload, max_ulong_str_size, "%lu",
                    (unsigned long)SESSION_ID_MAX_CLIENTS_REACHED_BY_CONFIG);
  payload += (retval > max_ulong_str_size)? max_ulong_str_size: retval;
  *(payload++) = ' ';
  /* uptime */
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  retval = snprintf(payload, max_ulong_str_size, "%lu", sec);
  payload += (retval > max_ulong_str_size)? max_ulong_str_size: retval;
  *(payload++) = ' ';
  /* max-clients limit */
  retval = snprintf(payload, max_ulong_str_size, "%lu",
                    (unsigned long)max_clients);
  payload += (retval > max_ulong_str_size)? max_ulong_str_size: retval;
  *(payload++) = ' ';
  /* remote address */
  payload += snprintf(payload, sizeof(REMOTE_ADDR_MAX_CLIENTS_REACHED_BY_CONFIG),
                      REMOTE_ADDR_MAX_CLIENTS_REACHED_BY_CONFIG);
  msg.header.length = payload - msg.payload;
  retval = vsf_sysutil_write(*eventlog_fd, &msg,
                             sizeof(msg.header) + msg.header.length + 1);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_event_clear(eventlog_fd);
  }
}

void vsf_event_init(int* eventlog_fd)
{
  if (!tunable_events_enable)
  {
    return;
  }
  if (*eventlog_fd != -1)
  {
    return;
  }
  /* create event socket */
  *eventlog_fd = vsf_sysutil_get_unix_sock();
  /* populate local address */
  {
    struct mystr path = INIT_MYSTR;
    struct vsf_sysutil_sockaddr* addr = 0;
    int retval;

    str_alloc_text(&path, ".ftp_events.sock.");
    str_append_ulong(&path, vsf_sysutil_getpid());
    vsf_sysutil_sockaddr_alloc_un(&addr);
    vsf_sysutil_sockaddr_set_un_path(addr, &path, 1);
    str_free(&path);
    retval = vsf_sysutil_bind(*eventlog_fd, addr);
    if (vsf_sysutil_retval_is_error(retval))
    {
      vsf_sysutil_close_failok(*eventlog_fd);
      *eventlog_fd = -1;
    }
    vsf_sysutil_free(addr);
  }
  /* connect to server */
  if (*eventlog_fd != -1)
  {
    struct mystr path = INIT_MYSTR;
    struct vsf_sysutil_sockaddr* addr = 0;
    int retval;

    vsf_sysutil_sockaddr_alloc_un(&addr);
    str_alloc_text(&path, tunable_events_socket_path);
    vsf_sysutil_sockaddr_set_un_path(addr, &path, 0);
    str_free(&path);
    retval = vsf_sysutil_connect_timeout(*eventlog_fd, addr, 0);
    if (vsf_sysutil_retval_is_error(retval))
    {
      vsf_sysutil_close_failok(*eventlog_fd);
      *eventlog_fd = -1;
    }
    vsf_sysutil_free(addr);
  }
}

static
void vsf_event_clear(int* eventlog_fd)
{
  if (!tunable_events_enable)
  {
    return;
  }
  if (*eventlog_fd == -1)
  {
    return;
  }
  vsf_sysutil_close(*eventlog_fd);
  *eventlog_fd = -1;
}

static
void vsf_event_trigger(int* eventlog_fd,
                       enum EVSFEventType what,
                       const struct mystr* p_str)
{
  int retval;
  int msg_size;
  struct {
    unsigned int type;
    unsigned int length;
    char payload[0];
  } *header = 0;

  if (!tunable_events_enable)
  {
    return;
  }
  vsf_event_init(eventlog_fd);
  if (*eventlog_fd == -1)
  {
    return;
  }
  msg_size = sizeof(*header) + str_getlen(p_str) + 1;
  header = vsf_sysutil_malloc(msg_size);
  vsf_sysutil_memclr(header, msg_size);
  header->type = (unsigned int)what;
  header->length = str_getlen(p_str);
  vsf_sysutil_memcpy(header->payload,
                     str_getbuf(p_str),
                     header->length);
  retval = vsf_sysutil_write(*eventlog_fd, header, msg_size);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_event_clear(eventlog_fd);
    /* fall through */
  }
  vsf_sysutil_free(header);
}
