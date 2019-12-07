#include "events.h"
#include "logging.h"
#include "str.h"
#include "sysutil.h"
#include "tunables.h"
#include <string.h>
#include <errno.h>

static void vsf_event_trigger(struct vsf_session* p_sess,
                              enum EVSFEventType what,
                              const struct mystr* p_str);
static void vsf_event_clear(struct vsf_session* p_sess);
static void vsf_event_log_err(struct vsf_session* p_sess, const char *msg);

void vsf_event_idle_start(struct vsf_session* p_sess)
{
  struct mystr event_str = INIT_MYSTR;
  unsigned long sec;

  str_alloc_ulong(&event_str, vsf_sysutil_getppid());
  str_append_text(&event_str, " ");
  vsf_sysutil_get_monotonic_clock(&sec, 0);
  str_append_ulong(&event_str, sec);
  vsf_event_trigger(p_sess, kVSFEventIdleStart, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventIdleStop, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventLoginSuccessful, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventLoginFailed, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventSessionClosed, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventIdleSessionTimeout, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventDataConnectionTimeout, &event_str);
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
  vsf_event_trigger(p_sess, kVSFEventMaxClientsReached, &event_str);
  str_free(&event_str);
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
  vsf_event_trigger(p_sess, kVSFEventMaxClientsReject, &event_str);
  str_free(&event_str);
}

void vsf_event_init(struct vsf_session* p_sess)
{
  if (!tunable_events_enable)
  {
    return;
  }
  if (p_sess->eventlog_fd != -1)
  {
    return;
  }
  /* create event socket */
  p_sess->eventlog_fd = vsf_sysutil_get_unix_sock();
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
    retval = vsf_sysutil_bind(p_sess->eventlog_fd, addr);
    if (vsf_sysutil_retval_is_error(retval))
    {
      vsf_sysutil_close_failok(p_sess->eventlog_fd);
      p_sess->eventlog_fd = -1;
    }
    vsf_sysutil_free(addr);
  }
  /* connect to server */
  if (p_sess->eventlog_fd != -1)
  {
    struct mystr path = INIT_MYSTR;
    struct vsf_sysutil_sockaddr* addr = 0;
    int retval;

    vsf_sysutil_sockaddr_alloc_un(&addr);
    str_alloc_text(&path, tunable_events_socket_path);
    vsf_sysutil_sockaddr_set_un_path(addr, &path, 0);
    str_free(&path);
    retval = vsf_sysutil_connect_timeout(p_sess->eventlog_fd, addr, 0);
    if (vsf_sysutil_retval_is_error(retval))
    {
      vsf_sysutil_close_failok(p_sess->eventlog_fd);
      p_sess->eventlog_fd = -1;
    }
    vsf_sysutil_free(addr);
  }
}

static
void vsf_event_clear(struct vsf_session* p_sess)
{
  if (!tunable_events_enable)
  {
    return;
  }
  if (p_sess->eventlog_fd == -1)
  {
    return;
  }
  vsf_sysutil_close(p_sess->eventlog_fd);
  p_sess->eventlog_fd = -1;
}

static void
vsf_event_log_err(struct vsf_session* p_sess, const char *msg)
{
  struct mystr log_line = INIT_MYSTR;
  str_alloc_text(&log_line, msg);
  str_append_text(&log_line, " failed. Reason: ");
  str_append_text(&log_line, strerror(errno));
  vsf_log_line(p_sess, kVSFLogEntryConnection, &log_line);
  str_free(&log_line);
}

static
void vsf_event_trigger(struct vsf_session* p_sess,
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
  vsf_event_init(p_sess);
  if (p_sess->eventlog_fd == -1)
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
  retval = vsf_sysutil_write(p_sess->eventlog_fd, header, msg_size);
  if (vsf_sysutil_retval_is_error(retval))
  {
    vsf_event_log_err(p_sess, "eventlog write");
    vsf_event_clear(p_sess);
    /* fall through */
  }
  vsf_sysutil_free(header);
}
