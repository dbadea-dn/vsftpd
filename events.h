#ifndef VSF_EVENTS_H
#define VSF_EVENTS_H

#include "session.h"

enum EVSFEventType
{
  kVSFEventNop = 0,
  kVSFEventIdleStart,
  kVSFEventIdleStop,
  kVSFEventLoginSuccessful,
  kVSFEventLoginFailed,
  kVSFEventSessionClosed,
  kVSFEventIdleSessionTimeout,
  kVSFEventDataConnectionTimeout,
  kVSFEventMaxClientsReached,
  kVSFEventMaxClientsReject,
  kVSFEventMaxClientsCleared,
};

void vsf_event_init(int* eventlog_fd);
void vsf_event_idle_start(struct vsf_session* p_sess);
void vsf_event_idle_stop(struct vsf_session* p_sess);
void vsf_event_login_successful(struct vsf_session* p_sess);
void vsf_event_login_failed(struct vsf_session* p_sess);
void vsf_event_session_closed(struct vsf_session* p_sess);
void vsf_event_idle_session_timeout(struct vsf_session* p_sess);
void vsf_event_data_connection_timeout(struct vsf_session* p_sess);
void vsf_event_max_clients_reached(struct vsf_session* p_sess);
void vsf_event_max_clients_reject(struct vsf_session* p_sess);
void vsf_event_max_clients_cleared(int* eventlog_fd, unsigned int max_clients);

#endif
