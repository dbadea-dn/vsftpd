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
};

void vsf_event_init(struct vsf_session* p_sess);
void vsf_event_idle_start(struct vsf_session* p_sess);
void vsf_event_idle_stop(struct vsf_session* p_sess);
void vsf_event_login_successful(struct vsf_session* p_sess);
void vsf_event_login_failed(struct vsf_session* p_sess);

#endif
