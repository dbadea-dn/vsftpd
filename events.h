#ifndef VSF_EVENTS_H
#define VSF_EVENTS_H

#include "session.h"

enum EVSFEventType
{
  kVSFEventNop = 0,
  kVSFEventIdleStart,
  kVSFEventIdleStop,
};

void vsf_event_init(struct vsf_session* p_sess);
void vsf_event_idle_start(struct vsf_session* p_sess);
void vsf_event_idle_stop(struct vsf_session* p_sess);

#endif
