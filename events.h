#ifndef VSF_EVENTS_H
#define VSF_EVENTS_H

#include "session.h"

enum EVSFEventType
{
  kVSFEventNop = 0,
};

void vsf_event_init(struct vsf_session* p_sess);

#endif
