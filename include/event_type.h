#ifndef EVENT_TYPE_H
#define EVENT_TYPE_H

#include <stdint.h>

typedef enum {
    EVENT_UNKNOWN = 0,
    EVENT_SCORE,
    EVENT_FOUL,
    EVENT_SUB,
    EVENT_MISS_SHOT,
    EVENT_ASSIST,
    EVENT_TIMEOUT,
    EVENT_INJURY,
    EVENT_KEY_ROTATION,
    // add more as needed...
} EventType;

EventType parse_event_type(const char *s);
const char *event_type_name(EventType t);

#endif
