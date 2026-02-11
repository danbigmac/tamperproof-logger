#ifndef EVENT_TYPE_H
#define EVENT_TYPE_H

#include <stdint.h>

/** Event types for game actions */
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

/** Parse event type from string */
EventType parse_event_type(const char *s);
/** Get event type string from event enum */
const char *event_type_name(EventType t);

#endif
