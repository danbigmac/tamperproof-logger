#include "event_type.h"
#include <strings.h> // for strcasecmp

EventType parse_event_type(const char *s)
{
    if (!s) return EVENT_UNKNOWN;

    if (strcasecmp(s, "score") == 0) return EVENT_SCORE;
    if (strcasecmp(s, "foul")  == 0) return EVENT_FOUL;
    if (strcasecmp(s, "sub") == 0 ||
        strcasecmp(s, "substitution") == 0) return EVENT_SUB;

    return EVENT_UNKNOWN;
}

const char *event_type_name(EventType t)
{
    switch (t) {
        case EVENT_SCORE: return "SCORE";
        case EVENT_FOUL:  return "FOUL";
        case EVENT_SUB:   return "SUB";
        default: return "UNKNOWN";
    }
}
