#pragma once
#include <stdbool.h>
#include <stdint.h>

/* Core v5.4 Vol 2 Part B 4.5.3, 6.6.2 and 7.6.2.6.
 * Payload STOP persists until a CRC-verified ACL-U GO. Header STOP applies to
 * the next transmission only (a missing/invalid header implies GO). POLL/NULL
 * must retain the SEQN of the last transmitted CRC packet, even after its ACK. */
typedef struct {
    uint8_t payload_go;
    uint8_t last_seqn;
} br_flow_t;

#define BR_FLOW_INLINE static inline __attribute__((always_inline))
BR_FLOW_INLINE void br_flow_reset(volatile br_flow_t *s)
{
    s->payload_go = 1;
    s->last_seqn = 0;
}
/* Call only after successful CRC verification, including empty ACL-U packets. */
BR_FLOW_INLINE void br_flow_payload(volatile br_flow_t *s, uint8_t llid, uint8_t go)
{
    if (llid == 1 || llid == 2) s->payload_go = !!go;
}
BR_FLOW_INLINE bool br_flow_allow(const volatile br_flow_t *s, bool header_go, uint8_t llid)
{
    return header_go && (llid == 3 || ((llid == 1 || llid == 2) && s->payload_go));
}
BR_FLOW_INLINE uint8_t br_flow_seqn(volatile br_flow_t *s, bool data, uint8_t seqn)
{
    if (data) s->last_seqn = seqn & 1u;
    return s->last_seqn;
}
#undef BR_FLOW_INLINE
