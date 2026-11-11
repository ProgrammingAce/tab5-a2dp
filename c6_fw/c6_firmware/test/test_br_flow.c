#include <assert.h>
#include <stdio.h>
#include "br_flow.h"

int main(void)
{
    br_flow_t s;
    br_flow_reset(&s);
    assert(br_flow_allow(&s, true, 1));
    assert(br_flow_allow(&s, true, 2));
    assert(br_flow_seqn(&s, true, 1) == 1);
    /* An ACK advances the next data SEQN to zero, but a POLL must retain one. */
    assert(br_flow_seqn(&s, false, 0) == 1);
    br_flow_payload(&s, 1, 0);
    assert(!br_flow_allow(&s, true, 1));
    assert(!br_flow_allow(&s, true, 2));
    assert(br_flow_allow(&s, true, 3));
    /* An unrelated LMP packet does not clear payload STOP. */
    br_flow_payload(&s, 3, 1);
    assert(!br_flow_allow(&s, true, 2));
    assert(br_flow_seqn(&s, false, 0) == 1);
    br_flow_payload(&s, 1, 1);
    assert(br_flow_allow(&s, true, 2));
    /* Header STOP blocks every ACL packet while retaining the pending SEQN. */
    for (uint8_t llid = 1; llid <= 3; ++llid) assert(!br_flow_allow(&s, false, llid));
    assert(br_flow_seqn(&s, false, 0) == 1);
    assert(br_flow_allow(&s, true, 2));
    assert(br_flow_seqn(&s, true, 0) == 0);
    assert(br_flow_seqn(&s, false, 1) == 0);
    br_flow_payload(&s, 2, 0);
    br_flow_reset(&s);
    assert(br_flow_allow(&s, true, 2));
    assert(br_flow_seqn(&s, false, 1) == 0);
    puts("BR flow control: PASS");
    return 0;
}
