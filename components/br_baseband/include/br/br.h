#pragma once
/*
 * Bluetooth BR (Basic Rate) baseband library.
 *
 * Bit order everywhere: the first bit on air is bit 0. Packed buffers store bit i at
 * buf[i >> 3] bit (i & 7). Integer fields (sync word, HEC, CRC) hold their first transmitted bit in bit 0.
 *
 * References are to the Bluetooth Core Specification, Vol 2 Part B ("Baseband").
 */
#include "br/br_bits.h"
#include "br/br_access_code.h"
#include "br/br_crc.h"
#include "br/br_whiten.h"
#include "br/br_fec.h"
#include "br/br_header.h"
#include "br/br_packet.h"
#include "br/br_hop.h"
#include "br/br_safer.h"
#include "br/br_e0.h"
#include "br/br_ssp.h"
