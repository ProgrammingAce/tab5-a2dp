/* Shim for the vendored Bluedroid SBC encoder. */
#pragma once
#include <stdlib.h>
#define osi_malloc(n) malloc(n)
#define osi_free(p) free(p)
