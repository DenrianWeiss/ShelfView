#ifndef BC_CONTROL_WIRE_H
#define BC_CONTROL_WIRE_H
#include <stdint.h>

static inline void bc_wire_write_be(uint8_t *p, uint64_t value, unsigned n) {
    for (unsigned i = n; i; --i) { p[i - 1] = (uint8_t)value; value >>= 8; }
}
static inline uint64_t bc_wire_read_be(const uint8_t *p, unsigned n) {
    uint64_t value = 0;
    for (unsigned i = 0; i < n; ++i) value = (value << 8) | p[i];
    return value;
}
static inline void bc_wire_write_le(uint8_t *p, uint64_t value, unsigned n) {
    for (unsigned i = 0; i < n; ++i) { p[i] = (uint8_t)value; value >>= 8; }
}
static inline uint64_t bc_wire_read_le(const uint8_t *p, unsigned n) {
    uint64_t value = 0;
    for (unsigned i = n; i; --i) value = (value << 8) | p[i - 1];
    return value;
}
/* Two's complement checksum used by IPMI: the summed range including the
   checksum byte is zero modulo 256. */
static inline uint8_t bc_wire_checksum(const uint8_t *p, uint64_t n) {
    uint8_t sum = 0;
    while (n--) sum = (uint8_t)(sum + *p++);
    return (uint8_t)(0u - sum);
}
#endif
