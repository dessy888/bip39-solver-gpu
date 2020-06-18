static int secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
  return (a->d[0] | a->d[1] | a->d[2] | a->d[3] | a->d[4] | a->d[5] | a->d[6] | a->d[7]) == 0;
}

static int secp256k1_scalar_reduce(secp256k1_scalar *r, uint32_t overflow) {
    uint64_t t;
    t = (uint64_t)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[3] + overflow * SECP256K1_N_C_3;
    r->d[3] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[4] + overflow * SECP256K1_N_C_4;
    r->d[4] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[5];
    r->d[5] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[6];
    r->d[6] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)r->d[7];
    r->d[7] = t & 0xFFFFFFFFUL;
    return overflow;
}

static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[7] < SECP256K1_N_7); /* No need for a > check. */
    no |= (a->d[6] < SECP256K1_N_6); /* No need for a > check. */
    no |= (a->d[5] < SECP256K1_N_5); /* No need for a > check. */
    no |= (a->d[4] < SECP256K1_N_4);
    yes |= (a->d[4] > SECP256K1_N_4) & ~no;
    no |= (a->d[3] < SECP256K1_N_3) & ~yes;
    yes |= (a->d[3] > SECP256K1_N_3) & ~no;
    no |= (a->d[2] < SECP256K1_N_2) & ~yes;
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1) & ~yes;
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

static void secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v) {
  r->d[0] = v;
  r->d[1] = 0;
  r->d[2] = 0;
  r->d[3] = 0;
  r->d[4] = 0;
  r->d[5] = 0;
  r->d[6] = 0;
  r->d[7] = 0;
}

static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar* a) {
    bin[0] = a->d[7] >> 24; bin[1] = a->d[7] >> 16; bin[2] = a->d[7] >> 8; bin[3] = a->d[7];
    bin[4] = a->d[6] >> 24; bin[5] = a->d[6] >> 16; bin[6] = a->d[6] >> 8; bin[7] = a->d[6];
    bin[8] = a->d[5] >> 24; bin[9] = a->d[5] >> 16; bin[10] = a->d[5] >> 8; bin[11] = a->d[5];
    bin[12] = a->d[4] >> 24; bin[13] = a->d[4] >> 16; bin[14] = a->d[4] >> 8; bin[15] = a->d[4];
    bin[16] = a->d[3] >> 24; bin[17] = a->d[3] >> 16; bin[18] = a->d[3] >> 8; bin[19] = a->d[3];
    bin[20] = a->d[2] >> 24; bin[21] = a->d[2] >> 16; bin[22] = a->d[2] >> 8; bin[23] = a->d[2];
    bin[24] = a->d[1] >> 24; bin[25] = a->d[1] >> 16; bin[26] = a->d[1] >> 8; bin[27] = a->d[1];
    bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint32_t)b32[31] | (uint32_t)b32[30] << 8 | (uint32_t)b32[29] << 16 | (uint32_t)b32[28] << 24;
    r->d[1] = (uint32_t)b32[27] | (uint32_t)b32[26] << 8 | (uint32_t)b32[25] << 16 | (uint32_t)b32[24] << 24;
    r->d[2] = (uint32_t)b32[23] | (uint32_t)b32[22] << 8 | (uint32_t)b32[21] << 16 | (uint32_t)b32[20] << 24;
    r->d[3] = (uint32_t)b32[19] | (uint32_t)b32[18] << 8 | (uint32_t)b32[17] << 16 | (uint32_t)b32[16] << 24;
    r->d[4] = (uint32_t)b32[15] | (uint32_t)b32[14] << 8 | (uint32_t)b32[13] << 16 | (uint32_t)b32[12] << 24;
    r->d[5] = (uint32_t)b32[11] | (uint32_t)b32[10] << 8 | (uint32_t)b32[9] << 16 | (uint32_t)b32[8] << 24;
    r->d[6] = (uint32_t)b32[7] | (uint32_t)b32[6] << 8 | (uint32_t)b32[5] << 16 | (uint32_t)b32[4] << 24;
    r->d[7] = (uint32_t)b32[3] | (uint32_t)b32[2] << 8 | (uint32_t)b32[1] << 16 | (uint32_t)b32[0] << 24;
    over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if (overflow) {
        *overflow = over;
    }
}

static int secp256k1_scalar_set_b32_seckey(secp256k1_scalar *r, const unsigned char *bin) {
    int overflow;
    secp256k1_scalar_set_b32(r, bin, &overflow);
    return (!overflow) & (!secp256k1_scalar_is_zero(r));
}

static void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
    uint32_t mask0, mask1;
    mask0 = flag + ~((uint32_t)0);
    mask1 = ~mask0;
    r->d[0] = (r->d[0] & mask0) | (a->d[0] & mask1);
    r->d[1] = (r->d[1] & mask0) | (a->d[1] & mask1);
    r->d[2] = (r->d[2] & mask0) | (a->d[2] & mask1);
    r->d[3] = (r->d[3] & mask0) | (a->d[3] & mask1);
    r->d[4] = (r->d[4] & mask0) | (a->d[4] & mask1);
    r->d[5] = (r->d[5] & mask0) | (a->d[5] & mask1);
    r->d[6] = (r->d[6] & mask0) | (a->d[6] & mask1);
    r->d[7] = (r->d[7] & mask0) | (a->d[7] & mask1);
}

static int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    int overflow;
    uint64_t t = (uint64_t)a->d[0] + b->d[0];
    r->d[0] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[1] + b->d[1];
    r->d[1] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[2] + b->d[2];
    r->d[2] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[3] + b->d[3];
    r->d[3] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[4] + b->d[4];
    r->d[4] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[5] + b->d[5];
    r->d[5] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[6] + b->d[6];
    r->d[6] = t & 0xFFFFFFFFUL; t >>= 32;
    t += (uint64_t)a->d[7] + b->d[7];
    r->d[7] = t & 0xFFFFFFFFUL; t >>= 32;
    overflow = t + secp256k1_scalar_check_overflow(r);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

static void secp256k1_scalar_clear(secp256k1_scalar *r) {
  r->d[0] = 0;
  r->d[1] = 0;
  r->d[2] = 0;
  r->d[3] = 0;
  r->d[4] = 0;
  r->d[5] = 0;
  r->d[6] = 0;
  r->d[7] = 0;
}

static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
  return (a->d[offset >> 5] >> (offset & 0x1F)) & ((1 << count) - 1);
}