#define uint32_t uint
#define uint64_t ulong
#define uint8_t uchar
#define NULL 0

static void memset(uchar *str, int c, size_t n){
  for(int i=0;i<n;i++){
    str[i] = c;
  }
}

static void memcpy(uchar *dest, uchar *src, size_t n){
  for(int i=0;i<n;i++){
    dest[i] = src[i];
  }
}

static void memcpy_offset(uchar *dest, uchar *src, int offset, uchar bytes_to_copy){
  for(int i=0;i<bytes_to_copy;i++){
    dest[i] = src[offset+i];
  }
}

static void memzero(void *const pnt, const size_t len) {
  volatile unsigned char *volatile pnt_ = (volatile unsigned char *volatile)pnt;
  size_t i = (size_t)0U;

  while (i < len) {
    pnt_[i++] = 0U;
  }
}

static void memczero(void *s, size_t len, int flag) {
    unsigned char *p = (unsigned char *)s;
    volatile int vflag = flag;
    unsigned char mask = -(unsigned char) vflag;
    while (len) {
        *p &= ~mask;
        p++;
        len--;
    }
}

void copy_pad_previous(uchar *pad, uchar *previous, uchar *joined) {
  for(int x=0;x<128;x++){
    joined[x] = pad[x];
  }
  for(int x=0;x<64;x++){
    joined[x+128] = previous[x];
  }
}

void print_byte_array_hex(uchar *arr, int len) {
  for (int i = 0; i < len; i++) {
    printf("%02x", arr[i]);
  }
  printf("\n\n");
}

void xor_seed_with_round(char *seed, char *round) {
  for(int x=0;x<64;x++){
    seed[x] = seed[x] ^ round[x];
  }
}

void print_seed(uchar *seed){
  printf("seed: ");
  print_byte_array_hex(seed, 64);
}

void print_raw_address(uchar *address){
  printf("address: ");
  print_byte_array_hex(address, 25);
}

void print_mnemonic(uchar *mnemonic) {
  printf("mnemonic: ");
  for(int i=0;i<120;i++){
    printf("%c", mnemonic[i]);
  }
  printf("\n");
}

void print_byte_array(uchar *arr, int len) {
  printf("[");
  for(int x=0;x<len;x++){
    printf("%u", arr[x]);
    if(x < len-1){
      printf(", ");
    }
  }
  printf("]\n");
}