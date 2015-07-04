#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#include <openssl/bn.h>
#include <openssl/rsa.h>
#include <openssl/sha.h>

#pragma clang diagnostic ignored "-Wdeprecated-declarations"

static int probable_prime(BIGNUM *rnd, int bits);
static char *hex_encode(const uint8_t *buf, size_t len);

int main(void) {
  unsigned char gpg_packet[272] = {
    0x99, 0x01, 0x0D, 0x04, 0x55, 0xa8, 0x45, 0x80, 0x01
  };

  unsigned char fingerprint[20];

  BIGNUM *e = BN_new();
  gpg_packet[267] = 0x00;
  gpg_packet[268] = 0x11;

  BN_set_word(e, 65537);
  BN_bn2bin(e, &gpg_packet[269]);

  RSA *rsa = RSA_new();
  gpg_packet[9] = 0x08;
  gpg_packet[10] = 0x00;

  bool match = false;

  while (!match) {
    RSA_generate_key_ex(rsa, 2048, e, NULL);
    BN_bn2bin(rsa->n, &gpg_packet[11]);

  	for (uint32_t t = 1435708800; t <= 1438300800; t++) {
      (*(uint32_t *) &gpg_packet[4]) = htonl(t);

      SHA1(gpg_packet, 272, fingerprint);

      if (fingerprint[19] == 0xDE) {
        // fprintf(stderr, "\n0xDE\n");

        if (fingerprint[18] == 0xCA) {
          // fprintf(stderr, "\n0xCA 0xDE\n");

          if (fingerprint[17] == 0xDE) {
            match = true;
            break;
          }
        }
      }
    }
  }

  fprintf(stderr, "%s\n", BN_bn2hex(rsa->d));
  fprintf(stderr, "%s\n", BN_bn2hex(rsa->p));
  fprintf(stderr, "%s\n", BN_bn2hex(rsa->q));
  fprintf(stderr, "%s\n", hex_encode(gpg_packet, sizeof(gpg_packet)));
  fprintf(stderr, "%s\n", hex_encode(fingerprint, sizeof(fingerprint)));

  return 0;
}

static char * hex_encode(const uint8_t *buf, size_t len) {
  char *ret = calloc((len * 2) + 1, 1);

  for (size_t i = 0; i < len; i++) {
    sprintf(ret + (i * 2), "%02X", buf[i]);
  }

  return ret;
}
