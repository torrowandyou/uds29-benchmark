#ifndef GMT0130_H
#define GMT0130_H

#include <stddef.h>

#include <openssl/bn.h>
#include <openssl/ec.h>

#define GMT0130_HA_LEN 32
#define GMT0130_POINT_LEN 33
#define GMT0130_SIGNATURE_LEN 64

typedef struct {
  EC_GROUP *group;
  BIGNUM *order;
  BIGNUM *master_private;
  BIGNUM *user_private;
  EC_POINT *master_public;
  EC_POINT *claimed_public;
  unsigned char *identity;
  size_t identity_len;
  unsigned char ha[GMT0130_HA_LEN];
} gmt0130_key;

int gmt0130_key_generate(gmt0130_key *key, const unsigned char *identity,
                         size_t identity_len);
int gmt0130_key_generate_fixed(gmt0130_key *key,
                               const unsigned char *identity,
                               size_t identity_len, const BIGNUM *master,
                               const BIGNUM *user_secret,
                               const BIGNUM *kgc_random);
void gmt0130_key_cleanup(gmt0130_key *key);

int gmt0130_encode_point(const gmt0130_key *key, const EC_POINT *point,
                         unsigned char out[GMT0130_POINT_LEN]);
int gmt0130_decode_point(const gmt0130_key *key,
                         const unsigned char in[GMT0130_POINT_LEN],
                         EC_POINT **point);
int gmt0130_derive_public(const gmt0130_key *key,
                          const unsigned char *identity, size_t identity_len,
                          const EC_POINT *claimed_public,
                          EC_POINT **actual_public);

int gmt0130_sign(const gmt0130_key *key, const unsigned char *message,
                 size_t message_len,
                 unsigned char signature[GMT0130_SIGNATURE_LEN]);
int gmt0130_sign_fixed_k(const gmt0130_key *key,
                         const unsigned char *message, size_t message_len,
                         const BIGNUM *k,
                         unsigned char signature[GMT0130_SIGNATURE_LEN]);
int gmt0130_verify(const gmt0130_key *key, const unsigned char *identity,
                   size_t identity_len, const EC_POINT *claimed_public,
                   const EC_POINT *actual_public,
                   const unsigned char *message, size_t message_len,
                   const unsigned char signature[GMT0130_SIGNATURE_LEN]);

#endif
