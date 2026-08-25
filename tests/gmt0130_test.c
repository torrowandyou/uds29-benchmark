#include "gmt0130.h"

#include <stdio.h>
#include <string.h>

static int failures;

static BIGNUM *hex_bn(const char *hex) {
  BIGNUM *value = NULL;
  if (!BN_hex2bn(&value, hex)) {
    fprintf(stderr, "cannot parse test BIGNUM\n");
    failures++;
  }
  return value;
}

static EC_POINT *hex_point(const EC_GROUP *group, const char *xhex,
                           const char *yhex) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *x = hex_bn(xhex), *y = hex_bn(yhex);
  EC_POINT *point = EC_POINT_new(group);
  if (ctx == NULL || x == NULL || y == NULL || point == NULL ||
      EC_POINT_set_affine_coordinates(group, point, x, y, ctx) <= 0) {
    fprintf(stderr, "cannot parse test EC point\n");
    failures++;
    EC_POINT_free(point);
    point = NULL;
  }
  BN_CTX_free(ctx);
  BN_free(x);
  BN_free(y);
  return point;
}

static void expect_bn(const char *name, const BIGNUM *actual,
                      const char *expected_hex) {
  BIGNUM *expected = hex_bn(expected_hex);
  if (expected == NULL || BN_cmp(actual, expected) != 0) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    printf("PASS: %s\n", name);
  }
  BN_free(expected);
}

static void expect_bytes(const char *name, const unsigned char *actual,
                         size_t length, const char *expected_hex) {
  unsigned char expected[128];
  size_t expected_length = strlen(expected_hex) / 2;
  size_t i;
  if (expected_length != length || length > sizeof(expected)) {
    fprintf(stderr, "FAIL: invalid expected length for %s\n", name);
    failures++;
    return;
  }
  for (i = 0; i < length; i++) {
    unsigned int byte;
    if (sscanf(expected_hex + 2 * i, "%2x", &byte) != 1) {
      failures++;
      return;
    }
    expected[i] = (unsigned char)byte;
  }
  if (memcmp(actual, expected, length) != 0) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    printf("PASS: %s\n", name);
  }
}

static void expect_point(const char *name, const EC_GROUP *group,
                         const EC_POINT *actual, const char *xhex,
                         const char *yhex) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *expected = hex_point(group, xhex, yhex);
  if (ctx == NULL || expected == NULL ||
      EC_POINT_cmp(group, actual, expected, ctx) != 0) {
    fprintf(stderr, "FAIL: %s\n", name);
    failures++;
  } else {
    printf("PASS: %s\n", name);
  }
  BN_CTX_free(ctx);
  EC_POINT_free(expected);
}

int main(void) {
  static const unsigned char identity[] = "Alice";
  static const unsigned char message[] = "message digest";
  gmt0130_key key;
  BIGNUM *master = hex_bn(
      "6BDD93B210F79415FE0F6388C1C932C208319FF7D7E99C972B3535C9F19A9FF9");
  BIGNUM *user_secret = hex_bn(
      "04914C20251A59A2C311102944C600430A02285A0433144228142A1848004C00");
  BIGNUM *kgc_random = hex_bn(
      "6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F");
  BIGNUM *k = hex_bn(
      "34914C20251A59A2C311102944C600430A02285A0433144228142A1848004C14");
  EC_POINT *actual = NULL;
  unsigned char signature[GMT0130_SIGNATURE_LEN], bad_message[sizeof(message) - 1];

  if (master == NULL || user_secret == NULL || kgc_random == NULL || k == NULL ||
      !gmt0130_key_generate_fixed(&key, identity, sizeof(identity) - 1, master,
                                  user_secret, kgc_random)) {
    fprintf(stderr, "FAIL: initialize GM/T 0130 Annex A vector\n");
    return 1;
  }

  expect_point(
      "Annex A Ppub", key.group, key.master_public,
      "F294B710601DE1C5D34420C4902D81C3A30644903E5799BFE4013E56C55C864C",
      "5C003EB1B50B9BBB2E8807782AA3C38EA800E23B30B777FAAD8F0F7146D66AC1");
  expect_bytes("Annex A HA", key.ha, sizeof(key.ha),
               "CC2DC29253D9C77385781813985D421A6C6F9CCBCE61FAD37EC79D8B6EFC8F71");
  expect_point(
      "Annex A WA", key.group, key.claimed_public,
      "DB65BF80F08E3FEA9758A9490F2C257A2D8ADEAA59DA786CBFAFEF221E78ADB4",
      "0728185A257F64B79DFA929C16C987ED956FB32D00B6CAF7678E56E66E01530F");
  expect_bn("Annex A dA", key.user_private,
            "C048380BBE577886A905D28E55433B3ACA963EF412B0F14C9C148DA42A71AD4F");

  if (!gmt0130_derive_public(&key, identity, sizeof(identity) - 1,
                             key.claimed_public, &actual)) {
    fprintf(stderr, "FAIL: derive Annex A actual public key\n");
    failures++;
  } else {
    expect_point(
        "Annex A PA", key.group, actual,
        "12B72E936C902048F99D77F4C556D112F72FDF6A7BA24DE106BC5B7300C4B5C4",
        "8C5AF329D45B9E6270D07645F10B283C35D8BF9A35F58AB41E8CD4A1DD70D18B");
  }

  if (!gmt0130_sign_fixed_k(&key, message, sizeof(message) - 1, k, signature)) {
    fprintf(stderr, "FAIL: create Annex A signature\n");
    failures++;
  } else {
    expect_bytes(
        "Annex A signature (r,s)", signature, sizeof(signature),
        "73CBEB43EBBD6AA5B747FAA537194CE979754A401AB5B0DA37B55F72862F1DFF"
        "F358CDF5527F157D2B7DCB74A82DBA83605290164EBAA046A584FAB0D4CEAFB0");
    if (actual == NULL ||
        !gmt0130_verify(&key, identity, sizeof(identity) - 1,
                        key.claimed_public, actual, message,
                        sizeof(message) - 1, signature)) {
      fprintf(stderr, "FAIL: verify Annex A signature\n");
      failures++;
    } else {
      printf("PASS: Annex A signature verification\n");
    }
    memcpy(bad_message, message, sizeof(bad_message));
    bad_message[0] ^= 1;
    if (actual != NULL &&
        gmt0130_verify(&key, identity, sizeof(identity) - 1,
                       key.claimed_public, actual, bad_message,
                       sizeof(bad_message), signature)) {
      fprintf(stderr, "FAIL: tampered message accepted\n");
      failures++;
    } else {
      printf("PASS: tampered message rejected\n");
    }
  }

  EC_POINT_free(actual);
  gmt0130_key_cleanup(&key);
  BN_free(master);
  BN_free(user_secret);
  BN_free(kgc_random);
  BN_free(k);
  if (failures != 0) {
    fprintf(stderr, "%d test(s) failed\n", failures);
    return 1;
  }
  printf("All GM/T 0130-2023 Annex A tests passed.\n");
  return 0;
}
