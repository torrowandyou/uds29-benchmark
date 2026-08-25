#include "gmt0130.h"

#include <limits.h>
#include <string.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>

#define FIELD_LEN 32

/**
 * @brief 检查标量是否位于椭圆曲线标量域的有效范围 [1, n-1]。
 *
 * @param[in] value 待检查的标量。
 * @param[in] order 曲线基点的阶 n。
 * @return 有效返回 1，否则返回 0。
 */
static int bn_in_range(const BIGNUM *value, const BIGNUM *order) {
  return value != NULL && !BN_is_negative(value) && !BN_is_zero(value) &&
         BN_cmp(value, order) < 0;
}

/**
 * @brief 使用密码学安全随机源生成 [1, n-1] 范围内的随机标量。
 *
 * BN_priv_rand_range() 可能产生 0，因此持续采样直到获得非零值。
 *
 * @param[out] value 接收随机标量的 BIGNUM。
 * @param[in] order 曲线基点的阶 n。
 * @return 成功返回 1，随机数生成失败返回 0。
 */
static int random_nonzero(BIGNUM *value, const BIGNUM *order) {
  do {
    if (!BN_priv_rand_range(value, order))
      return 0;
  } while (BN_is_zero(value));
  return 1;
}

/**
 * @brief 对多段字节串的顺序拼接结果计算 SM3 摘要。
 *
 * 该函数采用分段更新方式计算 SM3(parts[0] || ... || parts[count-1])，
 * 避免为中间拼接数据额外分配内存。长度为 0 的数据段会被跳过。
 *
 * @param[in] parts 各输入数据段的首地址数组。
 * @param[in] lengths 各数据段对应的字节长度数组。
 * @param[in] count 数据段数量。
 * @param[out] out 接收 32 字节 SM3 摘要的缓冲区。
 * @return 成功返回 1，摘要上下文创建或计算失败返回 0。
 */
static int sm3_parts(const unsigned char *const *parts, const size_t *lengths,
                     size_t count, unsigned char out[GMT0130_HA_LEN]) {
  EVP_MD_CTX *md = EVP_MD_CTX_new();
  unsigned int length = 0;
  size_t i;
  int ok = 0;
  if (md == NULL || EVP_DigestInit_ex(md, EVP_sm3(), NULL) <= 0)
    goto end;
  for (i = 0; i < count; i++) {
    if (lengths[i] != 0 && EVP_DigestUpdate(md, parts[i], lengths[i]) <= 0)
      goto end;
  }
  if (EVP_DigestFinal_ex(md, out, &length) <= 0 || length != GMT0130_HA_LEN)
    goto end;
  ok = 1;
end:
  EVP_MD_CTX_free(md);
  return ok;
}

/**
 * @brief 导出 SM2 曲线上点的仿射坐标并编码为定长大端字节串。
 *
 * @param[in] group 点所属的椭圆曲线群。
 * @param[in] point 待编码的曲线点。
 * @param[out] xbuf 接收 32 字节 x 坐标。
 * @param[out] ybuf 接收 32 字节 y 坐标。
 * @param[in,out] ctx OpenSSL 大数运算上下文。
 * @return 成功返回 1，坐标读取或定长编码失败返回 0。
 */
static int point_xy(const EC_GROUP *group, const EC_POINT *point,
                    unsigned char xbuf[FIELD_LEN],
                    unsigned char ybuf[FIELD_LEN], BN_CTX *ctx) {
  BIGNUM *x = BN_new(), *y = BN_new();
  int ok = 0;
  if (x == NULL || y == NULL ||
      EC_POINT_get_affine_coordinates(group, point, x, y, ctx) <= 0 ||
      BN_bn2binpad(x, xbuf, FIELD_LEN) != FIELD_LEN ||
      BN_bn2binpad(y, ybuf, FIELD_LEN) != FIELD_LEN)
    goto end;
  ok = 1;
end:
  BN_free(x);
  BN_free(y);
  return ok;
}

/**
 * @brief 按 GM/T 0130-2023 计算用户身份杂凑值 HA。
 *
 * 计算公式为：
 * HA = SM3(ENTL || ID || a || b || xG || yG || xPpub || yPpub)，
 * 其中 ENTL 是身份 ID 的比特长度，采用 2 字节大端编码；Ppub 为 KGC
 * 主公钥。身份长度必须能以 16 位比特长度表示。
 *
 * @param[in] group SM2 椭圆曲线群。
 * @param[in] master_public KGC 主公钥 Ppub。
 * @param[in] identity 用户身份标识 ID。
 * @param[in] identity_len 身份标识的字节长度。
 * @param[out] out 接收 32 字节 HA 的缓冲区。
 * @param[in,out] ctx OpenSSL 大数运算上下文。
 * @return 成功返回 1，参数无效或计算失败返回 0。
 */
static int compute_ha(const EC_GROUP *group, const EC_POINT *master_public,
                      const unsigned char *identity, size_t identity_len,
                      unsigned char out[GMT0130_HA_LEN], BN_CTX *ctx) {
  BIGNUM *p = BN_new(), *a = BN_new(), *b = BN_new();
  const EC_POINT *generator = EC_GROUP_get0_generator(group);
  unsigned char entl[2], abuf[FIELD_LEN], bbuf[FIELD_LEN];
  unsigned char gx[FIELD_LEN], gy[FIELD_LEN], px[FIELD_LEN], py[FIELD_LEN];
  const unsigned char *parts[8];
  size_t lengths[8] = {sizeof(entl), identity_len, FIELD_LEN, FIELD_LEN,
                       FIELD_LEN,   FIELD_LEN,   FIELD_LEN, FIELD_LEN};
  int ok = 0;
  if (identity == NULL || identity_len > UINT16_MAX / 8 || p == NULL ||
      a == NULL || b == NULL || generator == NULL)
    goto end;
  entl[0] = (unsigned char)((identity_len * 8) >> 8);
  entl[1] = (unsigned char)(identity_len * 8);
  if (EC_GROUP_get_curve(group, p, a, b, ctx) <= 0 ||
      BN_bn2binpad(a, abuf, FIELD_LEN) != FIELD_LEN ||
      BN_bn2binpad(b, bbuf, FIELD_LEN) != FIELD_LEN ||
      !point_xy(group, generator, gx, gy, ctx) ||
      !point_xy(group, master_public, px, py, ctx))
    goto end;
  parts[0] = entl;
  parts[1] = identity;
  parts[2] = abuf;
  parts[3] = bbuf;
  parts[4] = gx;
  parts[5] = gy;
  parts[6] = px;
  parts[7] = py;
  ok = sm3_parts(parts, lengths, 8, out);
end:
  BN_free(p);
  BN_free(a);
  BN_free(b);
  return ok;
}

/**
 * @brief 计算无证书公钥派生标量 lambda。
 *
 * 计算公式为 lambda = SM3(xW || yW || HA) mod n，其中 W 是用户声称
 * 公钥，n 是 SM2 基点的阶。
 *
 * @param[in] group SM2 椭圆曲线群。
 * @param[in] order 曲线基点的阶 n。
 * @param[in] claimed_public 用户声称公钥 W。
 * @param[in] ha 用户身份杂凑值 HA。
 * @param[in,out] ctx OpenSSL 大数运算上下文。
 * @return 成功时返回新分配的 lambda，调用者须用 BN_free() 释放；
 * 失败返回 NULL。
 */
static BIGNUM *compute_lambda(const EC_GROUP *group, const BIGNUM *order,
                              const EC_POINT *claimed_public,
                              const unsigned char ha[GMT0130_HA_LEN],
                              BN_CTX *ctx) {
  unsigned char x[FIELD_LEN], y[FIELD_LEN], digest[GMT0130_HA_LEN];
  const unsigned char *parts[3] = {x, y, ha};
  const size_t lengths[3] = {FIELD_LEN, FIELD_LEN, GMT0130_HA_LEN};
  BIGNUM *lambda = NULL;
  if (!point_xy(group, claimed_public, x, y, ctx) ||
      !sm3_parts(parts, lengths, 3, digest))
    return NULL;
  lambda = BN_bin2bn(digest, sizeof(digest), NULL);
  if (lambda == NULL || BN_mod(lambda, lambda, order, ctx) <= 0) {
    BN_free(lambda);
    return NULL;
  }
  return lambda;
}

/**
 * @brief 计算标准 SM2 签名使用的消息摘要 e。
 *
 * 本实现中 ZA = HA || xW || yW，因此：
 * e = SM3(ZA || M) = SM3(HA || xW || yW || M)。
 *
 * @param[in] key 提供 SM2 曲线参数的密钥上下文。
 * @param[in] claimed_public 用户声称公钥 W。
 * @param[in] ha 用户身份杂凑值 HA。
 * @param[in] message 待签名或验签的消息 M。
 * @param[in] message_len 消息的字节长度。
 * @param[out] out 接收 32 字节摘要 e 的缓冲区。
 * @param[in,out] ctx OpenSSL 大数运算上下文。
 * @return 成功返回 1，失败返回 0。
 */
static int message_digest(const gmt0130_key *key,
                          const EC_POINT *claimed_public,
                          const unsigned char ha[GMT0130_HA_LEN],
                          const unsigned char *message, size_t message_len,
                          unsigned char out[GMT0130_HA_LEN], BN_CTX *ctx) {
  unsigned char x[FIELD_LEN], y[FIELD_LEN];
  const unsigned char *parts[4] = {ha, x, y, message};
  const size_t lengths[4] = {GMT0130_HA_LEN, FIELD_LEN, FIELD_LEN, message_len};
  return point_xy(key->group, claimed_public, x, y, ctx) &&
         sm3_parts(parts, lengths, 4, out);
}

/**
 * @brief 使用指定标量生成 GM/T 0130-2023 无证书用户密钥。
 *
 * 该确定性入口主要用于附录 A 参考向量测试。设 KGC 主私钥为 ms，
 * 用户秘密值为 d'，KGC 随机数为 w，则依次计算：
 * U = d'G，W = wG + U，t = w + lambda * ms mod n，
 * d = t + d' mod n，实际公钥 P = W + lambda * Ppub。
 * 函数最后验证 P == dG，确保生成结果内部一致。
 *
 * @param[out] key 接收完整密钥上下文；失败时会被清理并清零。
 * @param[in] identity 用户身份标识 ID。
 * @param[in] identity_len 身份标识的字节长度。
 * @param[in] master KGC 主私钥 ms，范围必须为 [1, n-1]。
 * @param[in] user_secret 用户秘密值 d'，范围必须为 [1, n-1]。
 * @param[in] kgc_random KGC 随机数 w，范围必须为 [1, n-1]。
 * @return 成功返回 1，参数无效、内存分配或密码运算失败返回 0。
 */
int gmt0130_key_generate_fixed(gmt0130_key *key,
                               const unsigned char *identity,
                               size_t identity_len, const BIGNUM *master,
                               const BIGNUM *user_secret,
                               const BIGNUM *kgc_random) {
  BN_CTX *ctx = NULL;
  BIGNUM *lambda = NULL, *t = NULL;
  EC_POINT *user_public = NULL, *kgc_point = NULL, *check = NULL;
  EC_POINT *actual = NULL;
  int ok = 0;
  memset(key, 0, sizeof(*key));
  key->group = EC_GROUP_new_by_curve_name(NID_sm2);
  key->order = BN_new();
  key->master_private = BN_dup(master);
  key->user_private = BN_new();
  key->master_public = key->group ? EC_POINT_new(key->group) : NULL;
  key->claimed_public = key->group ? EC_POINT_new(key->group) : NULL;
  key->identity = OPENSSL_memdup(identity, identity_len);
  key->identity_len = identity_len;
  ctx = BN_CTX_new();
  t = BN_new();
  user_public = key->group ? EC_POINT_new(key->group) : NULL;
  kgc_point = key->group ? EC_POINT_new(key->group) : NULL;
  check = key->group ? EC_POINT_new(key->group) : NULL;
  if (key->group == NULL || key->order == NULL || key->master_private == NULL ||
      key->user_private == NULL || key->master_public == NULL ||
      key->claimed_public == NULL || key->identity == NULL || ctx == NULL ||
      t == NULL || user_public == NULL || kgc_point == NULL || check == NULL ||
      EC_GROUP_get_order(key->group, key->order, ctx) <= 0 ||
      !bn_in_range(master, key->order) ||
      !bn_in_range(user_secret, key->order) ||
      !bn_in_range(kgc_random, key->order) ||
      EC_POINT_mul(key->group, key->master_public, master, NULL, NULL, ctx) <= 0 ||
      EC_POINT_mul(key->group, user_public, user_secret, NULL, NULL, ctx) <= 0 ||
      EC_POINT_mul(key->group, kgc_point, kgc_random, NULL, NULL, ctx) <= 0 ||
      EC_POINT_add(key->group, key->claimed_public, kgc_point, user_public, ctx) <=
          0 ||
      !compute_ha(key->group, key->master_public, identity, identity_len,
                  key->ha, ctx))
    goto end;
  lambda = compute_lambda(key->group, key->order, key->claimed_public, key->ha,
                          ctx);
  if (lambda == NULL ||
      BN_mod_mul(t, lambda, master, key->order, ctx) <= 0 ||
      BN_mod_add(t, t, kgc_random, key->order, ctx) <= 0 ||
      BN_mod_add(key->user_private, t, user_secret, key->order, ctx) <= 0 ||
      BN_is_zero(key->user_private) ||
      EC_POINT_mul(key->group, check, key->user_private, NULL, NULL, ctx) <= 0 ||
      !gmt0130_derive_public(key, identity, identity_len, key->claimed_public,
                             &actual) ||
      EC_POINT_cmp(key->group, check, actual, ctx) != 0)
    goto end;
  ok = 1;
end:
  BN_free(lambda);
  BN_clear_free(t);
  EC_POINT_free(user_public);
  EC_POINT_free(kgc_point);
  EC_POINT_free(check);
  EC_POINT_free(actual);
  BN_CTX_free(ctx);
  if (!ok)
    gmt0130_key_cleanup(key);
  return ok;
}

/**
 * @brief 随机生成 GM/T 0130-2023 无证书用户密钥。
 *
 * 为 ms、d' 和 w 生成密码学安全的非零随机标量，并调用
 * gmt0130_key_generate_fixed() 完成密钥构造。遇到极小概率的无效
 * 中间值时最多重新尝试 8 次。
 *
 * @param[out] key 接收完整密钥上下文；成功后须调用
 * gmt0130_key_cleanup()。
 * @param[in] identity 用户身份标识 ID。
 * @param[in] identity_len 身份标识的字节长度。
 * @return 成功返回 1，随机数生成或密钥构造失败返回 0。
 */
int gmt0130_key_generate(gmt0130_key *key, const unsigned char *identity,
                         size_t identity_len) {
  EC_GROUP *group = EC_GROUP_new_by_curve_name(NID_sm2);
  BIGNUM *order = BN_new(), *master = BN_new(), *user = BN_new(), *random = BN_new();
  BN_CTX *ctx = BN_CTX_new();
  int ok = 0, attempts;
  if (group == NULL || order == NULL || master == NULL || user == NULL ||
      random == NULL || ctx == NULL ||
      EC_GROUP_get_order(group, order, ctx) <= 0)
    goto end;
  for (attempts = 0; attempts < 8; attempts++) {
    if (!random_nonzero(master, order) || !random_nonzero(user, order) ||
        !random_nonzero(random, order))
      goto end;
    if (gmt0130_key_generate_fixed(key, identity, identity_len, master, user,
                                   random)) {
      ok = 1;
      break;
    }
  }
end:
  EC_GROUP_free(group);
  BN_clear_free(order);
  BN_clear_free(master);
  BN_clear_free(user);
  BN_clear_free(random);
  BN_CTX_free(ctx);
  return ok;
}

/**
 * @brief 释放密钥上下文持有的资源并清除敏感数据。
 *
 * 主私钥、用户私钥和身份缓冲区使用清零释放，随后将整个结构体清零。
 * 允许传入 NULL，也允许清理已成功初始化或生成失败后的上下文。
 *
 * @param[in,out] key 待清理的密钥上下文。
 */
void gmt0130_key_cleanup(gmt0130_key *key) {
  if (key == NULL)
    return;
  EC_GROUP_free(key->group);
  BN_free(key->order);
  BN_clear_free(key->master_private);
  BN_clear_free(key->user_private);
  EC_POINT_free(key->master_public);
  EC_POINT_free(key->claimed_public);
  OPENSSL_clear_free(key->identity, key->identity_len);
  memset(key, 0, sizeof(*key));
}

/**
 * @brief 将 SM2 曲线点编码为 33 字节 SEC1 压缩格式。
 *
 * @param[in] key 提供 SM2 曲线群的密钥上下文。
 * @param[in] point 待编码的曲线点。
 * @param[out] out 接收压缩点的 33 字节缓冲区。
 * @return 编码长度恰为 GMT0130_POINT_LEN 时返回 1，否则返回 0。
 */
int gmt0130_encode_point(const gmt0130_key *key, const EC_POINT *point,
                         unsigned char out[GMT0130_POINT_LEN]) {
  BN_CTX *ctx = BN_CTX_new();
  size_t length = 0;
  if (ctx != NULL)
    length = EC_POINT_point2oct(key->group, point, POINT_CONVERSION_COMPRESSED,
                               out, GMT0130_POINT_LEN, ctx);
  BN_CTX_free(ctx);
  return length == GMT0130_POINT_LEN;
}

/**
 * @brief 解码并校验 33 字节 SEC1 压缩 SM2 曲线点。
 *
 * 除格式解码外，还会检查结果位于 SM2 曲线上且不是无穷远点。
 *
 * @param[in] key 提供 SM2 曲线群的密钥上下文。
 * @param[in] in 待解码的 33 字节压缩点。
 * @param[out] point 成功时接收新分配的 EC_POINT；调用者须用
 * EC_POINT_free() 释放。失败时被置为 NULL。
 * @return 成功返回 1，格式或曲线合法性校验失败返回 0。
 */
int gmt0130_decode_point(const gmt0130_key *key,
                         const unsigned char in[GMT0130_POINT_LEN],
                         EC_POINT **point) {
  BN_CTX *ctx = BN_CTX_new();
  EC_POINT *decoded = EC_POINT_new(key->group);
  int ok = 0;
  *point = NULL;
  if (ctx != NULL && decoded != NULL &&
      EC_POINT_oct2point(key->group, decoded, in, GMT0130_POINT_LEN, ctx) > 0 &&
      EC_POINT_is_on_curve(key->group, decoded, ctx) == 1 &&
      !EC_POINT_is_at_infinity(key->group, decoded)) {
    *point = decoded;
    decoded = NULL;
    ok = 1;
  }
  EC_POINT_free(decoded);
  BN_CTX_free(ctx);
  return ok;
}

/**
 * @brief 从用户身份和声称公钥派生用户实际公钥。
 *
 * 重新计算 HA 和 lambda，并按 P = W + lambda * Ppub 得到实际公钥 P。
 * 输入的声称公钥 W 必须位于 SM2 曲线上且不是无穷远点。
 *
 * @param[in] key 包含曲线参数、阶和 KGC 主公钥的上下文。
 * @param[in] identity 用户身份标识 ID。
 * @param[in] identity_len 身份标识的字节长度。
 * @param[in] claimed_public 用户声称公钥 W。
 * @param[out] actual_public 成功时接收新分配的实际公钥 P；调用者须用
 * EC_POINT_free() 释放。失败时被置为 NULL。
 * @return 成功返回 1，输入点无效或派生失败返回 0。
 */
int gmt0130_derive_public(const gmt0130_key *key,
                          const unsigned char *identity, size_t identity_len,
                          const EC_POINT *claimed_public,
                          EC_POINT **actual_public) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *lambda = NULL;
  EC_POINT *term = EC_POINT_new(key->group);
  EC_POINT *actual = EC_POINT_new(key->group);
  unsigned char ha[GMT0130_HA_LEN];
  int ok = 0;
  *actual_public = NULL;
  if (ctx == NULL || term == NULL || actual == NULL ||
      EC_POINT_is_on_curve(key->group, claimed_public, ctx) != 1 ||
      EC_POINT_is_at_infinity(key->group, claimed_public) ||
      !compute_ha(key->group, key->master_public, identity, identity_len, ha,
                  ctx))
    goto end;
  lambda = compute_lambda(key->group, key->order, claimed_public, ha, ctx);
  if (lambda == NULL ||
      EC_POINT_mul(key->group, term, NULL, key->master_public, lambda, ctx) <= 0 ||
      EC_POINT_add(key->group, actual, claimed_public, term, ctx) <= 0 ||
      EC_POINT_is_at_infinity(key->group, actual))
    goto end;
  *actual_public = actual;
  actual = NULL;
  ok = 1;
end:
  BN_free(lambda);
  EC_POINT_free(term);
  EC_POINT_free(actual);
  BN_CTX_free(ctx);
  return ok;
}

/**
 * @brief 使用指定随机标量 k 生成定长 SM2 签名。
 *
 * 该确定性入口用于标准参考向量测试。按照 SM2 签名公式计算：
 * r = (e + x1) mod n，s = ((1 + d)^-1 * (k - r*d)) mod n，
 * 其中 (x1, y1) = kG。输出采用固定 64 字节 r || s 大端编码，
 * 而非 DER。
 *
 * @param[in] key 包含完整用户私钥 d、HA 和声称公钥 W 的上下文。
 * @param[in] message 待签名消息 M。
 * @param[in] message_len 消息的字节长度。
 * @param[in] k 指定的签名随机标量，范围必须为 [1, n-1]。
 * @param[out] signature 接收 64 字节 r || s 签名的缓冲区。
 * @return 成功返回 1；参数无效、中间值不满足 SM2 要求或运算失败
 * 返回 0。
 */
int gmt0130_sign_fixed_k(const gmt0130_key *key,
                         const unsigned char *message, size_t message_len,
                         const BIGNUM *k,
                         unsigned char signature[GMT0130_SIGNATURE_LEN]) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *e = NULL, *x = BN_new(), *r = BN_new(), *s = BN_new();
  BIGNUM *tmp = BN_new(), *inverse = NULL;
  EC_POINT *point = EC_POINT_new(key->group);
  unsigned char digest[GMT0130_HA_LEN];
  int ok = 0;
  if (ctx == NULL || x == NULL || r == NULL || s == NULL || tmp == NULL ||
      point == NULL || !bn_in_range(k, key->order) ||
      !message_digest(key, key->claimed_public, key->ha, message, message_len,
                      digest, ctx) ||
      (e = BN_bin2bn(digest, sizeof(digest), NULL)) == NULL ||
      EC_POINT_mul(key->group, point, k, NULL, NULL, ctx) <= 0 ||
      EC_POINT_get_affine_coordinates(key->group, point, x, NULL, ctx) <= 0 ||
      BN_mod_add(r, e, x, key->order, ctx) <= 0 || BN_is_zero(r) ||
      BN_add(tmp, r, k) <= 0 || BN_cmp(tmp, key->order) == 0)
    goto end;
  if (BN_mod_mul(tmp, r, key->user_private, key->order, ctx) <= 0 ||
      BN_mod_sub(tmp, k, tmp, key->order, ctx) <= 0 ||
      BN_copy(s, key->user_private) == NULL ||
      BN_add_word(s, 1) <= 0 ||
      (inverse = BN_mod_inverse(NULL, s, key->order, ctx)) == NULL ||
      BN_mod_mul(s, inverse, tmp, key->order, ctx) <= 0 || BN_is_zero(s) ||
      BN_bn2binpad(r, signature, FIELD_LEN) != FIELD_LEN ||
      BN_bn2binpad(s, signature + FIELD_LEN, FIELD_LEN) != FIELD_LEN)
    goto end;
  ok = 1;
end:
  BN_free(e);
  BN_free(x);
  BN_free(r);
  BN_free(s);
  BN_free(tmp);
  BN_free(inverse);
  EC_POINT_free(point);
  BN_CTX_free(ctx);
  return ok;
}

/**
 * @brief 使用随机 k 生成定长 SM2 签名。
 *
 * 每次使用密码学安全随机源生成 k，并调用 gmt0130_sign_fixed_k()。
 * 当 r、s 等中间值不满足 SM2 签名要求时重新取值，最多尝试 16 次。
 *
 * @param[in] key 包含完整用户私钥及签名上下文的密钥对象。
 * @param[in] message 待签名消息 M。
 * @param[in] message_len 消息的字节长度。
 * @param[out] signature 接收 64 字节 r || s 签名的缓冲区。
 * @return 成功返回 1，随机数生成或签名失败返回 0。
 */
int gmt0130_sign(const gmt0130_key *key, const unsigned char *message,
                 size_t message_len,
                 unsigned char signature[GMT0130_SIGNATURE_LEN]) {
  BIGNUM *k = BN_new();
  int ok = 0, attempts;
  if (k == NULL)
    return 0;
  for (attempts = 0; attempts < 16; attempts++) {
    if (!random_nonzero(k, key->order))
      break;
    if (gmt0130_sign_fixed_k(key, message, message_len, k, signature)) {
      ok = 1;
      break;
    }
  }
  BN_clear_free(k);
  return ok;
}

/**
 * @brief 验证 GM/T 0130-2023 用户生成的定长 SM2 签名。
 *
 * 函数重新计算身份杂凑值和消息摘要，检查 r、s 属于 [1, n-1]，
 * 再计算：
 * t = (r + s) mod n，(x1, y1) = sG + tP，R = (e + x1) mod n。
 * 仅当 R == r 时验签成功。actual_public 应由相同 ID、W 和 KGC 主公钥
 * 按 P = W + lambda * Ppub 派生。
 *
 * @param[in] key 提供 SM2 曲线参数和 KGC 主公钥的上下文。
 * @param[in] identity 签名者身份标识 ID。
 * @param[in] identity_len 身份标识的字节长度。
 * @param[in] claimed_public 签名者声称公钥 W。
 * @param[in] actual_public 签名者实际公钥 P。
 * @param[in] message 待验证消息 M。
 * @param[in] message_len 消息的字节长度。
 * @param[in] signature 64 字节 r || s 格式签名。
 * @return 签名有效返回 1，无效或验证过程失败返回 0。
 */
int gmt0130_verify(const gmt0130_key *key, const unsigned char *identity,
                   size_t identity_len, const EC_POINT *claimed_public,
                   const EC_POINT *actual_public,
                   const unsigned char *message, size_t message_len,
                   const unsigned char signature[GMT0130_SIGNATURE_LEN]) {
  BN_CTX *ctx = BN_CTX_new();
  BIGNUM *r = BN_bin2bn(signature, FIELD_LEN, NULL);
  BIGNUM *s = BN_bin2bn(signature + FIELD_LEN, FIELD_LEN, NULL);
  BIGNUM *t = BN_new(), *x = BN_new(), *e = NULL, *result = BN_new();
  EC_POINT *point = EC_POINT_new(key->group);
  unsigned char ha[GMT0130_HA_LEN], digest[GMT0130_HA_LEN];
  int ok = 0;
  if (ctx == NULL || r == NULL || s == NULL || t == NULL || x == NULL ||
      result == NULL || point == NULL || !bn_in_range(r, key->order) ||
      !bn_in_range(s, key->order) ||
      !compute_ha(key->group, key->master_public, identity, identity_len, ha,
                  ctx) ||
      EC_POINT_is_on_curve(key->group, actual_public, ctx) != 1 ||
      EC_POINT_is_at_infinity(key->group, actual_public) ||
      !message_digest(key, claimed_public, ha, message, message_len, digest,
                      ctx) ||
      (e = BN_bin2bn(digest, sizeof(digest), NULL)) == NULL ||
      BN_mod_add(t, r, s, key->order, ctx) <= 0 || BN_is_zero(t) ||
      EC_POINT_mul(key->group, point, s, actual_public, t, ctx) <= 0 ||
      EC_POINT_is_at_infinity(key->group, point) ||
      EC_POINT_get_affine_coordinates(key->group, point, x, NULL, ctx) <= 0 ||
      BN_mod_add(result, e, x, key->order, ctx) <= 0)
    goto end;
  ok = BN_cmp(result, r) == 0;
end:
  BN_free(r);
  BN_free(s);
  BN_free(t);
  BN_free(x);
  BN_free(e);
  BN_free(result);
  EC_POINT_free(point);
  BN_CTX_free(ctx);
  return ok;
}
