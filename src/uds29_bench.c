#define _POSIX_C_SOURCE 200809L

#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/crypto.h>
#include <openssl/ec.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/obj_mac.h>
#include <openssl/rand.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>
#include <openssl/x509_vfy.h>
#include <openssl/x509v3.h>

#include <errno.h>
#include <inttypes.h>
#include <math.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#define UUID_LEN 16
#define CHAL_LEN 32
#define POINT_LEN 33
#define SCALAR_LEN 32
#define ECS_CRED_LEN (UUID_LEN + 2 * POINT_LEN)
#define ECS_SIG_LEN (POINT_LEN + SCALAR_LEN)
#define PHASES 4

enum { P_CREDENTIAL, P_CHALLENGE, P_SIGN, P_VERIFY };

typedef struct {
    double *v[PHASES];
    size_t n;
    size_t wire_2901, wire_6901, wire_2903, wire_6903;
    size_t cert_len, pub_len, sig_len_min, sig_len_max;
    const char *name;
} result_set;

typedef struct {
    EC_GROUP *group;
    BIGNUM *order, *master, *x, *d;
    EC_POINT *ppub, *X, *R;
    unsigned char uuid[UUID_LEN];
    unsigned char credential[ECS_CRED_LEN];
} ecs_ctx;

typedef struct {
    const char *name;
    const char *key_type;
    const char *group;
    int rsa, sm2;
    EVP_PKEY *ca_key, *leaf_key;
    X509 *ca_cert, *leaf_cert;
    X509_STORE *store;
    unsigned char *cert_der;
    int cert_der_len;
    unsigned char uuid[UUID_LEN];
} cert_ctx;

static uint64_t now_ns(void)
{
    struct timespec ts;
    if (clock_gettime(CLOCK_MONOTONIC_RAW, &ts) != 0) {
        perror("clock_gettime");
        exit(2);
    }
    return (uint64_t)ts.tv_sec * UINT64_C(1000000000) + (uint64_t)ts.tv_nsec;
}

static void ossl_fail(const char *where)
{
    fprintf(stderr, "ERROR: %s\n", where);
    ERR_print_errors_fp(stderr);
    exit(2);
}

#define CHECK_OSSL(x) do { if (!(x)) ossl_fail(#x); } while (0)
#define CHECK_ALLOC(x) do { if ((x) == NULL) ossl_fail(#x); } while (0)

static void put_u32(unsigned char out[4], size_t n)
{
    out[0] = (unsigned char)(n >> 24); out[1] = (unsigned char)(n >> 16);
    out[2] = (unsigned char)(n >> 8); out[3] = (unsigned char)n;
}

/* Length-prefix every field to make the transcript encoding unambiguous. */
static BIGNUM *hash_scalar(const EC_GROUP *group, const char *domain,
                          const unsigned char **parts, const size_t *lens,
                          size_t count, BN_CTX *bnctx)
{
    EVP_MD_CTX *m = EVP_MD_CTX_new();
    unsigned char digest[EVP_MAX_MD_SIZE], lenbuf[4];
    unsigned int dlen = 0;
    BIGNUM *h = NULL, *order = BN_new();
    size_t i;
    CHECK_ALLOC(m); CHECK_ALLOC(order);
    CHECK_OSSL(EVP_DigestInit_ex(m, EVP_sm3(), NULL));
    CHECK_OSSL(EVP_DigestUpdate(m, domain, strlen(domain)));
    for (i = 0; i < count; i++) {
        put_u32(lenbuf, lens[i]);
        CHECK_OSSL(EVP_DigestUpdate(m, lenbuf, sizeof(lenbuf)));
        CHECK_OSSL(EVP_DigestUpdate(m, parts[i], lens[i]));
    }
    CHECK_OSSL(EVP_DigestFinal_ex(m, digest, &dlen));
    CHECK_OSSL(EC_GROUP_get_order(group, order, bnctx));
    h = BN_bin2bn(digest, (int)dlen, NULL); CHECK_ALLOC(h);
    CHECK_OSSL(BN_mod(h, h, order, bnctx));
    EVP_MD_CTX_free(m); BN_free(order);
    return h;
}

static void random_nonzero(BIGNUM *r, const BIGNUM *order)
{
    do { CHECK_OSSL(BN_priv_rand_range(r, order)); } while (BN_is_zero(r));
}

static size_t point_oct(const EC_GROUP *g, const EC_POINT *p, unsigned char out[POINT_LEN], BN_CTX *ctx)
{
    size_t n = EC_POINT_point2oct(g, p, POINT_CONVERSION_COMPRESSED, out, POINT_LEN, ctx);
    if (n != POINT_LEN) ossl_fail("EC_POINT_point2oct");
    return n;
}

static void ecs_init(ecs_ctx *e)
{
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r = BN_new(), *h1 = NULL, *tmp = BN_new();
    unsigned char roct[POINT_LEN], poct[POINT_LEN];
    const unsigned char *parts[3]; size_t lens[3] = {UUID_LEN, POINT_LEN, POINT_LEN};
    memset(e, 0, sizeof(*e));
    CHECK_ALLOC(ctx); CHECK_ALLOC(r); CHECK_ALLOC(tmp);
    e->group = EC_GROUP_new_by_curve_name(NID_sm2); CHECK_ALLOC(e->group);
    e->order = BN_new(); e->master = BN_new(); e->x = BN_new(); e->d = BN_new();
    e->ppub = EC_POINT_new(e->group); e->X = EC_POINT_new(e->group); e->R = EC_POINT_new(e->group);
    CHECK_ALLOC(e->order); CHECK_ALLOC(e->master); CHECK_ALLOC(e->x); CHECK_ALLOC(e->d);
    CHECK_ALLOC(e->ppub); CHECK_ALLOC(e->X); CHECK_ALLOC(e->R);
    CHECK_OSSL(EC_GROUP_get_order(e->group, e->order, ctx));
    CHECK_OSSL(RAND_bytes(e->uuid, UUID_LEN));
    random_nonzero(e->master, e->order); random_nonzero(e->x, e->order); random_nonzero(r, e->order);
    CHECK_OSSL(EC_POINT_mul(e->group, e->ppub, e->master, NULL, NULL, ctx));
    CHECK_OSSL(EC_POINT_mul(e->group, e->X, e->x, NULL, NULL, ctx));
    CHECK_OSSL(EC_POINT_mul(e->group, e->R, r, NULL, NULL, ctx));
    point_oct(e->group, e->R, roct, ctx); point_oct(e->group, e->ppub, poct, ctx);
    parts[0] = e->uuid; parts[1] = roct; parts[2] = poct;
    h1 = hash_scalar(e->group, "UDS29-ECS-H1-v1", parts, lens, 3, ctx);
    CHECK_OSSL(BN_mod_mul(tmp, h1, e->master, e->order, ctx));
    CHECK_OSSL(BN_mod_add(e->d, r, tmp, e->order, ctx));
    memcpy(e->credential, e->uuid, UUID_LEN);
    point_oct(e->group, e->X, e->credential + UUID_LEN, ctx);
    point_oct(e->group, e->R, e->credential + UUID_LEN + POINT_LEN, ctx);
    BN_free(r); BN_free(h1); BN_free(tmp); BN_CTX_free(ctx);
}

static int ecs_parse_credential(const ecs_ctx *e, const unsigned char cred[ECS_CRED_LEN],
                                EC_POINT **Q)
{
    BN_CTX *ctx = BN_CTX_new(); EC_POINT *X = NULL, *R = NULL, *tmp = NULL;
    BIGNUM *h1 = NULL; unsigned char roct[POINT_LEN], poct[POINT_LEN]; int ok = 0;
    const unsigned char *parts[3]; size_t lens[3] = {UUID_LEN, POINT_LEN, POINT_LEN};
    *Q = NULL; X = EC_POINT_new(e->group); R = EC_POINT_new(e->group);
    tmp = EC_POINT_new(e->group); *Q = EC_POINT_new(e->group);
    if (ctx == NULL || X == NULL || R == NULL || tmp == NULL || *Q == NULL
        || memcmp(cred, e->uuid, UUID_LEN) != 0) goto end;
    if (!EC_POINT_oct2point(e->group, X, cred + UUID_LEN, POINT_LEN, ctx)
        || !EC_POINT_oct2point(e->group, R, cred + UUID_LEN + POINT_LEN, POINT_LEN, ctx)) goto end;
    if (EC_POINT_is_on_curve(e->group, X, ctx) != 1 || EC_POINT_is_on_curve(e->group, R, ctx) != 1
        || EC_POINT_is_at_infinity(e->group, X) || EC_POINT_is_at_infinity(e->group, R)) goto end;
    point_oct(e->group, R, roct, ctx); point_oct(e->group, e->ppub, poct, ctx);
    parts[0] = cred; parts[1] = roct; parts[2] = poct;
    h1 = hash_scalar(e->group, "UDS29-ECS-H1-v1", parts, lens, 3, ctx);
    if (!EC_POINT_mul(e->group, tmp, NULL, e->ppub, h1, ctx)
        || !EC_POINT_add(e->group, *Q, X, R, ctx)
        || !EC_POINT_add(e->group, *Q, *Q, tmp, ctx)) goto end;
    ok = !EC_POINT_is_at_infinity(e->group, *Q);
end:
    EC_POINT_free(X); EC_POINT_free(R); EC_POINT_free(tmp); BN_free(h1); BN_CTX_free(ctx);
    if (!ok) { EC_POINT_free(*Q); *Q = NULL; }
    return ok;
}

static int ecs_sign(const ecs_ctx *e, const unsigned char chal[CHAL_LEN], unsigned char sig[ECS_SIG_LEN])
{
    BN_CTX *ctx = BN_CTX_new(); BIGNUM *k = BN_new(), *h2 = NULL, *sum = BN_new(), *z = BN_new();
    EC_POINT *U = EC_POINT_new(e->group); unsigned char uoct[POINT_LEN];
    const unsigned char *parts[5]; size_t lens[5] = {UUID_LEN, POINT_LEN, POINT_LEN, CHAL_LEN, POINT_LEN};
    int ok = 0;
    if (!ctx || !k || !sum || !z || !U) goto end;
    random_nonzero(k, e->order);
    if (!EC_POINT_mul(e->group, U, k, NULL, NULL, ctx)) goto end;
    point_oct(e->group, U, uoct, ctx);
    parts[0] = e->uuid; parts[1] = e->credential + UUID_LEN;
    parts[2] = e->credential + UUID_LEN + POINT_LEN; parts[3] = chal; parts[4] = uoct;
    h2 = hash_scalar(e->group, "UDS29-ECS-H2-v1", parts, lens, 5, ctx);
    if (!BN_mod_add(sum, e->x, e->d, e->order, ctx)
        || !BN_mod_mul(z, h2, sum, e->order, ctx)
        || !BN_mod_add(z, z, k, e->order, ctx)) goto end;
    memcpy(sig, uoct, POINT_LEN);
    if (BN_bn2binpad(z, sig + POINT_LEN, SCALAR_LEN) != SCALAR_LEN) goto end;
    ok = 1;
end:
    BN_free(k); BN_free(h2); BN_free(sum); BN_free(z); EC_POINT_free(U); BN_CTX_free(ctx); return ok;
}

static int ecs_verify(const ecs_ctx *e, const unsigned char cred[ECS_CRED_LEN], const EC_POINT *Q,
                      const unsigned char chal[CHAL_LEN], const unsigned char sig[ECS_SIG_LEN])
{
    BN_CTX *ctx = BN_CTX_new(); BIGNUM *h2 = NULL, *z = NULL;
    EC_POINT *U = EC_POINT_new(e->group);
    EC_POINT *lhs = EC_POINT_new(e->group), *rhs = EC_POINT_new(e->group), *tmp = EC_POINT_new(e->group);
    int ok = 0; const unsigned char *p2[5];
    size_t l2[5] = {UUID_LEN,POINT_LEN,POINT_LEN,CHAL_LEN,POINT_LEN};
    if (!ctx || !U || !lhs || !rhs || !tmp) goto end;
    if (!EC_POINT_oct2point(e->group, U, sig, POINT_LEN, ctx)
        || EC_POINT_is_on_curve(e->group, U, ctx) != 1 || EC_POINT_is_at_infinity(e->group, U)) goto end;
    z = BN_bin2bn(sig + POINT_LEN, SCALAR_LEN, NULL);
    if (!z || BN_is_zero(z) || BN_cmp(z, e->order) >= 0) goto end;
    p2[0]=cred; p2[1]=cred+UUID_LEN; p2[2]=cred+UUID_LEN+POINT_LEN;
    p2[3]=chal; p2[4]=sig;
    h2=hash_scalar(e->group,"UDS29-ECS-H2-v1",p2,l2,5,ctx);
    /* 0x2901 cached Q = X + R + h1*Ppub; now check zP == U + h2*Q. */
    if (!EC_POINT_mul(e->group,tmp,NULL,Q,h2,ctx) || !EC_POINT_add(e->group,rhs,U,tmp,ctx)
        || !EC_POINT_mul(e->group,lhs,z,NULL,NULL,ctx)) goto end;
    ok = EC_POINT_cmp(e->group,lhs,rhs,ctx) == 0;
end:
    BN_free(h2); BN_free(z); EC_POINT_free(U);
    EC_POINT_free(lhs); EC_POINT_free(rhs); EC_POINT_free(tmp); BN_CTX_free(ctx); return ok;
}

static EVP_PKEY *make_key(const cert_ctx *c)
{
    EVP_PKEY *p;
    if (c->rsa) p = EVP_PKEY_Q_keygen(NULL, NULL, "RSA", (size_t)2048);
    else if (c->sm2) p = EVP_PKEY_Q_keygen(NULL, NULL, "SM2");
    else p = EVP_PKEY_Q_keygen(NULL, NULL, "EC", c->group);
    CHECK_ALLOC(p); return p;
}

static void uuid_hex(const unsigned char uuid[UUID_LEN], char out[2 * UUID_LEN + 1])
{
    static const char hex[] = "0123456789abcdef";
    size_t i;
    for (i = 0; i < UUID_LEN; i++) {
        out[2 * i] = hex[uuid[i] >> 4];
        out[2 * i + 1] = hex[uuid[i] & 15];
    }
    out[2 * UUID_LEN] = '\0';
}

static X509 *make_cert(EVP_PKEY *subject_key, const char *cn, X509 *issuer,
                       EVP_PKEY *issuer_key, long serial, int ca)
{
    X509 *x = X509_new(); X509_NAME *name = X509_NAME_new();
    X509_EXTENSION *ext = NULL; X509V3_CTX v3;
    CHECK_ALLOC(x); CHECK_ALLOC(name);
    CHECK_OSSL(X509_set_version(x, 2)); CHECK_OSSL(ASN1_INTEGER_set(X509_get_serialNumber(x), serial));
    CHECK_OSSL(X509_gmtime_adj(X509_getm_notBefore(x), -60));
    CHECK_OSSL(X509_gmtime_adj(X509_getm_notAfter(x), 86400L * 3650));
    CHECK_OSSL(X509_set_pubkey(x, subject_key));
    CHECK_OSSL(X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                                          (const unsigned char *)cn, -1, -1, 0));
    CHECK_OSSL(X509_set_subject_name(x, name));
    CHECK_OSSL(X509_set_issuer_name(x, issuer ? X509_get_subject_name(issuer) : name));
    X509V3_set_ctx(&v3, issuer ? issuer : x, x, NULL, NULL, 0);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_basic_constraints, ca ? "critical,CA:TRUE" : "critical,CA:FALSE");
    CHECK_ALLOC(ext); CHECK_OSSL(X509_add_ext(x, ext, -1)); X509_EXTENSION_free(ext);
    ext = X509V3_EXT_conf_nid(NULL, &v3, NID_key_usage, ca ? "critical,keyCertSign,cRLSign" : "critical,digitalSignature");
    CHECK_ALLOC(ext); CHECK_OSSL(X509_add_ext(x, ext, -1)); X509_EXTENSION_free(ext);
    EVP_PKEY *signing_key = issuer_key ? issuer_key : subject_key;
    CHECK_OSSL(X509_sign(x, signing_key,
                        EVP_PKEY_is_a(signing_key, "SM2") ? EVP_sm3() : EVP_sha256()));
    X509_NAME_free(name); return x;
}

static void cert_init(cert_ctx *c, const char *name, int rsa, int sm2)
{
    unsigned char *p; char identity[2 * UUID_LEN + 1];
    const char *root_name;
    memset(c, 0, sizeof(*c)); c->name=name; c->rsa=rsa; c->sm2=sm2;
    c->key_type=rsa?"RSA":(sm2?"SM2":"EC"); c->group=(rsa||sm2)?NULL:"prime256v1";
    CHECK_OSSL(RAND_bytes(c->uuid, UUID_LEN)); uuid_hex(c->uuid, identity);
    c->ca_key=make_key(c); c->leaf_key=make_key(c);
    root_name=rsa?"UDS RSA Test Root":(sm2?"UDS SM2 Test Root":"UDS ECDSA Test Root");
    c->ca_cert=make_cert(c->ca_key,root_name,NULL,NULL,1,1);
    c->leaf_cert=make_cert(c->leaf_key,identity,c->ca_cert,c->ca_key,2,0);
    c->cert_der_len=i2d_X509(c->leaf_cert,NULL); if(c->cert_der_len<=0) ossl_fail("i2d_X509 length");
    c->cert_der=OPENSSL_malloc((size_t)c->cert_der_len); CHECK_ALLOC(c->cert_der); p=c->cert_der;
    if(i2d_X509(c->leaf_cert,&p)!=c->cert_der_len) ossl_fail("i2d_X509");
    c->store=X509_STORE_new(); CHECK_ALLOC(c->store); CHECK_OSSL(X509_STORE_add_cert(c->store,c->ca_cert));
}

static EVP_PKEY *verify_cert_der(const cert_ctx *c)
{
    const unsigned char *p=c->cert_der; X509 *leaf=d2i_X509(NULL,&p,c->cert_der_len);
    X509_STORE_CTX *sctx=X509_STORE_CTX_new(); EVP_PKEY *pub=NULL;
    char actual[2 * UUID_LEN + 2], expected[2 * UUID_LEN + 1];
    if(!leaf||!sctx) goto end;
    uuid_hex(c->uuid, expected);
    if(!X509_STORE_CTX_init(sctx,c->store,leaf,NULL) || X509_verify_cert(sctx)!=1
       || X509_NAME_get_text_by_NID(X509_get_subject_name(leaf),NID_commonName,actual,sizeof(actual))<0
       || strcmp(actual,expected)!=0) goto end;
    pub=X509_get_pubkey(leaf);
end:
    X509_STORE_CTX_free(sctx); X509_free(leaf); return pub;
}

static int digest_sign(const cert_ctx *c, const unsigned char *msg, size_t mlen,
                       unsigned char *sig, size_t *slen)
{
    EVP_MD_CTX *m=EVP_MD_CTX_new(); EVP_PKEY_CTX *pk=NULL; int ok=0;
    if(!m) return 0;
    if(EVP_DigestSignInit_ex(m,&pk,c->sm2?"SM3":"SHA256",NULL,NULL,c->leaf_key,NULL)<=0) goto end;
    if(c->sm2 && EVP_PKEY_CTX_set1_id(pk,"1234567812345678",16)<=0) goto end;
    if(c->rsa && (EVP_PKEY_CTX_set_rsa_padding(pk,RSA_PKCS1_PSS_PADDING)<=0
       || EVP_PKEY_CTX_set_rsa_pss_saltlen(pk,RSA_PSS_SALTLEN_DIGEST)<=0)) goto end;
    ok=EVP_DigestSign(m,sig,slen,msg,mlen)>0;
end: EVP_MD_CTX_free(m); return ok;
}

static int digest_verify(const cert_ctx *c, EVP_PKEY *pub, const unsigned char *msg, size_t mlen,
                         const unsigned char *sig, size_t slen)
{
    EVP_MD_CTX *m=EVP_MD_CTX_new(); EVP_PKEY_CTX *pk=NULL; int ok=0;
    if(!m) return 0;
    if(EVP_DigestVerifyInit_ex(m,&pk,c->sm2?"SM3":"SHA256",NULL,NULL,pub,NULL)<=0) goto end;
    if(c->sm2 && EVP_PKEY_CTX_set1_id(pk,"1234567812345678",16)<=0) goto end;
    if(c->rsa && (EVP_PKEY_CTX_set_rsa_padding(pk,RSA_PKCS1_PSS_PADDING)<=0
       || EVP_PKEY_CTX_set_rsa_pss_saltlen(pk,RSA_PSS_SALTLEN_DIGEST)<=0)) goto end;
    ok=EVP_DigestVerify(m,sig,slen,msg,mlen)==1;
end: EVP_MD_CTX_free(m); return ok;
}

static void init_result(result_set *r, const char *name, size_t n)
{
    int p; memset(r,0,sizeof(*r)); r->name=name; r->n=n; r->sig_len_min=(size_t)-1;
    for(p=0;p<PHASES;p++){ r->v[p]=calloc(n,sizeof(double)); if(!r->v[p]){perror("calloc");exit(2);} }
}

static void run_ecs_once(const ecs_ctx *e, result_set *r, size_t idx, int record)
{
    unsigned char chal[CHAL_LEN], sig[ECS_SIG_LEN]; EC_POINT *Q=NULL; uint64_t a,b;
    a=now_ns(); if(!ecs_parse_credential(e,e->credential,&Q)) ossl_fail("ECS credential"); b=now_ns();
    if(record) r->v[P_CREDENTIAL][idx]=(double)(b-a)/1000.0;
    a=now_ns(); CHECK_OSSL(RAND_bytes(chal,sizeof(chal))); b=now_ns(); if(record)r->v[P_CHALLENGE][idx]=(double)(b-a)/1000.0;
    a=now_ns(); CHECK_OSSL(ecs_sign(e,chal,sig)); b=now_ns(); if(record)r->v[P_SIGN][idx]=(double)(b-a)/1000.0;
    a=now_ns(); if(!ecs_verify(e,e->credential,Q,chal,sig))ossl_fail("ECS verify"); b=now_ns(); if(record)r->v[P_VERIFY][idx]=(double)(b-a)/1000.0;
    EC_POINT_free(Q);
}

static void run_cert_once(const cert_ctx *c, result_set *r, size_t idx, int record)
{
    unsigned char transcript[UUID_LEN+CHAL_LEN],sig[512]; size_t slen=sizeof(sig); EVP_PKEY *pub; uint64_t a,b;
    memcpy(transcript,c->uuid,UUID_LEN);
    a=now_ns(); pub=verify_cert_der(c); if(!pub)ossl_fail("certificate validation"); b=now_ns();
    if(record)r->v[P_CREDENTIAL][idx]=(double)(b-a)/1000.0;
    a=now_ns();CHECK_OSSL(RAND_bytes(transcript+UUID_LEN,CHAL_LEN));b=now_ns();if(record)r->v[P_CHALLENGE][idx]=(double)(b-a)/1000.0;
    a=now_ns();CHECK_OSSL(digest_sign(c,transcript,sizeof(transcript),sig,&slen));b=now_ns();if(record)r->v[P_SIGN][idx]=(double)(b-a)/1000.0;
    a=now_ns();if(!digest_verify(c,pub,transcript,sizeof(transcript),sig,slen))ossl_fail("signature verify");b=now_ns();if(record)r->v[P_VERIFY][idx]=(double)(b-a)/1000.0;
    if(record){if(slen<r->sig_len_min)r->sig_len_min=slen;if(slen>r->sig_len_max)r->sig_len_max=slen;}
    EVP_PKEY_free(pub);
}

static int cmp_double(const void *a,const void *b){double x=*(const double*)a,y=*(const double*)b;return(x>y)-(x<y);}
typedef struct {double mean,sd,median,p95;} summary;
static summary summarize(const double *v,size_t n)
{
    summary s={0}; double *copy=malloc(n*sizeof(*copy)),ss=0;size_t i;
    if(!copy){perror("malloc");exit(2);} memcpy(copy,v,n*sizeof(*copy));qsort(copy,n,sizeof(*copy),cmp_double);
    for(i=0;i<n;i++) s.mean+=v[i];
    s.mean/=n;
    for(i=0;i<n;i++){double d=v[i]-s.mean;ss+=d*d;}
    s.sd=n>1?sqrt(ss/(n-1)):0;s.median=copy[n/2];s.p95=copy[(size_t)floor(0.95*(double)(n-1))];free(copy);return s;
}

static void report(result_set *r,FILE *csv)
{
    const char *pn[PHASES]={"2901_credential","6901_challenge","2903_sign","6903_verify"};
    double *total=calloc(r->n,sizeof(*total));size_t i;int p;summary s;
    if(!total){perror("calloc");exit(2);} printf("\n%-18s wire=%zu bytes (2901=%zu,6901=%zu,2903=%zu,6903=%zu)\n",r->name,r->wire_2901+r->wire_6901+r->wire_2903+r->wire_6903,r->wire_2901,r->wire_6901,r->wire_2903,r->wire_6903);
    for(p=0;p<PHASES;p++){for(i=0;i<r->n;i++)total[i]+=r->v[p][i];s=summarize(r->v[p],r->n);printf("  %-18s mean=%9.3f us  median=%9.3f  p95=%9.3f  sd=%8.3f\n",pn[p],s.mean,s.median,s.p95,s.sd);if(csv)fprintf(csv,"%s,%s,%.6f,%.6f,%.6f,%.6f,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",r->name,pn[p],s.mean,s.median,s.p95,s.sd,r->wire_2901,r->wire_6901,r->wire_2903,r->wire_6903,r->cert_len,r->pub_len,r->sig_len_min,r->sig_len_max);}
    s=summarize(total,r->n);printf("  %-18s mean=%9.3f us  median=%9.3f  p95=%9.3f  sd=%8.3f\n","crypto_total",s.mean,s.median,s.p95,s.sd);if(csv)fprintf(csv,"%s,total,%.6f,%.6f,%.6f,%.6f,%zu,%zu,%zu,%zu,%zu,%zu,%zu,%zu\n",r->name,s.mean,s.median,s.p95,s.sd,r->wire_2901,r->wire_6901,r->wire_2903,r->wire_6903,r->cert_len,r->pub_len,r->sig_len_min,r->sig_len_max);free(total);
}

static void negative_cert_test(const cert_ctx *c, const unsigned char chal[CHAL_LEN],
                               unsigned char sig[512])
{
    unsigned char transcript[UUID_LEN+CHAL_LEN],bad[UUID_LEN+CHAL_LEN];
    size_t n=512; EVP_PKEY *p;
    memcpy(transcript,c->uuid,UUID_LEN);memcpy(transcript+UUID_LEN,chal,CHAL_LEN);
    memcpy(bad,transcript,sizeof(bad));bad[UUID_LEN]^=1;
    CHECK_OSSL(digest_sign(c,transcript,sizeof(transcript),sig,&n));
    p=verify_cert_der(c);CHECK_ALLOC(p);
    if(digest_verify(c,p,bad,sizeof(bad),sig,n))ossl_fail("certificate scheme negative test");
    EVP_PKEY_free(p);
}

static void negative_tests(const ecs_ctx *e,const cert_ctx *rsa,const cert_ctx *ecdsa,
                           const cert_ctx *sm2)
{
    unsigned char chal[CHAL_LEN]={0},bad[CHAL_LEN],esig[ECS_SIG_LEN],sig[512];EC_POINT *Q=NULL;
    memcpy(bad,chal,sizeof(bad));bad[0]^=1;CHECK_OSSL(ecs_parse_credential(e,e->credential,&Q));CHECK_OSSL(ecs_sign(e,chal,esig));if(ecs_verify(e,e->credential,Q,bad,esig))ossl_fail("ECS negative test");EC_POINT_free(Q);
    negative_cert_test(rsa,chal,sig);negative_cert_test(ecdsa,chal,sig);negative_cert_test(sm2,chal,sig);
}

static void free_ecs(ecs_ctx *e){BN_free(e->order);BN_clear_free(e->master);BN_clear_free(e->x);BN_clear_free(e->d);EC_POINT_free(e->ppub);EC_POINT_free(e->X);EC_POINT_free(e->R);EC_GROUP_free(e->group);}
static void free_cert(cert_ctx *c){EVP_PKEY_free(c->ca_key);EVP_PKEY_free(c->leaf_key);X509_free(c->ca_cert);X509_free(c->leaf_cert);X509_STORE_free(c->store);OPENSSL_free(c->cert_der);}
static void free_result(result_set *r){int p;for(p=0;p<PHASES;p++)free(r->v[p]);}

int main(int argc,char **argv)
{
    size_t iterations=2000,warmup=200,i;const char *csv_path=NULL;FILE *csv=NULL;ecs_ctx ecs;cert_ctx rsa,ecdsa,sm2;result_set re,rr,rc,rs;
    for(int a=1;a<argc;a++){if(!strcmp(argv[a],"--iterations")&&a+1<argc)iterations=strtoull(argv[++a],NULL,10);else if(!strcmp(argv[a],"--warmup")&&a+1<argc)warmup=strtoull(argv[++a],NULL,10);else if(!strcmp(argv[a],"--csv")&&a+1<argc)csv_path=argv[++a];else{fprintf(stderr,"usage: %s [--iterations N] [--warmup N] [--csv FILE]\n",argv[0]);return 2;}}
    if(iterations<2){fprintf(stderr,"iterations must be >= 2\n");return 2;}
    ecs_init(&ecs);cert_init(&rsa,"RSA-2048-PSS+X509",1,0);cert_init(&ecdsa,"ECDSA-P256+X509",0,0);
    cert_init(&sm2,"SM2-SM3+X509",0,1);negative_tests(&ecs,&rsa,&ecdsa,&sm2);
    init_result(&re,"CL-ECS-SM2",iterations);init_result(&rr,rsa.name,iterations);init_result(&rc,ecdsa.name,iterations);init_result(&rs,sm2.name,iterations);
    re.pub_len=2*POINT_LEN;re.cert_len=0;re.sig_len_min=re.sig_len_max=ECS_SIG_LEN;
    rr.pub_len=256;rr.cert_len=(size_t)rsa.cert_der_len;rc.pub_len=POINT_LEN;rc.cert_len=(size_t)ecdsa.cert_der_len;rs.pub_len=POINT_LEN;rs.cert_len=(size_t)sm2.cert_der_len;
    re.wire_2901=2+ECS_CRED_LEN;re.wire_6901=2+CHAL_LEN;re.wire_2903=2+ECS_SIG_LEN;re.wire_6903=3;
    rr.wire_2901=2+UUID_LEN+(size_t)rsa.cert_der_len;rr.wire_6901=2+CHAL_LEN;rr.wire_6903=3;
    rc.wire_2901=2+UUID_LEN+(size_t)ecdsa.cert_der_len;rc.wire_6901=2+CHAL_LEN;rc.wire_6903=3;
    rs.wire_2901=2+UUID_LEN+(size_t)sm2.cert_der_len;rs.wire_6901=2+CHAL_LEN;rs.wire_6903=3;
    for(i=0;i<warmup;i++){run_ecs_once(&ecs,&re,0,0);run_cert_once(&rsa,&rr,0,0);run_cert_once(&ecdsa,&rc,0,0);run_cert_once(&sm2,&rs,0,0);}
    for(i=0;i<iterations;i++){switch(i%4){
        case 0:run_ecs_once(&ecs,&re,i,1);run_cert_once(&rsa,&rr,i,1);run_cert_once(&ecdsa,&rc,i,1);run_cert_once(&sm2,&rs,i,1);break;
        case 1:run_cert_once(&rsa,&rr,i,1);run_cert_once(&ecdsa,&rc,i,1);run_cert_once(&sm2,&rs,i,1);run_ecs_once(&ecs,&re,i,1);break;
        case 2:run_cert_once(&ecdsa,&rc,i,1);run_cert_once(&sm2,&rs,i,1);run_ecs_once(&ecs,&re,i,1);run_cert_once(&rsa,&rr,i,1);break;
        default:run_cert_once(&sm2,&rs,i,1);run_ecs_once(&ecs,&re,i,1);run_cert_once(&rsa,&rr,i,1);run_cert_once(&ecdsa,&rc,i,1);}}
    rr.wire_2903=2+rr.sig_len_max;rc.wire_2903=2+rc.sig_len_max;rs.wire_2903=2+rs.sig_len_max;
    if(csv_path){csv=fopen(csv_path,"w");if(!csv){fprintf(stderr,"%s: %s\n",csv_path,strerror(errno));return 2;}fprintf(csv,"scheme,phase,mean_us,median_us,p95_us,sd_us,wire_2901,wire_6901,wire_2903,wire_6903,cert_bytes,public_key_bytes,sig_min_bytes,sig_max_bytes\n");}
    printf("Tongsuo/OpenSSL: %s\niterations=%zu warmup=%zu challenge=%d bytes; negative tests=PASS\n",OpenSSL_version(OPENSSL_VERSION),iterations,warmup,CHAL_LEN);
    report(&re,csv);report(&rr,csv);report(&rc,csv);report(&rs,csv);if(csv)fclose(csv);
    free_result(&re);free_result(&rr);free_result(&rc);free_result(&rs);free_ecs(&ecs);free_cert(&rsa);free_cert(&ecdsa);free_cert(&sm2);return 0;
}
