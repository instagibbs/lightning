#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <ccan/mem/mem.h>
#include <ccan/str/hex/hex.h>
#include <common/utils.h>
#include <wire/wire.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

bool pubkey_from_der(const u8 *der, size_t len, struct pubkey *key)
{
	if (len != PUBKEY_CMPR_LEN)
		return false;

	if (!secp256k1_ec_pubkey_parse(secp256k1_ctx, &key->pubkey,
				       memcheck(der, len), len))
		return false;

	return true;
}

void pubkey_to_der(u8 der[PUBKEY_CMPR_LEN], const struct pubkey *key)
{
	size_t outlen = PUBKEY_CMPR_LEN;
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen,
					   &key->pubkey,
					   SECP256K1_EC_COMPRESSED))
		abort();
	assert(outlen == PUBKEY_CMPR_LEN);
}

bool pubkey_from_secret(const struct secret *secret, struct pubkey *key)
{
	if (!secp256k1_ec_pubkey_create(secp256k1_ctx,
					&key->pubkey, secret->data))
		return false;
	return true;
}

bool pubkey_from_privkey(const struct privkey *privkey,
			 struct pubkey *key)
{
	return pubkey_from_secret(&privkey->secret, key);
}

bool pubkey_from_hexstr(const char *derstr, size_t slen, struct pubkey *key)
{
	size_t dlen;
	unsigned char der[PUBKEY_CMPR_LEN];

	dlen = hex_data_size(slen);
	if (dlen != sizeof(der))
		return false;

	if (!hex_decode(derstr, slen, der, dlen))
		return false;

	return pubkey_from_der(der, dlen, key);
}

char *fmt_pubkey(const tal_t *ctx, const struct pubkey *key)
{
	unsigned char der[PUBKEY_CMPR_LEN];

	pubkey_to_der(der, key);
	return tal_hexstr(ctx, der, sizeof(der));
}

char *fmt_secp256k1_pubkey(const tal_t *ctx, const secp256k1_pubkey *key)
{
	unsigned char der[PUBKEY_CMPR_LEN];
	size_t outlen = sizeof(der);
	if (!secp256k1_ec_pubkey_serialize(secp256k1_ctx, der, &outlen, key,
					   SECP256K1_EC_COMPRESSED))
		abort();
	assert(outlen == sizeof(der));
	return tal_hexstr(ctx, der, sizeof(der));
}

int pubkey_cmp(const struct pubkey *a, const struct pubkey *b)
{
	u8 keya[PUBKEY_CMPR_LEN], keyb[PUBKEY_CMPR_LEN];
	pubkey_to_der(keya, a);
	pubkey_to_der(keyb, b);
	return memcmp(keya, keyb, sizeof(keya));
}

void pubkey_to_hash160(const struct pubkey *pk, struct ripemd160 *hash)
{
	u8 der[PUBKEY_CMPR_LEN];
	struct sha256 h;

	pubkey_to_der(der, pk);
	sha256(&h, der, sizeof(der));
	ripemd160(hash, h.u.u8, sizeof(h));
}

void fromwire_pubkey(const u8 **cursor, size_t *max, struct pubkey *pubkey)
{
	u8 der[PUBKEY_CMPR_LEN];

	if (!fromwire(cursor, max, der, sizeof(der)))
		return;

	if (!pubkey_from_der(der, sizeof(der), pubkey)) {
		SUPERVERBOSE("not a valid point");
		fromwire_fail(cursor, max);
	}
}

void towire_pubkey(u8 **pptr, const struct pubkey *pubkey)
{
	u8 output[PUBKEY_CMPR_LEN];
	size_t outputlen = sizeof(output);

	secp256k1_ec_pubkey_serialize(secp256k1_ctx, output, &outputlen,
				      &pubkey->pubkey,
				      SECP256K1_EC_COMPRESSED);

	towire(pptr, output, outputlen);
}

void fromwire_point32(const u8 **cursor, size_t *max, struct point32 *point32)
{
	u8 raw[32];

	if (!fromwire(cursor, max, raw, sizeof(raw)))
		return;

	if (secp256k1_xonly_pubkey_parse(secp256k1_ctx,
					 &point32->pubkey,
					 raw) != 1) {
		SUPERVERBOSE("not a valid point");
		fromwire_fail(cursor, max);
	}
}

void towire_point32(u8 **pptr, const struct point32 *point32)
{
	u8 output[32];

	secp256k1_xonly_pubkey_serialize(secp256k1_ctx, output,
					 &point32->pubkey);
	towire(pptr, output, sizeof(output));
}

void fromwire_nonce(const u8 **cursor, size_t *max, struct nonce *nonce)
{
    u8 raw[66];

    if (!fromwire(cursor, max, raw, sizeof(raw)))
        return;

    if (!secp256k1_musig_pubnonce_parse(secp256k1_ctx,
            &nonce->nonce,
            raw)) {
        SUPERVERBOSE("not a valid musig nonce");
        fromwire_fail(cursor, max);
    }
}

void towire_nonce(u8 **pptr, const struct nonce *nonce)
{
    u8 nonce_output[66];

    secp256k1_musig_pubnonce_serialize(secp256k1_ctx,
        nonce_output,
        &nonce->nonce);

	towire(pptr, nonce_output, sizeof(nonce_output));
}

static char *point32_to_hexstr(const tal_t *ctx, const struct point32 *point32)
{
	u8 output[32];

	secp256k1_xonly_pubkey_serialize(secp256k1_ctx, output,
					 &point32->pubkey);
	return tal_hexstr(ctx, output, sizeof(output));
}
REGISTER_TYPE_TO_STRING(point32, point32_to_hexstr);

static char *nonce_to_hexstr(const tal_t *ctx, const struct nonce *nonce)
{
    u8 nonce_output[66];

    secp256k1_musig_pubnonce_serialize(secp256k1_ctx,
        nonce_output,
        &nonce->nonce);

    return tal_hexstr(ctx, nonce_output, sizeof(nonce_output));
}
REGISTER_TYPE_TO_STRING(nonce, nonce_to_hexstr);
