#include "config.h"
#include <assert.h>
#include <bitcoin/privkey.h>
#include <bitcoin/psbt.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/shadouble.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <ccan/mem/mem.h>
#include <common/type_to_string.h>
#include <wire/wire.h>
#include <sodium/randombytes.h>

#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

#undef DEBUG
#ifdef DEBUG
# include <ccan/err/err.h>
# include <stdio.h>
#define SHA_FMT					   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"	   \
	"%02x%02x%02x%02x%02x%02x%02x%02x"

#define SHA_VALS(e)							\
	e[0], e[1], e[2], e[3], e[4], e[5], e[6], e[7],			\
		e[8], e[9], e[10], e[11], e[12], e[13], e[14], e[15],	\
		e[16], e[17], e[18], e[19], e[20], e[21], e[22], e[23], \
		e[24], e[25], e[25], e[26], e[28], e[29], e[30], e[31]

static void dump_tx(const char *msg,
		    const struct bitcoin_tx *tx, size_t inputnum,
		    const u8 *script,
		    const struct pubkey *key,
            const struct point32 *x_key,
		    const struct sha256_double *h)
{
	size_t i, j;
	warnx("%s tx version %u locktime %#x:",
	      msg, tx->wtx->version, tx->wtx->locktime);
	for (i = 0; i < tx->wtx->num_inputs; i++) {
		warnx("input[%zu].txid = "SHA_FMT, i,
		      SHA_VALS(tx->wtx->inputs[i].txhash));
		warnx("input[%zu].index = %u", i, tx->wtx->inputs[i].index);
	}
	for (i = 0; i < tx->wtx->num_outputs; i++) {
		warnx("output[%zu].amount = %llu",
		      i, (long long)tx->wtx->outputs[i].satoshi);
		warnx("output[%zu].script = %zu",
		      i, tx->wtx->outputs[i].script_len);
		for (j = 0; j < tx->wtx->outputs[i].script_len; j++)
			fprintf(stderr, "%02x", tx->wtx->outputs[i].script[j]);
		fprintf(stderr, "\n");
	}
	warnx("input[%zu].script = %zu", inputnum, tal_count(script));
	for (i = 0; i < tal_count(script); i++)
		fprintf(stderr, "%02x", script[i]);
	if (key) {
		fprintf(stderr, "\nPubkey: ");
		for (i = 0; i < sizeof(key->pubkey); i++)
			fprintf(stderr, "%02x", ((u8 *)&key->pubkey)[i]);
		fprintf(stderr, "\n");
	} else if (x_key) {
		fprintf(stderr, "\nPubkey: ");
		for (i = 0; i < sizeof(x_key->pubkey); i++)
			fprintf(stderr, "%02x", ((u8 *)&x_key->pubkey)[i]);
		fprintf(stderr, "\n");
	}
	if (h) {
		fprintf(stderr, "\nHash: ");
		for (i = 0; i < sizeof(h->sha.u.u8); i++)
			fprintf(stderr, "%02x", h->sha.u.u8[i]);
		fprintf(stderr, "\n");
	}
}
#else
static void dump_tx(const char *msg UNUSED,
		    const struct bitcoin_tx *tx UNUSED, size_t inputnum UNUSED,
		    const u8 *script UNUSED,
		    const struct pubkey *key UNUSED,
            const struct point32 *x_key,
		    const struct sha256_double *h UNUSED)
{
}
#endif

/* Taken from https://github.com/bitcoin/bitcoin/blob/master/src/key.cpp */
/* Check that the sig has a low R value and will be less than 71 bytes */
static bool sig_has_low_r(const secp256k1_ecdsa_signature* sig)
{
	unsigned char compact_sig[64];
	secp256k1_ecdsa_signature_serialize_compact(secp256k1_ctx, compact_sig, sig);

	/* In DER serialization, all values are interpreted as big-endian, signed
	 * integers. The highest bit in the integer indicates its signed-ness; 0 is
	 * positive, 1 is negative. When the value is interpreted as a negative
	 * integer, it must be converted to a positive value by prepending a 0x00
	 * byte so that the highest bit is 0. We can avoid this prepending by
	 * ensuring that our highest bit is always 0, and thus we must check that
	 * the first byte is less than 0x80. */
	return compact_sig[0] < 0x80;
}

#if DEVELOPER
/* Some of the spec test vectors assume no sig grinding. */
extern bool dev_no_grind;

bool dev_no_grind = false;
#endif

void sign_hash(const struct privkey *privkey,
	       const struct sha256_double *h,
	       secp256k1_ecdsa_signature *s)
{
	bool ok;
	unsigned char extra_entropy[32] = {0};

	/* Grind for low R */
	do {
		ok = secp256k1_ecdsa_sign(secp256k1_ctx,
					  s,
					  h->sha.u.u8,
					  privkey->secret.data, NULL,
					  IFDEV(dev_no_grind ? NULL
						: extra_entropy,
						extra_entropy));
		((u32 *)extra_entropy)[0]++;
		if (IFDEV(dev_no_grind, false))
			break;
	} while (!sig_has_low_r(s));

	assert(ok);
}

void bip340_sign_hash(const struct privkey *privkey,
	       const struct sha256_double *hash,
	       struct bip340sig *sig)
{
	bool ok;
    secp256k1_xonly_pubkey pubkey;
    secp256k1_keypair keypair;

    ok = secp256k1_keypair_create(secp256k1_ctx,
                  &keypair,
                  privkey->secret.data);

    assert(ok);

    ok = secp256k1_schnorrsig_sign32(secp256k1_ctx,
                  sig->u8,
                  hash->sha.u.u8,
                  &keypair, /* aux_rand32 */ NULL);


    ok = secp256k1_keypair_xonly_pub(secp256k1_ctx, &pubkey, NULL /* pk_parity */, &keypair);
	assert(ok);

    assert(secp256k1_schnorrsig_verify(secp256k1_ctx, sig->u8, hash->sha.u.u8, sizeof(hash->sha.u.u8), &pubkey));
}

void bipmusig_inner_pubkey(struct pubkey *inner_pubkey,
           secp256k1_musig_keyagg_cache *keyagg_cache,
           const struct pubkey * const* pubkeys,
           size_t n_pubkeys)
{
    int i, ok;
    assert(n_pubkeys <= 100);

    /* Sorting moves pubkeys themselves, we copy and discard after */
    secp256k1_xonly_pubkey x_keys[100];
    const secp256k1_xonly_pubkey *x_keys_ptr[100];

    for (i=0; i < n_pubkeys; ++i) {
        ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &x_keys[i], /* pk_parity */ NULL,
            &(pubkeys[i]->pubkey));
        assert(ok);
        x_keys_ptr[i] = &x_keys[i];
    }

    ok = secp256k1_xonly_sort(secp256k1_ctx,
        x_keys_ptr,
        n_pubkeys);

    assert(ok);

    ok = secp256k1_musig_pubkey_agg(secp256k1_ctx,
        NULL /* scratch */,
        NULL /* agg_pk */,
        keyagg_cache,
        x_keys_ptr,
        n_pubkeys); 

    assert(ok);

    ok = secp256k1_musig_pubkey_get(secp256k1_ctx,
        &inner_pubkey->pubkey,
        keyagg_cache);

    assert(ok);
}

void bipmusig_finalize_keys(struct pubkey *agg_pk,
           secp256k1_musig_keyagg_cache *keyagg_cache,
           const struct pubkey * const* pubkeys,
           size_t n_pubkeys,
           const struct sha256 *tap_merkle_root,
           unsigned char *tap_tweak_out,
		   struct pubkey *inner_pubkey)
{
    int i, ok;
    unsigned char taptweak_preimage[64];
    secp256k1_xonly_pubkey agg_x_key;
    assert(n_pubkeys <= 100);

    /* Sorting moves pubkeys themselves, we copy and discard after */
    secp256k1_xonly_pubkey x_keys[100];
    const secp256k1_xonly_pubkey *x_keys_ptr[100];

    for (i=0; i < n_pubkeys; ++i) {
        ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &x_keys[i], /* pk_parity */ NULL,
            &(pubkeys[i]->pubkey));
        assert(ok);
        x_keys_ptr[i] = &x_keys[i];
    }

    ok = secp256k1_xonly_sort(secp256k1_ctx,
        x_keys_ptr,
        n_pubkeys);

    assert(ok);

    ok = secp256k1_musig_pubkey_agg(secp256k1_ctx,
        NULL /* scratch */,
        &agg_x_key,
        keyagg_cache,
        x_keys_ptr,
        n_pubkeys); 

    assert(ok);

	if (inner_pubkey) {
		ok = secp256k1_musig_pubkey_get(secp256k1_ctx,
			&inner_pubkey->pubkey,
			keyagg_cache);

		assert(ok);
	}

    ok = secp256k1_xonly_pubkey_serialize(secp256k1_ctx, taptweak_preimage, &agg_x_key);

    assert(ok);

    if (!tap_merkle_root) {
        /* No-tapscript recommended commitment: Q = P + int(hashTapTweak(bytes(P)))G */
        ok = wally_tagged_hash(taptweak_preimage, 32, is_elements(chainparams) ? "TapTweak/elements" : "TapTweak", tap_tweak_out);
        assert(ok == WALLY_OK);
        ok = secp256k1_musig_pubkey_xonly_tweak_add(secp256k1_ctx, &(agg_pk->pubkey), keyagg_cache, tap_tweak_out);
        assert(ok);
    } else {
        /* Otherwise: Q = P + int(hashTapTweak(bytes(P)||tap_merkle_root))G */
        memcpy(taptweak_preimage + 32, tap_merkle_root->u.u8, sizeof(tap_merkle_root->u.u8));
        ok = wally_tagged_hash(taptweak_preimage, sizeof(taptweak_preimage), is_elements(chainparams) ? "TapTweak/elements" : "TapTweak", tap_tweak_out);
        assert(ok == WALLY_OK);
        ok = secp256k1_musig_pubkey_xonly_tweak_add(secp256k1_ctx, &(agg_pk->pubkey), keyagg_cache, tap_tweak_out);
        assert(ok);
    }
}

void bipmusig_gen_nonce(secp256k1_musig_secnonce *secnonce,
           secp256k1_musig_pubnonce *pubnonce,
           const struct privkey *privkey,
           secp256k1_musig_keyagg_cache *keyagg_cache,
           const unsigned char *msg32)
{
    /* MUST be unique for each signing attempt or SFYL */
    /* FIXME Does it help at all to get 32 more bytes of randomness? */
    unsigned char session_id[32];
    int ok;

    randombytes_buf(session_id, sizeof(session_id));

    ok = secp256k1_musig_nonce_gen(secp256k1_ctx, secnonce, pubnonce, session_id, privkey->secret.data, msg32, keyagg_cache, NULL /* extra_input32 */);

    assert(ok);
}

void bipmusig_partial_sign(const struct privkey *privkey,
           secp256k1_musig_secnonce *secnonce,
           const secp256k1_musig_pubnonce * const *pubnonces,
           size_t num_signers,
           struct sha256_double *msg32,
           secp256k1_musig_keyagg_cache *cache,
           secp256k1_musig_session *session,
	       secp256k1_musig_partial_sig *p_sig)
{
	bool ok;
    secp256k1_keypair keypair;
    secp256k1_musig_aggnonce agg_pubnonce;

    /* Create aggregate nonce and initialize the session */
    ok = secp256k1_musig_nonce_agg(secp256k1_ctx, &agg_pubnonce, pubnonces, num_signers);

    assert(ok);

    ok = secp256k1_musig_nonce_process(secp256k1_ctx, session, &agg_pubnonce, msg32->sha.u.u8, cache, /* adaptor */ NULL);

    assert(ok);

    ok = secp256k1_keypair_create(secp256k1_ctx,
                  &keypair,
                  privkey->secret.data);

    assert(ok);

    ok = secp256k1_musig_partial_sign(secp256k1_ctx, p_sig, secnonce, &keypair, cache, session);

    assert(ok);
}

bool bipmusig_partial_sigs_combine_verify(const secp256k1_musig_partial_sig * const *p_sigs,
           size_t num_signers,
           const struct pubkey *agg_pk,
           secp256k1_musig_session *session,
           const struct sha256_double *hash,
           struct bip340sig *sig)
{
    int ret;
    secp256k1_xonly_pubkey xonly_inner_pubkey;

    ret = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
        &xonly_inner_pubkey,
        NULL /* pk_parity */,
        &agg_pk->pubkey);

    if (!ret) {
        return false;
    }

    ret = secp256k1_musig_partial_sig_agg(secp256k1_ctx, sig->u8, session, p_sigs, num_signers);

    if (!ret) {
        return false;
    }

    return secp256k1_schnorrsig_verify(secp256k1_ctx, sig->u8, hash->sha.u.u8, sizeof(hash->sha.u.u8), &xonly_inner_pubkey);
}

bool bipmusig_partial_sig_verify(const struct partial_sig *p_sig,
								const struct nonce *signer_nonce,
								const struct pubkey *signer_pk,
								const struct musig_keyagg_cache *keyagg_cache,
								struct musig_session *session)
{
    int ret;
    secp256k1_xonly_pubkey xonly_inner_pubkey;

    ret = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
        &xonly_inner_pubkey,
        NULL /* pk_parity */,
        &signer_pk->pubkey);

    if (!ret) {
        return false;
    }

	return secp256k1_musig_partial_sig_verify(secp256k1_ctx,
												&p_sig->p_sig,
												&signer_nonce->nonce,
												&xonly_inner_pubkey,
												&keyagg_cache->cache,
												&session->session);
}

bool bipmusig_partial_sigs_combine(const secp256k1_musig_partial_sig * const *p_sigs,
           size_t num_signers,
           const secp256k1_musig_session *session,
           struct bip340sig *sig)
{
    return secp256k1_musig_partial_sig_agg(secp256k1_ctx, sig->u8, session, p_sigs, num_signers);
}

void bitcoin_tx_hash_for_sig(const struct bitcoin_tx *tx, unsigned int in,
			     const u8 *script,
			     enum sighash_type sighash_type,
			     struct sha256_double *dest)
{
	int ret;
	u8 value[9];
	u64 input_val_sats;
	struct amount_sat input_amt;
	int flags = WALLY_TX_FLAG_USE_WITNESS;

	input_amt = psbt_input_get_amount(tx->psbt, in);
	input_val_sats = input_amt.satoshis; /* Raw: type conversion */

	/* Wally can allocate here, iff tx doesn't fit on stack */
	tal_wally_start();
	if (is_elements(chainparams)) {
		ret = wally_tx_confidential_value_from_satoshi(input_val_sats, value, sizeof(value));
		assert(ret == WALLY_OK);
		ret = wally_tx_get_elements_signature_hash(
		    tx->wtx, in, script, tal_bytelen(script), value,
		    sizeof(value), sighash_type, flags, dest->sha.u.u8,
		    sizeof(*dest));
		assert(ret == WALLY_OK);
	} else {
		ret = wally_tx_get_btc_signature_hash(
		    tx->wtx, in, script, tal_bytelen(script), input_val_sats,
		    sighash_type, flags, dest->sha.u.u8, sizeof(*dest));
		assert(ret == WALLY_OK);
	}
	tal_wally_end(tx->wtx);
}

void bitcoin_tx_taproot_hash_for_sig(const struct bitcoin_tx *tx,
                 unsigned int input_index,
			     enum sighash_type sighash_type, /* FIXME get from PSBT? */
                 const unsigned char *tapleaf_script, /* FIXME Get directly from PSBT? */
                 u8 *annex,
			     struct sha256_double *dest)
{
	/* HACK: don't actually compute sighashes for elements but let it through */
	if (is_elements(chainparams))
		return;

	int ret, i;

    /* Preparing args for taproot*/
    size_t input_count = tx->wtx->num_inputs;
    const unsigned char *input_spks[input_count];
    size_t input_spk_lens[input_count];
	u64 input_val_sats[input_count];

    for (i=0; i < input_count; ++i) {
        input_spks[i] = psbt_input_get_scriptpubkey(tx->psbt, i);
        input_spk_lens[i] = tal_bytelen(input_spks[i]); /* FIXME ??? tal_bytelen? */
        input_val_sats[i] = psbt_input_get_amount(tx->psbt, i).satoshis;
    }

	/* Wally can allocate here, iff tx doesn't fit on stack */
	tal_wally_start();
    ret = wally_tx_get_btc_taproot_signature_hash(
        tx->wtx, sighash_type, input_index, input_spks, input_spk_lens,
        input_val_sats, tapleaf_script, tal_bytelen(tapleaf_script), (sighash_type & SIGHASH_ANYPREVOUTANYSCRIPT) == SIGHASH_ANYPREVOUTANYSCRIPT ? 0x01 : 0x00 /* key_version */,
        0xFFFFFFFF /* codesep_position */, annex, tal_count(annex), 0 /* flags */, dest->sha.u.u8,
		    sizeof(*dest));

    assert(ret == WALLY_OK);
	tal_wally_end(tx->wtx);

}

void sign_tx_input(const struct bitcoin_tx *tx,
		   unsigned int in,
		   const u8 *subscript,
		   const u8 *witness_script,
		   const struct privkey *privkey, const struct pubkey *key,
		   enum sighash_type sighash_type,
		   struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool use_segwit = witness_script != NULL;
	const u8 *script = use_segwit ? witness_script : subscript;

	assert(sighash_type_valid(sighash_type));

	sig->sighash_type = sighash_type;
	bitcoin_tx_hash_for_sig(tx, in, script, sighash_type, &hash);

	dump_tx("Signing", tx, in, subscript, key, NULL /* x_key */, &hash);
	sign_hash(privkey, &hash, &sig->s);
}

void sign_tx_taproot_input(const struct bitcoin_tx *tx,
		   unsigned int input_index,
		   enum sighash_type sighash_type,
           const u8 *tapleaf_script,
		   const secp256k1_keypair *key_pair,
		   struct bip340sig *sig)
{
	struct sha256_double hash;
    int ret;
    secp256k1_xonly_pubkey pubkey;
    struct point32 x_key;
    struct privkey privkey;

	/* FIXME assert sighashes we actually support assert(sighash_type_valid(sighash_type)); */
	bitcoin_tx_taproot_hash_for_sig(tx, input_index, sighash_type, tapleaf_script, NULL /* annex */, &hash);

    /* TODO just have it take keypair? */
    ret = secp256k1_keypair_xonly_pub(secp256k1_ctx, &pubkey, NULL /* pk_parity */, key_pair);
    assert(ret);
    x_key.pubkey = pubkey;
	dump_tx("Signing taproot input:", tx, input_index, tapleaf_script, NULL /* key */, &x_key, &hash);
    ret = secp256k1_keypair_sec(secp256k1_ctx, privkey.secret.data, key_pair);
    assert(ret);
	bip340_sign_hash(&privkey, &hash, sig);
}

bool check_signed_hash(const struct sha256_double *hash,
		       const secp256k1_ecdsa_signature *signature,
		       const struct pubkey *key)
{
	int ret;

	/* BOLT #2:
	 *
	 * - if `signature` is incorrect OR non-compliant with
	 *   LOW-S-standard rule
	 */
	/* From the secp256k1_ecdsa_verify documentation: "To avoid
	 * accepting malleable signatures, only ECDSA signatures in
	 * lower-S form are accepted." */
	ret = secp256k1_ecdsa_verify(secp256k1_ctx,
				     signature,
				     hash->sha.u.u8, &key->pubkey);
	return ret == 1;
}

bool check_signed_bip340_hash(const struct sha256_double *hash,
		       const struct bip340sig *signature,
		       const struct point32 *key)
{
	int ret;
    ret = secp256k1_schnorrsig_verify(secp256k1_ctx, signature->u8, hash->sha.u.u8, sizeof(hash->sha.u.u8), &key->pubkey);
	return ret == 1;
}

bool check_tx_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *redeemscript,
		  const u8 *witness_script,
		  const struct pubkey *key,
		  const struct bitcoin_signature *sig)
{
	struct sha256_double hash;
	bool use_segwit = witness_script != NULL;
	const u8 *script = use_segwit ? witness_script : redeemscript;
	bool ret;

	/* We only support a limited subset of sighash types. */
	if (sig->sighash_type != SIGHASH_ALL) {
		if (!witness_script)
			return false;
		if (sig->sighash_type != (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
			return false;
	}
	assert(input_num < tx->wtx->num_inputs);

	bitcoin_tx_hash_for_sig(tx, input_num, script, sig->sighash_type, &hash);
	dump_tx("check_tx_sig", tx, input_num, script, key, NULL /* x_key */, &hash);

	ret = check_signed_hash(&hash, &sig->s, key);
	if (!ret)
		dump_tx("Sig failed", tx, input_num, redeemscript, key, NULL /* x_key */, &hash);
	return ret;
}

bool check_tx_taproot_sig(const struct bitcoin_tx *tx, size_t input_num,
		  const u8 *tapleaf_script,
		  const struct point32 *x_key,
          enum sighash_type sighash_type,
		  const struct bip340sig *sig)
{
	struct sha256_double hash;
	bool ret;

	/* FIXME We only support a limited subset of sighash types. */
	if (sighash_type != SIGHASH_ALL) {
		if (sighash_type != (SIGHASH_SINGLE|SIGHASH_ANYONECANPAY))
			return false;
	}
	assert(input_num < tx->wtx->num_inputs);

	bitcoin_tx_taproot_hash_for_sig(tx, input_num, sighash_type, tapleaf_script, /* annex */ NULL, &hash);

	dump_tx("check_tx_sig", tx, input_num, tapleaf_script, NULL /* key */, x_key, &hash);

	ret = check_signed_bip340_hash(&hash, sig, x_key);
	if (!ret)
		dump_tx("Sig failed", tx, input_num, tapleaf_script, NULL /* key */, x_key, &hash);
	return ret;
}

/* Stolen direct from bitcoin/src/script/sign.cpp:
// Copyright (c) 2009-2010 Satoshi Nakamoto
// Copyright (c) 2009-2014 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.
*/
static bool IsValidSignatureEncoding(const unsigned char sig[], size_t len)
{
    // Format: 0x30 [total-length] 0x02 [R-length] [R] 0x02 [S-length] [S] [sighash]
    // * total-length: 1-byte length descriptor of everything that follows,
    //   excluding the sighash byte.
    // * R-length: 1-byte length descriptor of the R value that follows.
    // * R: arbitrary-length big-endian encoded R value. It must use the shortest
    //   possible encoding for a positive integers (which means no null bytes at
    //   the start, except a single one when the next byte has its highest bit set).
    // * S-length: 1-byte length descriptor of the S value that follows.
    // * S: arbitrary-length big-endian encoded S value. The same rules apply.
    // * sighash: 1-byte value indicating what data is hashed (not part of the DER
    //   signature)

    // Minimum and maximum size constraints.
    if (len < 9) return false;
    if (len > 73) return false;

    // A signature is of type 0x30 (compound).
    if (sig[0] != 0x30) return false;

    // Make sure the length covers the entire signature.
    if (sig[1] != len - 3) return false;

    // Extract the length of the R element.
    unsigned int lenR = sig[3];

    // Make sure the length of the S element is still inside the signature.
    if (5 + lenR >= len) return false;

    // Extract the length of the S element.
    unsigned int lenS = sig[5 + lenR];

    // Verify that the length of the signature matches the sum of the length
    // of the elements.
    if ((size_t)lenR + (size_t)lenS + 7 != len) return false;

    // Check whether the R element is an integer.
    if (sig[2] != 0x02) return false;

    // Zero-length integers are not allowed for R.
    if (lenR == 0) return false;

    // Negative numbers are not allowed for R.
    if (sig[4] & 0x80) return false;

    // Null bytes at the start of R are not allowed, unless R would
    // otherwise be interpreted as a negative number.
    if (lenR > 1 && (sig[4] == 0x00) && !(sig[5] & 0x80)) return false;

    // Check whether the S element is an integer.
    if (sig[lenR + 4] != 0x02) return false;

    // Zero-length integers are not allowed for S.
    if (lenS == 0) return false;

    // Negative numbers are not allowed for S.
    if (sig[lenR + 6] & 0x80) return false;

    // Null bytes at the start of S are not allowed, unless S would otherwise be
    // interpreted as a negative number.
    if (lenS > 1 && (sig[lenR + 6] == 0x00) && !(sig[lenR + 7] & 0x80)) return false;

    return true;
}

size_t signature_to_der(u8 der[73], const struct bitcoin_signature *sig)
{
	size_t len = 72;

	secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx,
						der, &len, &sig->s);

	/* Append sighash type */
	der[len++] = sig->sighash_type;

	/* IsValidSignatureEncoding() expect extra byte for sighash */
	assert(IsValidSignatureEncoding(memcheck(der, len), len));
	return len;
}

bool signature_from_der(const u8 *der, size_t len, struct bitcoin_signature *sig)
{
	if (len < 1)
		return false;
	if (!secp256k1_ecdsa_signature_parse_der(secp256k1_ctx,
						 &sig->s, der, len-1))
		return false;
	sig->sighash_type = der[len-1];

	if (!sighash_type_valid(sig->sighash_type))
		return false;

	return true;
}

char *fmt_signature(const tal_t *ctx, const secp256k1_ecdsa_signature *sig)
{
	u8 der[72];
	size_t len = 72;

	secp256k1_ecdsa_signature_serialize_der(secp256k1_ctx,
						der, &len, sig);

	return tal_hexstr(ctx, der, len);
}
REGISTER_TYPE_TO_STRING(secp256k1_ecdsa_signature, fmt_signature);

static char *bitcoin_signature_to_hexstr(const tal_t *ctx,
					 const struct bitcoin_signature *sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, sig);

	return tal_hexstr(ctx, der, len);
}
REGISTER_TYPE_TO_STRING(bitcoin_signature, bitcoin_signature_to_hexstr);

void fromwire_bitcoin_signature(const u8 **cursor, size_t *max,
				struct bitcoin_signature *sig)
{
	fromwire_secp256k1_ecdsa_signature(cursor, max, &sig->s);
	sig->sighash_type = fromwire_u8(cursor, max);
	if (!sighash_type_valid(sig->sighash_type))
		fromwire_fail(cursor, max);
}

void towire_bitcoin_signature(u8 **pptr, const struct bitcoin_signature *sig)
{
	assert(sighash_type_valid(sig->sighash_type));
	towire_secp256k1_ecdsa_signature(pptr, &sig->s);
	towire_u8(pptr, sig->sighash_type);
}

void towire_bip340sig(u8 **pptr, const struct bip340sig *bip340sig)
{
	towire_u8_array(pptr, bip340sig->u8, sizeof(bip340sig->u8));
}

void fromwire_bip340sig(const u8 **cursor, size_t *max,
			struct bip340sig *bip340sig)
{
	fromwire_u8_array(cursor, max, bip340sig->u8, sizeof(bip340sig->u8));
}

void towire_partial_sig(u8 **pptr, const struct partial_sig *p_sig)
{
    u8 bip340sig_arr[32];
    secp256k1_musig_partial_sig_serialize(secp256k1_ctx, bip340sig_arr, &p_sig->p_sig);
	towire_u8_array(pptr, bip340sig_arr, sizeof(bip340sig_arr));
}

void fromwire_partial_sig(const u8 **cursor, size_t *max,
            struct partial_sig *p_sig)
{
    u8 raw[32];


    if (!fromwire(cursor, max, raw, sizeof(raw)))
        return;

    if (!secp256k1_musig_partial_sig_parse(secp256k1_ctx, &p_sig->p_sig, raw)) {
        SUPERVERBOSE("not a valid musig partial sig");
        fromwire_fail(cursor, max);
    }
}

char *fmt_partial_sig(const tal_t *ctx, const struct partial_sig *psig)
{
	return tal_hexstr(ctx, psig->p_sig.data, sizeof(psig->p_sig.data));
}

REGISTER_TYPE_TO_HEXSTR(partial_sig);

void towire_musig_session(u8 **pptr, const struct musig_session *session)
{
    /* No proper serialization/parsing supplied, we're just copying bytes */
    towire_u8_array(pptr, session->session.data, sizeof(session->session.data));
}

void fromwire_musig_session(const u8 **cursor, size_t *max,
            struct musig_session *session){
    /* No proper serialization/parsing supplied, we're just copying bytes */
    if (!fromwire(cursor, max, session->session.data, sizeof(session->session.data)))
        return;
}

char *fmt_bip340sig(const tal_t *ctx, const struct bip340sig *bip340sig)
{
	return tal_hexstr(ctx, bip340sig->u8, sizeof(bip340sig->u8));
}

REGISTER_TYPE_TO_HEXSTR(bip340sig);

char *fmt_musig_session(const tal_t *ctx, const struct musig_session *musig_session)
{
    return tal_hexstr(ctx, musig_session->session.data, sizeof(musig_session->session.data));
}

REGISTER_TYPE_TO_HEXSTR(musig_session);

void towire_musig_keyagg_cache(u8 **pptr, const struct musig_keyagg_cache *cache)
{
    /* No proper serialization/parsing supplied, we're just copying bytes */
    towire_u8_array(pptr, cache->cache.data, sizeof(cache->cache.data));
}

void fromwire_musig_keyagg_cache(const u8 **cursor, size_t *max,
            struct musig_keyagg_cache *cache){
    /* No proper serialization/parsing supplied, we're just copying bytes */
    if (!fromwire(cursor, max, cache->cache.data, sizeof(cache->cache.data)))
        return;
}

/* BIP-340:
 *
 * This proposal suggests to include the tag by prefixing the hashed
 * data with ''SHA256(tag) || SHA256(tag)''. Because this is a 64-byte
 * long context-specific constant and the ''SHA256'' block size is
 * also 64 bytes, optimized implementations are possible (identical to
 * SHA256 itself, but with a modified initial state). Using SHA256 of
 * the tag name itself is reasonably simple and efficient for
 * implementations that don't choose to use the optimization.
 */

/* For caller convenience, we hand in tag in parts (any can be "") */
void bip340_sighash_init(struct sha256_ctx *sctx,
			 const char *tag1,
			 const char *tag2,
			 const char *tag3)
{
	struct sha256 taghash;

	sha256_init(sctx);
	sha256_update(sctx, memcheck(tag1, strlen(tag1)), strlen(tag1));
	sha256_update(sctx, memcheck(tag2, strlen(tag2)), strlen(tag2));
	sha256_update(sctx, memcheck(tag3, strlen(tag3)), strlen(tag3));
	sha256_done(sctx, &taghash);

	sha256_init(sctx);
	sha256_update(sctx, &taghash, sizeof(taghash));
	sha256_update(sctx, &taghash, sizeof(taghash));
}

void create_keypair_of_one(secp256k1_keypair *G_pair)
{
    int ok;
    unsigned char g[32];

    /* Privkey of exactly 1, so the pubkey is the generator G */
    memset(g, 0x00, sizeof(g));
    g[sizeof(g)-1] = 0x01;

    ok = secp256k1_keypair_create(
        secp256k1_ctx,
        G_pair,
        g);
    assert(ok);
}

u8 *scriptpubkey_eltoo_funding(const tal_t *ctx, const struct pubkey *pubkey1, const struct pubkey *pubkey2)
{
    struct pubkey taproot_pubkey;
    secp256k1_musig_keyagg_cache keyagg_cache;
    const struct pubkey *pk_ptrs[2];
    struct sha256 tap_merkle_root;
    unsigned char tap_tweak_out[32];
    u8 *update_tapscript[1];

    pk_ptrs[0] = pubkey1;
    pk_ptrs[1] = pubkey2;

    update_tapscript[0] = make_eltoo_funding_update_script(tmpctx);

    compute_taptree_merkle_root(&tap_merkle_root, update_tapscript, /* num_scripts */ 1);

    bipmusig_finalize_keys(&taproot_pubkey,
           &keyagg_cache,
           pk_ptrs,
           /* n_pubkeys */ 2,
           &tap_merkle_root,
           tap_tweak_out,
		   NULL);

    return scriptpubkey_p2tr(ctx, &taproot_pubkey);
}
