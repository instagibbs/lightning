#include "config.h"
#include <assert.h>
#include <bitcoin/address.h>
#include <bitcoin/locktime.h>
#include <bitcoin/preimage.h>
#include <bitcoin/privkey.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <ccan/endian/endian.h>
#include <ccan/mem/mem.h>
#include <common/utils.h>
#include <sodium/randombytes.h>

#include <stdio.h>

/* To push 0-75 bytes onto stack. */
#define OP_PUSHBYTES(val) (val)

/* Bitcoin's OP_HASH160 is RIPEMD(SHA256()) */
static void hash160(struct ripemd160 *redeemhash, const void *mem, size_t len)
{
	struct sha256 h;

	sha256(&h, mem, len);
	ripemd160(redeemhash, h.u.u8, sizeof(h));
}

static void add(u8 **scriptp, const void *mem, size_t len)
{
	size_t oldlen = tal_count(*scriptp);
	tal_resize(scriptp, oldlen + len);
	memcpy(*scriptp + oldlen, mem, len);
}

static void add_op(u8 **scriptp, u8 op)
{
	add(scriptp, &op, 1);
}

void script_push_bytes(u8 **scriptp, const void *mem, size_t len)
{
	if (len < 76)
		add_op(scriptp, OP_PUSHBYTES(len));
	else if (len < 256) {
		char c = len;
		add_op(scriptp, OP_PUSHDATA1);
		add(scriptp, &c, 1);
	} else if (len < 65536) {
		le16 v = cpu_to_le16(len);
		add_op(scriptp, OP_PUSHDATA2);
		add(scriptp, &v, 2);
	} else {
		le32 v = cpu_to_le32(len);
		add_op(scriptp, OP_PUSHDATA4);
		add(scriptp, &v, 4);
	}

	add(scriptp, memcheck(mem, len), len);
}

static void add_number(u8 **script, u32 num)
{
	if (num == 0)
		add_op(script, 0);
	else if (num <= 16)
		add_op(script, 0x50 + num);
	else {
		le64 n = cpu_to_le64(num);

		/* Beware: encoding is signed! */
		if (num <= 0x0000007F)
			script_push_bytes(script, &n, 1);
		else if (num <= 0x00007FFF)
			script_push_bytes(script, &n, 2);
		else if (num <= 0x007FFFFF)
			script_push_bytes(script, &n, 3);
		else if (num <= 0x7FFFFFFF)
			script_push_bytes(script, &n, 4);
		else
			script_push_bytes(script, &n, 5);
	}
}

static void add_push_key(u8 **scriptp, const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];
	pubkey_to_der(der, key);

	script_push_bytes(scriptp, der, sizeof(der));
}

static void add_push_xonly_key(u8 **scriptp, const struct pubkey *key)
{
    int ok;
    unsigned char xonly_bytes[32];
    secp256k1_xonly_pubkey xonly;

    ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx, &xonly, /* parity_bit */ NULL, &(key->pubkey));
    assert(ok);
    ok = secp256k1_xonly_pubkey_serialize(secp256k1_ctx, xonly_bytes, &xonly);
    assert(ok);

    script_push_bytes(scriptp, xonly_bytes, sizeof(xonly_bytes));
}

static void add_push_sig(u8 **scriptp, const struct bitcoin_signature *sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, sig);

	script_push_bytes(scriptp, der, len);
}

static u8 *stack_key(const tal_t *ctx, const struct pubkey *key)
{
	u8 der[PUBKEY_CMPR_LEN];
	pubkey_to_der(der, key);

	return tal_dup_arr(ctx, u8, der, sizeof(der), 0);
}

/* Bitcoin wants DER encoding. */
static u8 *stack_sig(const tal_t *ctx, const struct bitcoin_signature *sig)
{
	u8 der[73];
	size_t len = signature_to_der(der, sig);

	return tal_dup_arr(ctx, u8, der, len, 0);
}

static u8 *stack_bip340sig(const tal_t *ctx, const struct bip340sig *sig, enum sighash_type sh_type)
{
    if (sh_type != SIGHASH_DEFAULT) {
        u8 sig_flag[65];
        memcpy(sig_flag, sig->u8, 64);
        sig_flag[sizeof(sig_flag)-1] = sh_type;
        return tal_dup_arr(ctx, u8, sig->u8, sizeof(sig_flag), 0);
    } else {
	    return tal_dup_arr(ctx, u8, sig->u8, 64, 0);
    }
}

static u8 *stack_preimage(const tal_t *ctx, const struct preimage *preimage)
{
	return tal_dup_arr(ctx, u8, preimage->r, sizeof(preimage->r), 0);
}

/* Bitcoin script stack values are a special, special snowflake.
 *
 * They're little endian values, but 0 is an empty value.  We only
 * handle single byte values here. */
static u8 *stack_number(const tal_t *ctx, unsigned int num)
{
	u8 val;

	if (num == 0)
		return tal_arr(ctx, u8, 0);

	val = num;
	assert(val == num);

	/* We use tal_dup_arr since we want tal_count() to work */
	return tal_dup_arr(ctx, u8, &val, 1, 0);
}

/* tal_count() gives the length of the script. */
u8 *bitcoin_redeem_2of2(const tal_t *ctx,
			const struct pubkey *key1,
			const struct pubkey *key2)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_number(&script, 2);
	if (pubkey_cmp(key1, key2) < 0) {
		add_push_key(&script, key1);
		add_push_key(&script, key2);
	} else {
		add_push_key(&script, key2);
		add_push_key(&script, key1);
	}
	add_number(&script, 2);
	add_op(&script, OP_CHECKMULTISIG);
	return script;
}

u8 *scriptpubkey_p2sh_hash(const tal_t *ctx, const struct ripemd160 *redeemhash)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_HASH160);
	script_push_bytes(&script, redeemhash->u.u8, sizeof(redeemhash->u.u8));
	add_op(&script, OP_EQUAL);
	assert(tal_count(script) == BITCOIN_SCRIPTPUBKEY_P2SH_LEN);
	return script;
}

/* Create p2sh for this redeem script. */
u8 *scriptpubkey_p2sh(const tal_t *ctx, const u8 *redeemscript)
{
	struct ripemd160 redeemhash;

	hash160(&redeemhash, redeemscript, tal_count(redeemscript));
	return scriptpubkey_p2sh_hash(ctx, &redeemhash);
}

/* Create an output script using p2pkh */
u8 *scriptpubkey_p2pkh(const tal_t *ctx, const struct bitcoin_address *addr)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	script_push_bytes(&script, &addr->addr, sizeof(addr->addr));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);
	assert(tal_count(script) == BITCOIN_SCRIPTPUBKEY_P2PKH_LEN);
	return script;
}

u8 *scriptpubkey_opreturn_padded(const tal_t *ctx)
{
	u8 *script = tal_arr(ctx, u8, 0);
	u8 random[20];
	randombytes_buf(random, sizeof(random));

	add_op(&script, OP_RETURN);
	script_push_bytes(&script, random, sizeof(random));
	return script;
}

/* Create an input script which spends p2pkh */
u8 *bitcoin_redeem_p2pkh(const tal_t *ctx, const struct pubkey *pubkey,
			 const struct bitcoin_signature *sig)
{
	u8 *script = tal_arr(ctx, u8, 0);

	add_push_sig(&script, sig);
	add_push_key(&script, pubkey);

	return script;
}

/* Create the redeemscript for a P2SH + P2WPKH (for signing tx) */
u8 *bitcoin_redeem_p2sh_p2wpkh(const tal_t *ctx, const struct pubkey *key)
{
	struct ripemd160 keyhash;
	u8 *script = tal_arr(ctx, u8, 0);

	/* BIP141: BIP16 redeemScript pushed in the scriptSig is exactly a
	 * push of a version byte plus a push of a witness program. */
	add_number(&script, 0);
	pubkey_to_hash160(key, &keyhash);
	script_push_bytes(&script, &keyhash, sizeof(keyhash));

	assert(tal_count(script) == BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN);
	return script;
}

u8 *bitcoin_scriptsig_redeem(const tal_t *ctx,
			     const u8 *redeemscript TAKES)
{
	u8 *script;

	/* BIP141: The scriptSig must be exactly a push of the BIP16
	 * redeemScript or validation fails. */
	script = tal_arr(ctx, u8, 0);
	script_push_bytes(&script, redeemscript,
			  tal_count(redeemscript));

	if (taken(redeemscript))
		tal_free(redeemscript);

	return script;
}

u8 *bitcoin_scriptsig_p2sh_p2wpkh(const tal_t *ctx, const struct pubkey *key)
{
	u8 *redeemscript =
		bitcoin_redeem_p2sh_p2wpkh(NULL, key);
	return bitcoin_scriptsig_redeem(ctx, take(redeemscript));
}

u8 **bitcoin_witness_p2wpkh(const tal_t *ctx,
			    const struct bitcoin_signature *sig,
			    const struct pubkey *key)
{
	u8 **witness;

	/* BIP141: The witness must consist of exactly 2 items (≤ 520
	 * bytes each). The first one a signature, and the second one
	 * a public key. */
	witness = tal_arr(ctx, u8 *, 2);
	witness[0] = stack_sig(witness, sig);
	witness[1] = stack_key(witness, key);
	return witness;
}

/* Create an output script for a 32-byte witness. */
u8 *scriptpubkey_p2wsh(const tal_t *ctx, const u8 *witnessscript)
{
	struct sha256 h;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_0);
	sha256(&h, witnessscript, tal_count(witnessscript));
	script_push_bytes(&script, h.u.u8, sizeof(h.u.u8));
	assert(tal_count(script) == BITCOIN_SCRIPTPUBKEY_P2WSH_LEN);
	return script;
}

/* Create an output script for a 20-byte witness. */
u8 *scriptpubkey_p2wpkh(const tal_t *ctx, const struct pubkey *key)
{
	struct ripemd160 h;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_0);
	pubkey_to_hash160(key, &h);
	script_push_bytes(&script, &h, sizeof(h));
	return script;
}

u8 *scriptpubkey_p2wpkh_derkey(const tal_t *ctx, const u8 der[33])
{
	u8 *script = tal_arr(ctx, u8, 0);
	struct ripemd160 h;

	add_op(&script, OP_0);
	hash160(&h, der, PUBKEY_CMPR_LEN);
	script_push_bytes(&script, &h, sizeof(h));
	return script;
}

u8 *scriptpubkey_witness_raw(const tal_t *ctx, u8 version,
			     const u8 *wprog, size_t wprog_size)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_number(&script, version);
	script_push_bytes(&script, wprog, wprog_size);
	return script;
}

int pubkey_parity(const struct pubkey *pubkey)
{
    int ok, pk_parity;
    secp256k1_xonly_pubkey x_key;

    ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
        &x_key,
        &pk_parity,
        &(pubkey->pubkey));
    assert(ok);

    return pk_parity;
}

/* Create an output script for a taproot output */
u8 *scriptpubkey_p2tr(const tal_t *ctx, const struct pubkey *pubkey)
{
    int ok;
    secp256k1_xonly_pubkey x_key;
    unsigned char x_key_bytes[32];
	//struct sha256 h;
	u8 *script = tal_arr(ctx, u8, 0);

	add_op(&script, OP_1);


    ok = secp256k1_xonly_pubkey_from_pubkey(secp256k1_ctx,
        &x_key,
        /* pk_parity */ NULL,
        &(pubkey->pubkey));
    assert(ok);

    ok = secp256k1_xonly_pubkey_serialize(secp256k1_ctx,
        x_key_bytes,
        &x_key);
    assert(ok);

	script_push_bytes(&script, x_key_bytes, sizeof(x_key_bytes));
	assert(tal_count(script) == BITCOIN_SCRIPTPUBKEY_P2TR_LEN);
	return script;
}

/* BOLT #3:
 *
 * #### `to_remote` Output
 *
 * If `option_anchor_outputs` applies to the commitment
 * transaction, the `to_remote` output is encumbered by a one
 * block csv lock.
 *    <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
 */
/* BOLT- #3
 * ##### Leased channel (`option_will_fund`)
 *
 * If a `lease` applies to the channel, the `to_remote` output
 * of the `initiator` ensures the `leasor` funds are not
 * spendable until the lease expires.
 *
 * <remote_pubkey> OP_CHECKSIGVERIFY MAX(1, lease_end - blockheight) OP_CHECKSEQUENCEVERIFY
 */

u8 *anchor_to_remote_redeem(const tal_t *ctx,
			    const struct pubkey *remote_key,
			    u32 csv_lock)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_key(&script, remote_key);
	add_op(&script, OP_CHECKSIGVERIFY);
	add_number(&script, csv_lock);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);

	assert(is_anchor_witness_script(script, tal_bytelen(script)));
	return script;
}

bool is_anchor_witness_script(const u8 *script, size_t script_len)
{
	size_t len = 34 + 1 + 1 + 1;
	/* With option_will_fund, the pushbytes can be up to 2 bytes more
	 *
	 * <remote_pubkey> OP_CHECKSIGVERIFY
	 * 		MAX(1, lease_end - blockheight)
	 * 		OP_CHECKSEQUENCEVERIFY
	 */
	if (script_len < len || script_len > len + 2)
		return false;
	if (script[0] != OP_PUSHBYTES(33))
		return false;
	if (script[34] != OP_CHECKSIGVERIFY)
		return false;
	/* FIXME: check for push value */
	if (script[script_len - 1] != OP_CHECKSEQUENCEVERIFY)
		return false;
	return true;
}

/* Create a witness which spends the 2of2. */
u8 **bitcoin_witness_2of2(const tal_t *ctx,
			  const struct bitcoin_signature *sig1,
			  const struct bitcoin_signature *sig2,
			  const struct pubkey *key1,
			  const struct pubkey *key2)
{
	u8 **witness = tal_arr(ctx, u8 *, 4);

	/* OP_CHECKMULTISIG has an out-by-one bug, which MBZ */
	witness[0] = stack_number(witness, 0);

	/* sig order should match key order. */
	if (pubkey_cmp(key1, key2) < 0) {
		witness[1] = stack_sig(witness, sig1);
		witness[2] = stack_sig(witness, sig2);
	} else {
		witness[1] = stack_sig(witness, sig2);
		witness[2] = stack_sig(witness, sig1);
	}

	witness[3] = bitcoin_redeem_2of2(witness, key1, key2);
	return witness;
}

/* Create scriptcode (fake witness, basically) for P2WPKH */
u8 *p2wpkh_scriptcode(const tal_t *ctx, const struct pubkey *key)
{
	struct ripemd160 pkhash;
	u8 *script = tal_arr(ctx, u8, 0);
	pubkey_to_hash160(key, &pkhash);

	/* BIP143:
	 *
	 * For P2WPKH witness program, the scriptCode is
	 * 0x1976a914{20-byte-pubkey-hash}88ac.
	 */

	/* PUSH(25): OP_DUP OP_HASH160 PUSH(20) 20-byte-pubkey-hash
	 * OP_EQUALVERIFY OP_CHECKSIG */
	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	script_push_bytes(&script, &pkhash, sizeof(pkhash));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);

	return script;
}

bool is_p2pkh(const u8 *script, struct bitcoin_address *addr)
{
	size_t script_len = tal_count(script);

	if (script_len != BITCOIN_SCRIPTPUBKEY_P2PKH_LEN)
		return false;
	if (script[0] != OP_DUP)
		return false;
	if (script[1] != OP_HASH160)
		return false;
	if (script[2] != OP_PUSHBYTES(20))
		return false;
	if (script[23] != OP_EQUALVERIFY)
		return false;
	if (script[24] != OP_CHECKSIG)
		return false;
	if (addr)
		memcpy(addr, script+3, 20);
	return true;
}

bool is_p2sh(const u8 *script, struct ripemd160 *addr)
{
	size_t script_len = tal_count(script);

	if (script_len != BITCOIN_SCRIPTPUBKEY_P2SH_LEN)
		return false;
	if (script[0] != OP_HASH160)
		return false;
	if (script[1] != OP_PUSHBYTES(20))
		return false;
	if (script[22] != OP_EQUAL)
		return false;
	if (addr)
		memcpy(addr, script+2, 20);
	return true;
}

bool is_p2wsh(const u8 *script, struct sha256 *addr)
{
	size_t script_len = tal_count(script);

	if (script_len != BITCOIN_SCRIPTPUBKEY_P2WSH_LEN)
		return false;
	if (script[0] != OP_0)
		return false;
	if (script[1] != OP_PUSHBYTES(sizeof(struct sha256)))
		return false;
	if (addr)
		memcpy(addr, script+2, sizeof(struct sha256));
	return true;
}

bool is_p2wpkh(const u8 *script, struct bitcoin_address *addr)
{
	size_t script_len = tal_count(script);

	if (script_len != BITCOIN_SCRIPTPUBKEY_P2WPKH_LEN)
		return false;
	if (script[0] != OP_0)
		return false;
	if (script[1] != OP_PUSHBYTES(sizeof(struct ripemd160)))
		return false;
	if (addr)
		memcpy(addr, script+2, sizeof(*addr));
	return true;
}

bool is_p2tr(const u8 *script, u8 *xonly_pubkey)
{
	size_t script_len = tal_count(script);

	if (script_len != BITCOIN_SCRIPTPUBKEY_P2TR_LEN)
		return false;
	if (script[0] != OP_1)
		return false;
    /* x-only pubkey */
	if (script[1] != OP_PUSHBYTES(32))
		return false;
	if (xonly_pubkey)
		memcpy(xonly_pubkey, script+2, 32);
	return true;
}

bool is_ephemeral_anchor(const u8 *script)
{
	size_t script_len = tal_count(script);

	if (script_len != 1)
		return false;
	if (script[0] != OP_1)
		return false;
    return true;
}

bool is_known_scripttype(const u8 *script)
{
	return is_p2wpkh(script, NULL) || is_p2wsh(script, NULL)
		|| is_p2sh(script, NULL) || is_p2pkh(script, NULL);
}

u8 **bitcoin_witness_sig_and_element(const tal_t *ctx,
				     const struct bitcoin_signature *sig,
				     const void *elem, size_t elemsize,
				     const u8 *witnessscript)
{
	u8 **witness = tal_arr(ctx, u8 *, 3);

	witness[0] = stack_sig(witness, sig);
	witness[1] = tal_dup_arr(witness, u8, elem, elemsize, 0);
	witness[2] = tal_dup_talarr(witness, u8, witnessscript);

	return witness;
}

u8 **bitcoin_witness_bip340sig_and_element(const tal_t *ctx,
				     const struct bip340sig *sig,
				     const void *elem, size_t elemsize,
				     const u8 *tapscript,
                     const u8 *control_block)
{
    /* Itms ordered as a stack for readability */
    if (elem) {
        /*
        *
        *    The recipient node can redeem the HTLC with the witness:
        *
        *        <payment_preimage> <recipient_settlement_pubkey_signature>
        *
        */
        u8 **witness = tal_arr(ctx, u8 *, 4);

        witness[3] = tal_dup_talarr(witness, u8, control_block);
        witness[2] = tal_dup_talarr(witness, u8, tapscript);
        witness[1] = stack_bip340sig(witness, sig, SIGHASH_DEFAULT);
	    witness[0] = tal_dup_arr(witness, u8, elem, elemsize, 0);

        return witness;
    } else {
        /*
        *    And the offerer via:
        *
        *        <offerer_settlement_pubkey_signature>
        */
        u8 **witness = tal_arr(ctx, u8 *, 3);

        witness[2] = tal_dup_talarr(witness, u8, control_block);
        witness[1] = tal_dup_talarr(witness, u8, tapscript);
        witness[0] = stack_bip340sig(witness, sig, SIGHASH_DEFAULT);

        return witness;
    }
}

/* BOLT #3:
 *
 * This output sends funds back to the owner of this commitment transaction and
 * thus must be timelocked using `OP_CHECKSEQUENCEVERIFY`. It can be claimed, without delay,
 * by the other party if they know the revocation private key. The output is a
 * version-0 P2WSH, with a witness script:
 *
 *     OP_IF
 *         # Penalty transaction
 *         <revocationpubkey>
 *     OP_ELSE
 *         `to_self_delay`
 *         OP_CHECKSEQUENCEVERIFY
 *         OP_DROP
 *         <local_delayedpubkey>
 *     OP_ENDIF
 *     OP_CHECKSIG
 */
/* BOLT- #3
 * ##### Leased channel (`option_will_fund`)
 * If a `lease` applies to the channel, the `to_local` output of the `accepter`
 * ensures the `leasor` funds are not spendable until the lease expires.
 *
 * In a leased channel, the `to_local` output that pays the `accepter` node
 * is modified so that its CSV is equal to the greater of the
 * `to_self_delay` or the `lease_end` - `blockheight`.
 *
 *  OP_IF
 *      # Penalty transaction
 *      <revocationpubkey>
 *  OP_ELSE
 *      MAX(`to_self_delay`, `lease_end` - `blockheight`)
 *      OP_CHECKSEQUENCEVERIFY
 *      OP_DROP
 *      <local_delayedpubkey>
 *  OP_ENDIF
 *  OP_CHECKSIG
 */
u8 *bitcoin_wscript_to_local(const tal_t *ctx, u16 to_self_delay,
			     u32 lease_remaining,
			     const struct pubkey *revocation_pubkey,
			     const struct pubkey *local_delayedkey)
{
	u8 *script = tal_arr(ctx, u8, 0);
	add_op(&script, OP_IF);
	add_push_key(&script, revocation_pubkey);
	add_op(&script, OP_ELSE);
	add_number(&script, max_unsigned(lease_remaining, to_self_delay));
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_DROP);
	add_push_key(&script, local_delayedkey);
	add_op(&script, OP_ENDIF);
	add_op(&script, OP_CHECKSIG);
	return script;
}

/* BOLT #3:
 *
 * #### Offered HTLC Outputs
 *
 * This output sends funds to either an HTLC-timeout transaction after the
 * HTLC-timeout or to the remote node using the payment preimage or the
 * revocation key. The output is a P2WSH, with a witness script (no
 * option_anchor_outputs):
 *
 *     # To remote node with revocation key
 *     OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 *     OP_IF
 *         OP_CHECKSIG
 *     OP_ELSE
 *         <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *         OP_NOTIF
 *             # To local node via HTLC-timeout transaction (timelocked).
 *             OP_DROP 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *         OP_ELSE
 *             # To remote node with preimage.
 *             OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *             OP_CHECKSIG
 *         OP_ENDIF
 *     OP_ENDIF
 *
 * Or, with `option_anchor_outputs`:
 *
 *  # To remote node with revocation key
 *  OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 *  OP_IF
 *      OP_CHECKSIG
 *  OP_ELSE
 *      <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *      OP_NOTIF
 *          # To local node via HTLC-timeout transaction (timelocked).
 *          OP_DROP 2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *      OP_ELSE
 *          # To remote node with preimage.
 *          OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *          OP_CHECKSIG
 *      OP_ENDIF
 *      1 OP_CHECKSEQUENCEVERIFY OP_DROP
 *  OP_ENDIF
 */
u8 *bitcoin_wscript_htlc_offer_ripemd160(const tal_t *ctx,
					 const struct pubkey *localhtlckey,
					 const struct pubkey *remotehtlckey,
					 const struct ripemd160 *payment_ripemd,
					 const struct pubkey *revocationkey,
					 bool option_anchor_outputs)
{
	u8 *script = tal_arr(ctx, u8, 0);
	struct ripemd160 ripemd;

	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	pubkey_to_hash160(revocationkey, &ripemd);
	script_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ELSE);
	add_push_key(&script, remotehtlckey);
	add_op(&script, OP_SWAP);
	add_op(&script, OP_SIZE);
	add_number(&script, 32);
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_NOTIF);
	add_op(&script, OP_DROP);
	add_number(&script, 2);
	add_op(&script, OP_SWAP);
	add_push_key(&script, localhtlckey);
	add_number(&script, 2);
	add_op(&script, OP_CHECKMULTISIG);
	add_op(&script, OP_ELSE);
	add_op(&script, OP_HASH160);
	script_push_bytes(&script,
			  payment_ripemd->u.u8, sizeof(payment_ripemd->u.u8));
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ENDIF);
	if (option_anchor_outputs) {
		add_number(&script, 1);
		add_op(&script, OP_CHECKSEQUENCEVERIFY);
		add_op(&script, OP_DROP);
	}
	add_op(&script, OP_ENDIF);

	return script;
}

u8 *bitcoin_wscript_htlc_offer(const tal_t *ctx,
			       const struct pubkey *localhtlckey,
			       const struct pubkey *remotehtlckey,
			       const struct sha256 *payment_hash,
			       const struct pubkey *revocationkey,
			       bool option_anchor_outputs)
{
	struct ripemd160 ripemd;

	ripemd160(&ripemd, payment_hash->u.u8, sizeof(payment_hash->u));
	return bitcoin_wscript_htlc_offer_ripemd160(ctx, localhtlckey,
						    remotehtlckey,
						    &ripemd, revocationkey,
						    option_anchor_outputs);
}

/* BOLT #3:
 *
 * #### Received HTLC Outputs
 *
 * This output sends funds to either the remote node after the HTLC-timeout or
 * using the revocation key, or to an HTLC-success transaction with a
 * successful payment preimage. The output is a P2WSH, with a witness script
 * (no `option_anchor_outputs`):
 *
 *     # To remote node with revocation key
 *     OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 *     OP_IF
 *         OP_CHECKSIG
 *     OP_ELSE
 *         <remote_htlcpubkey> OP_SWAP
 *             OP_SIZE 32 OP_EQUAL
 *         OP_IF
 *             # To local node via HTLC-success transaction.
 *             OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *             2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *         OP_ELSE
 *             # To remote node after timeout.
 *             OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *             OP_CHECKSIG
 *         OP_ENDIF
 *     OP_ENDIF
 *
 * Or, with `option_anchor_outputs`:
 *
 *  # To remote node with revocation key
 *  OP_DUP OP_HASH160 <RIPEMD160(SHA256(revocationpubkey))> OP_EQUAL
 *  OP_IF
 *      OP_CHECKSIG
 *  OP_ELSE
 *      <remote_htlcpubkey> OP_SWAP OP_SIZE 32 OP_EQUAL
 *      OP_IF
 *          # To local node via HTLC-success transaction.
 *          OP_HASH160 <RIPEMD160(payment_hash)> OP_EQUALVERIFY
 *          2 OP_SWAP <local_htlcpubkey> 2 OP_CHECKMULTISIG
 *      OP_ELSE
 *          # To remote node after timeout.
 *          OP_DROP <cltv_expiry> OP_CHECKLOCKTIMEVERIFY OP_DROP
 *          OP_CHECKSIG
 *      OP_ENDIF
 *      1 OP_CHECKSEQUENCEVERIFY OP_DROP
 *  OP_ENDIF
 */
u8 *bitcoin_wscript_htlc_receive_ripemd(const tal_t *ctx,
					const struct abs_locktime *htlc_abstimeout,
					const struct pubkey *localhtlckey,
					const struct pubkey *remotehtlckey,
					const struct ripemd160 *payment_ripemd,
					const struct pubkey *revocationkey,
					bool option_anchor_outputs)
{
	u8 *script = tal_arr(ctx, u8, 0);
	struct ripemd160 ripemd;

	add_op(&script, OP_DUP);
	add_op(&script, OP_HASH160);
	pubkey_to_hash160(revocationkey, &ripemd);
	script_push_bytes(&script, &ripemd, sizeof(ripemd));
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ELSE);
	add_push_key(&script, remotehtlckey);
	add_op(&script, OP_SWAP);
	add_op(&script, OP_SIZE);
	add_number(&script, 32);
	add_op(&script, OP_EQUAL);
	add_op(&script, OP_IF);
	add_op(&script, OP_HASH160);
	script_push_bytes(&script,
			  payment_ripemd->u.u8, sizeof(payment_ripemd->u.u8));
	add_op(&script, OP_EQUALVERIFY);
	add_number(&script, 2);
	add_op(&script, OP_SWAP);
	add_push_key(&script, localhtlckey);
	add_number(&script, 2);
	add_op(&script, OP_CHECKMULTISIG);
	add_op(&script, OP_ELSE);
	add_op(&script, OP_DROP);
	add_number(&script, htlc_abstimeout->locktime);
	add_op(&script, OP_CHECKLOCKTIMEVERIFY);
	add_op(&script, OP_DROP);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_ENDIF);
	if (option_anchor_outputs) {
		add_number(&script, 1);
		add_op(&script, OP_CHECKSEQUENCEVERIFY);
		add_op(&script, OP_DROP);
	}
	add_op(&script, OP_ENDIF);

	return script;
}

u8 *bitcoin_wscript_htlc_receive(const tal_t *ctx,
				 const struct abs_locktime *htlc_abstimeout,
				 const struct pubkey *localhtlckey,
				 const struct pubkey *remotehtlckey,
				 const struct sha256 *payment_hash,
				 const struct pubkey *revocationkey,
				 bool option_anchor_outputs)
{
	struct ripemd160 ripemd;

	ripemd160(&ripemd, payment_hash->u.u8, sizeof(payment_hash->u));
	return bitcoin_wscript_htlc_receive_ripemd(ctx, htlc_abstimeout,
						   localhtlckey, remotehtlckey,
						   &ripemd, revocationkey,
						   option_anchor_outputs);
}

/* BOLT #3:
 *
 * ## HTLC-Timeout and HTLC-Success Transactions
 *
 *...
 *   * `txin[0]` witness stack: `0 <remotehtlcsig> <localhtlcsig>  <payment_preimage>` for HTLC-success, `0 <remotehtlcsig> <localhtlcsig> <>` for HTLC-timeout
 */
u8 **bitcoin_witness_htlc_timeout_tx(const tal_t *ctx,
				     const struct bitcoin_signature *localhtlcsig,
				     const struct bitcoin_signature *remotehtlcsig,
				     const u8 *wscript)
{
	u8 **witness = tal_arr(ctx, u8 *, 5);

	witness[0] = stack_number(witness, 0);
	witness[1] = stack_sig(witness, remotehtlcsig);
	witness[2] = stack_sig(witness, localhtlcsig);
	witness[3] = stack_number(witness, 0);
	witness[4] = tal_dup_talarr(witness, u8, wscript);

	return witness;
}

u8 **bitcoin_witness_htlc_success_tx(const tal_t *ctx,
				     const struct bitcoin_signature *localhtlcsig,
				     const struct bitcoin_signature *remotesig,
				     const struct preimage *preimage,
				     const u8 *wscript)
{
	u8 **witness = tal_arr(ctx, u8 *, 5);

	witness[0] = stack_number(witness, 0);
	witness[1] = stack_sig(witness, remotesig);
	witness[2] = stack_sig(witness, localhtlcsig);
	witness[3] = stack_preimage(witness, preimage);
	witness[4] = tal_dup_talarr(witness, u8, wscript);

	return witness;
}
u8 *bitcoin_wscript_htlc_tx(const tal_t *ctx,
			    u16 to_self_delay,
			    const struct pubkey *revocation_pubkey,
			    const struct pubkey *local_delayedkey)
{
	u8 *script = tal_arr(ctx, u8, 0);

	/* BOLT #3:
	 *
	 * The witness script for the output is:
	 *
	 *     OP_IF
	 *         # Penalty transaction
	 *         <revocationpubkey>
	 *     OP_ELSE
	 *         `to_self_delay`
	 *         OP_CHECKSEQUENCEVERIFY
	 *         OP_DROP
	 *         <local_delayedpubkey>
	 *     OP_ENDIF
	 *     OP_CHECKSIG
	 */
	add_op(&script, OP_IF);
	add_push_key(&script, revocation_pubkey);
	add_op(&script, OP_ELSE);
	add_number(&script, to_self_delay);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_DROP);
	add_push_key(&script, local_delayedkey);
	add_op(&script, OP_ENDIF);
	add_op(&script, OP_CHECKSIG);

	return script;
}

u8 *bitcoin_wscript_anchor(const tal_t *ctx,
			   const struct pubkey *funding_pubkey)
{
	u8 *script = tal_arr(ctx, u8, 0);

	/* BOLT #3:
	 * #### `to_local_anchor` and `to_remote_anchor` Output (option_anchor_outputs)
	 *...
	 *  <local_funding_pubkey/remote_funding_pubkey> OP_CHECKSIG OP_IFDUP
	 *  OP_NOTIF
	 *      OP_16 OP_CHECKSEQUENCEVERIFY
	 *  OP_ENDIF
	 */
	add_push_key(&script, funding_pubkey);
	add_op(&script, OP_CHECKSIG);
	add_op(&script, OP_IFDUP);
	add_op(&script, OP_NOTIF);
	add_number(&script, 16);
	add_op(&script, OP_CHECKSEQUENCEVERIFY);
	add_op(&script, OP_ENDIF);

	return script;
}

bool scripteq(const u8 *s1, const u8 *s2)
{
	memcheck(s1, tal_count(s1));
	memcheck(s2, tal_count(s2));

	if (tal_count(s1) != tal_count(s2))
		return false;
	return memcmp(s1, s2, tal_count(s1)) == 0;
}

u8 *bitcoin_spk_ephemeral_anchor(const tal_t *ctx)
{
	u8 *script = tal_arr(ctx, u8, 0);

	/* BOLT #3:
     * FIXME cite the extension bolts
	 */
	add_op(&script, OP_TRUE);
	return script;
}

void compute_taptree_merkle_root(struct sha256 *hash_out, u8 **scripts, size_t num_scripts)
{
    int ok;
    unsigned char leaf_version = is_elements(chainparams) ? 0xc4 : 0xc0;
    unsigned char tag_hash_buf[1000]; /* Needs to be large enough for HTLC scripts */
    unsigned char tap_hashes[64]; /* To store the leaves for comparison */

    /* Only what's required for eltoo et al for now, sue me */
    assert(num_scripts == 1 || num_scripts == 2);
    if (num_scripts == 1) {
        size_t script_len = tal_count(scripts[0]);
        unsigned char *p = tag_hash_buf;
        /* Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash. */
        p[0] = leaf_version;
        p++;
        p += varint_put(p, script_len);
        memcpy(p, scripts[0], script_len);
        p += script_len;

        /* k0 == km, this is the merkle root so we directly write it out */
        ok = wally_tagged_hash(tag_hash_buf, p - tag_hash_buf, is_elements(chainparams) ? "TapLeaf/elements" : "TapLeaf", hash_out->u.u8);
        assert(ok == WALLY_OK);
    } else if (num_scripts == 2) {
		/* First script */
		size_t script_len = tal_count(scripts[0]);
		unsigned char *p = tag_hash_buf;
		/* Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash. */
		p[0] = leaf_version;
		p++;
		p += varint_put(p, script_len);
		memcpy(p, scripts[0], script_len);
		p += script_len;

		ok = wally_tagged_hash(tag_hash_buf, p - tag_hash_buf, is_elements(chainparams) ? "TapLeaf/elements" : "TapLeaf", tap_hashes);
		assert(ok == WALLY_OK);

		/* Second script */
		script_len = tal_count(scripts[1]);
		p = tag_hash_buf;
		/* Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash. */
		p[0] = leaf_version;
		p++;
		p += varint_put(p, script_len);
		memcpy(p, scripts[1], script_len);
		p += script_len;

		ok = wally_tagged_hash(tag_hash_buf, p - tag_hash_buf, is_elements(chainparams) ? "TapLeaf/elements" : "TapLeaf", tap_hashes + 32);
		assert(ok == WALLY_OK);

        /* If kj ≥ ej: kj+1 = hashTapBranch(ej || kj), swap them*/
        if (memcmp(tap_hashes, tap_hashes + 32, 32) >= 0) {
            memcpy(tag_hash_buf, tap_hashes, 32);
            memcpy(tap_hashes, tap_hashes + 32, 32);
            memcpy(tap_hashes + 32, tag_hash_buf, 32);
        }
        ok = wally_tagged_hash(tap_hashes, sizeof(tap_hashes), is_elements(chainparams) ? "TapBranch/elements" : "TapBranch", hash_out->u.u8);
        assert(ok == WALLY_OK);
    }
}

void compute_taptree_merkle_root_with_hint(struct sha256 *update_merkle_root, const u8 *update_tapscript, const u8 *invalidated_annex_hint)
{
    int ok;
    unsigned char leaf_version = is_elements(chainparams) ? 0xc4 : 0xc0;
    unsigned char tag_hash_buf[1000]; /* Needs to be large enough for HTLC scripts */
    unsigned char tap_hashes[64]; /* To store the leaves for comparison */

    size_t script_len = tal_count(update_tapscript);
    unsigned char *p = tag_hash_buf;

    assert(tal_count(invalidated_annex_hint) == 34 && invalidated_annex_hint[0] == 0x50);

    /* Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash. */
    p[0] = leaf_version;
    p++;
    p += varint_put(p, script_len);
    memcpy(p, update_tapscript, script_len);
    p += script_len;

    ok = wally_tagged_hash(tag_hash_buf, p - tag_hash_buf, is_elements(chainparams) ? "TapLeaf/elements" : "TapLeaf", tap_hashes);
    assert(ok == WALLY_OK);

    /* Put invalidated hint in place as a tapleaf hash directly */
    memcpy(tap_hashes + 32, invalidated_annex_hint + 2, 32);

    /* If kj ≥ ej: kj+1 = hashTapBranch(ej || kj), swap them*/
    if (memcmp(tap_hashes, tap_hashes + 32, 32) >= 0) {
        memcpy(tag_hash_buf, tap_hashes, 32);
        memcpy(tap_hashes, tap_hashes + 32, 32);
        memcpy(tap_hashes + 32, tag_hash_buf, 32);
    }
    ok = wally_tagged_hash(tap_hashes, sizeof(tap_hashes), is_elements(chainparams) ? "TapBranch/elements" : "TapBranch", update_merkle_root->u.u8);
    assert(ok == WALLY_OK);
}

u8 *compute_control_block(const tal_t *ctx, const u8 *other_script, const u8 *annex_hint, const struct pubkey *inner_pubkey, int parity_bit)
{
    int ok;
    u8 *control_block_cursor;
    u8 *control_block = tal_arr(ctx, u8, (other_script || annex_hint) ? 33 + 32 : 33);
    secp256k1_xonly_pubkey xonly_inner_pubkey;

    ok = secp256k1_xonly_pubkey_from_pubkey(
        secp256k1_ctx,
        &xonly_inner_pubkey,
        NULL /* pk_parity (this is parity bit from inner key, do not want */,
        &inner_pubkey->pubkey);

    assert(ok);

    /* other_script and annex_hint are mutually exclusive args */
    assert(!(other_script && annex_hint));

    control_block_cursor = control_block;

    unsigned char leaf_version = is_elements(chainparams) ? 0xc4 : 0xc0;
    unsigned char tag_hash_buf[1000]; /* Needs to be large enough for HTLC scripts */

    /* Only what's required for eltoo et al for now, 2 leaves max, sue me */

    assert(parity_bit == 0 || parity_bit == 1);
    control_block_cursor[0] = leaf_version | parity_bit;
    control_block_cursor++;

    ok = secp256k1_xonly_pubkey_serialize(
        secp256k1_ctx,
        control_block_cursor,
        &xonly_inner_pubkey);
    assert(ok);
    control_block_cursor += 32;

    /* Need tapleaf hash of the other script of the 2 */
    if (other_script) {
        size_t script_len = tal_count(other_script);
        unsigned char *p = tag_hash_buf;
        /* Let k0 = hashTapLeaf(v || compact_size(size of s) || s); also call it the tapleaf hash. */
        p[0] = leaf_version;
        p++;
        p += varint_put(p, script_len);
        memcpy(p, other_script, script_len);
        p += script_len;

        ok = wally_tagged_hash(tag_hash_buf, p - tag_hash_buf, is_elements(chainparams) ? "TapLeaf/elements" : "TapLeaf", control_block_cursor);
        assert(ok == WALLY_OK);
        control_block_cursor += 32;
    } else if (annex_hint) {
        assert(tal_count(annex_hint) == 34);
        assert(annex_hint[0] == 0x50);
        assert(annex_hint[1] == 32);
        memcpy(control_block_cursor, annex_hint + 2, 32);
        control_block_cursor += 32;
    }
    return control_block;
}

u8 *make_eltoo_settle_script(const tal_t *ctx, const struct bitcoin_tx *settle_tx, size_t input_index)
{
    int ok;
    enum sighash_type sh_type = SIGHASH_ANYPREVOUTANYSCRIPT|SIGHASH_ALL;
	u8 *script = tal_arr(ctx, u8, 0);
    struct sha256_double sighash;
    struct bip340sig sig;
    unsigned char sig_with_flag[65];
    secp256k1_keypair G_pair;
    secp256k1_xonly_pubkey G;
    struct privkey g;
    unsigned char one_G_bytes[33];

    /* We use tapleaf_script as a switch for doing BIP342 hash
     * We really shouldn't, but for now we pass in dummy
     * since APOAS sighash doesn't cover it anyways.
     */
    bitcoin_tx_taproot_hash_for_sig(settle_tx,
                 input_index,
                 sh_type,
                 script,
                 /* annex */ NULL,
                 &sighash);


    /* Should directly take keypair instead of extracting but... */
    create_keypair_of_one(&G_pair);
    ok = secp256k1_keypair_sec(
        secp256k1_ctx,
        g.secret.data,
        &G_pair);
    assert(ok);

    bip340_sign_hash(&g,
           &sighash,
           &sig);

    /* 0x01-prefixed G for APOAS pubkey */
    ok = secp256k1_keypair_xonly_pub(
        secp256k1_ctx,
        &G,
        /* pk_parity */ NULL,
        &G_pair);
    assert(ok);
    one_G_bytes[0] = 0x01;
    ok = secp256k1_xonly_pubkey_serialize(
        secp256k1_ctx,
        one_G_bytes+1,
        &G);

    memcpy(sig_with_flag, sig.u8, sizeof(sig.u8));
    sig_with_flag[64] = sh_type;

    /* Build the script */
    script_push_bytes(&script, sig_with_flag, sizeof(sig_with_flag));
    script_push_bytes(&script, one_G_bytes, sizeof(one_G_bytes));
	add_op(&script, OP_CHECKSIG);
    return script;
}

u8 *make_eltoo_update_script(const tal_t *ctx, u32 update_num)
{
    /* TL(n) = `500000000+o+n`
     * where EXPR_UPDATE(n) =
     *
     *`<1> OP_CHECKSIGVERIFY <TL(n)> OP_CHECKLOCKTIMEVERIFY` if `n > 0`
     */
	u8 *script = tal_arr(ctx, u8, 0);
	add_op(&script, OP_1);
	add_op(&script, OP_CHECKSIGVERIFY);
    add_number(&script, 500000000 + update_num);
    add_op(&script, OP_CHECKLOCKTIMEVERIFY);
    return script;
}

u8 *make_eltoo_funding_update_script(const tal_t *ctx)
{
    /* where EXPR_UPDATE(n) =
     *
     *`<1> OP_CHECKSIG`, in the case of `n == 0`
     */
	u8 *script = tal_arr(ctx, u8, 0);
	add_op(&script, OP_1);
	add_op(&script, OP_CHECKSIG);
    return script;
}

u8 *make_eltoo_htlc_success_script(const tal_t *ctx, const struct pubkey *settlement_pubkey, const struct ripemd160 *invoice_hash)
{
    /* where EXPR_SUCCESS =
     *
     * `<settlement_pubkey> OP_CHECKSIGVERIFY OP_SIZE <20> OP_EQUALVERIFY OP_HASH160 <H>
OP_EQUAL`
     */
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_xonly_key(&script, settlement_pubkey);
	add_op(&script, OP_CHECKSIGVERIFY);
	add_op(&script, OP_SIZE);
	add_number(&script, 32);
	add_op(&script, OP_EQUALVERIFY);
	add_op(&script, OP_HASH160);
    script_push_bytes(&script, invoice_hash->u.u8, sizeof(invoice_hash->u.u8));
	add_op(&script, OP_EQUAL);
    return script;
}

u8 *make_eltoo_htlc_timeout_script(const tal_t *ctx, const struct pubkey *settlement_pubkey, u32 htlc_timeout)
{
    /* and EXPR_TIMEOUT =
     *
     * `<settlement_pubkey> OP_CHECKSIGVERIFY N OP_CHECKLOCKTIMEVERIFY`
     */
	u8 *script = tal_arr(ctx, u8, 0);
	add_push_xonly_key(&script, settlement_pubkey);
	add_op(&script, OP_CHECKSIGVERIFY);
	add_number(&script, htlc_timeout);
	add_op(&script, OP_CHECKLOCKTIMEVERIFY);
    return script;
}
