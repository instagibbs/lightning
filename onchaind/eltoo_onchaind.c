#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/peer_billboard.h>
#include <common/psbt_keypath.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/update_tx.h>
#include <hsmd/hsmd_wiregen.h>
#include <onchaind/onchain_types.h>
#include <onchaind/onchaind_wiregen.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>
#include "onchain_types_names_gen.h"

/* stdin == requests */
#define REQ_FD STDIN_FILENO
#define HSM_FD 3

/* FIXME Everything copy/pasted bc static. Deduplicate later */

/* Should make this a reusable thing */
static bool bipmusig_partial_sigs_combine_state(const struct eltoo_sign *state,
           struct bip340sig *sig)
{   
    const secp256k1_musig_partial_sig *p_sigs[2];
    p_sigs[0] = &state->self_psig.p_sig;
    p_sigs[1] = &state->other_psig.p_sig;
    return bipmusig_partial_sigs_combine(p_sigs, 2 /* num_signers */, &state->session.session, sig);
}  

/* Used as one-way latch to detect when the state ordering is being settled */
static bool update_phase;

/* During update_phase we queue all payment preimage notifications */
static struct preimage *cached_preimages;

/* Full tx we have partial signatures for */
static struct bitcoin_tx *complete_update_tx, *complete_settle_tx;

/* Tx we do not have full signatures for, but may appear on-chain */
static struct bitcoin_tx *committed_update_tx, *committed_settle_tx;

/* Required in various places: keys for commitment transaction. */
static struct eltoo_keyset *keyset;

/* The feerate for transactions spending HTLC outputs. */
static u32 htlc_feerate;

/* The dust limit to use when we generate transactions. */
static struct amount_sat dust_limit;

/* When to tell master about HTLCs which are missing/timed out */
static u32 reasonable_depth;

/* The messages to send at that depth. */
static u8 **missing_htlc_msgs;

/* The messages which were sent to us before init_reply was processed. */
static u8 **queued_msgs;

/* Our recorded channel balance at 'chain time' */
static struct amount_msat our_msat;

/* If we broadcast a tx, or need a delay to resolve the output. */
struct proposed_resolution {
	/* This can be NULL if our proposal is to simply ignore it after depth
      OR if we can make a transaction JIT (ELTOO_HTLC_{SUCESS/TIMEOUT}) */
	const struct bitcoin_tx *tx;
	/* Non-zero if this is CSV-delayed. */
	u32 depth_required;
	enum eltoo_tx_type tx_type;
};

/* How it actually got resolved. */
struct resolution {
	struct bitcoin_txid txid;
	unsigned int depth;
	enum eltoo_tx_type tx_type;
};

struct tracked_output {
	enum eltoo_tx_type tx_type;
	struct bitcoin_outpoint outpoint;
	u32 tx_blockheight;
	/* FIXME: Convert all depths to blocknums, then just get new blk msgs */
	u32 depth;
	struct amount_sat sat;
	enum output_type output_type;
    u32 locktime; /* Used to detec update->settle transition */
	u8 *scriptPubKey;

	/* If it is an HTLC, this is set, tapscripts are non-NULL. */
	struct htlc_stub htlc;
    int parity_bit; /* Used to finish control block for tapscript spend of output */
	const u8 *htlc_success_tapscript; /* EXPR_SUCCESS */
	const u8 *htlc_timeout_tapscript; /* EXPR_TIMEOUT */

	/* Our proposed solution (if any) */
	struct proposed_resolution *proposal;

	/* If it is resolved. */
	struct resolution *resolved;

	/* stashed so we can pass it along to the coin ledger */
	struct sha256 payment_hash;
};

static const char *eltoo_tx_type_name(enum eltoo_tx_type tx_type)
{
	size_t i;

	for (i = 0; enum_eltoo_tx_type_names[i].name; i++)
		if (enum_eltoo_tx_type_names[i].v == tx_type)
			return enum_eltoo_tx_type_names[i].name;
	return "unknown";
}

static const char *output_type_name(enum output_type output_type)
{
	size_t i;

	for (i = 0; enum_output_type_names[i].name; i++)
		if (enum_output_type_names[i].v == output_type)
			return enum_output_type_names[i].name;
	return "unknown";
}

static u8 *htlc_timeout_to_us(const tal_t *ctx,
                 struct bitcoin_tx *tx,
                 const u8 *tapscript)
{
    return towire_hsmd_sign_eltoo_htlc_timeout_tx(ctx, 
                             tx, tapscript);
}

static u8 *htlc_success_to_us(const tal_t *ctx,
                 struct bitcoin_tx *tx,
                 const u8 *tapscript)
{
    return towire_hsmd_sign_eltoo_htlc_success_tx(ctx, 
                             tx, tapscript);
}

static void send_coin_mvt(struct chain_coin_mvt *mvt TAKES)
{
	wire_sync_write(REQ_FD,
			take(towire_onchaind_notify_coin_mvt(NULL, mvt)));

	if (taken(mvt))
		tal_free(mvt);
}

/* Currently only used for HTLC resolutions */
static struct bitcoin_tx *bip340_tx_to_us(const tal_t *ctx,
                   u8 *(*hsm_sign_msg)(const tal_t *ctx,
                               struct bitcoin_tx *tx,
                               const u8 *tapscript),
                   struct tracked_output *out,
                   u32 locktime,
                   const u8 *tapscript,
                   const u8 *control_block,
                   enum eltoo_tx_type *tx_type,
                   u32 feerate,
                   const void *elem, size_t elem_size)
{
    struct bitcoin_tx *tx;
    size_t max_weight;
    struct amount_sat fee, min_out, amt;
    u8 *msg;
    struct bip340sig sig;
    u8 **witness;
    /* Modifying later, we need this at the end for witness construction  */
    enum eltoo_tx_type tx_type_copy = *tx_type;

	status_debug("Making tx of type %s with outputs spk: %s, tapscript: %s, control block: %s, our funding key: %s, their funding key: %s, inner pubkey: %s",
		eltoo_tx_type_name(*tx_type),
		tal_hex(NULL, out->scriptPubKey),
		tal_hex(NULL, tapscript),
		tal_hex(NULL, control_block),
		type_to_string(NULL, struct pubkey,
                    &keyset->self_funding_key),
		type_to_string(NULL, struct pubkey,
                    &keyset->other_funding_key),
		type_to_string(NULL, struct pubkey,
                    &keyset->inner_pubkey));

    tx = bitcoin_tx(ctx, chainparams, 1, 1, locktime);
    bitcoin_tx_add_input(tx, &out->outpoint, 0 /* sequence */,
            NULL /* scriptSig */, out->sat, out->scriptPubKey /* scriptPubkey */,
            NULL /* input_wscript */, NULL /* inner_pubkey */, NULL /* tap_tree */);

    /* FIXME figure out taproot output support to go directly into wallet aka "our_wallet_pubkey" */
    bitcoin_tx_add_output(
        tx, scriptpubkey_p2wpkh(tmpctx, &keyset->self_settle_key), NULL, out->sat);

    /* BIP340 sigs are constant sized, 65 bytes for non-default, and we expose
     a control block sized 33 + 32 for internal public key and tapleaf hash  */
    max_weight = bitcoin_tx_weight(tx) +
        1 + /* Witness stack size */
        1 + /* control block size */
        tal_count(control_block) +
        1 + /* tapscript size*/
        tal_count(tapscript) +
		1 + /* elem size */
		elem_size +
        1 + /* signature size */
        64 /* BIP340 sig with default sighash flag */;

    /* FIXME elements support */
    max_weight += 0;

    fee = amount_tx_fee(feerate, max_weight);

    /* Result is trivial?  Spend with small feerate, but don't wait
     * around for it as it might not confirm. */
    if (!amount_sat_add(&min_out, dust_limit, fee)) {
        status_failed(STATUS_FAIL_INTERNAL_ERROR,
                  "Cannot add dust_limit %s and fee %s",
                  type_to_string(tmpctx, struct amount_sat, &dust_limit),
                  type_to_string(tmpctx, struct amount_sat, &fee));
    }

    if (amount_sat_less(out->sat, min_out)) {
        /* FIXME: We should use SIGHASH_NONE so others can take it */
        fee = amount_tx_fee(feerate_floor(), max_weight);
        status_unusual("TX %s amount %s too small to"
                   " pay reasonable fee, using minimal fee"
                   " and ignoring",
                   eltoo_tx_type_name(*tx_type),
                   type_to_string(tmpctx, struct amount_sat, &out->sat));
        *tx_type = IGNORING_TINY_PAYMENT;
    }

    /* This can only happen if feerate_floor() is still too high; shouldn't
     * happen! */
    if (!amount_sat_sub(&amt, out->sat, fee)) {
        amt = dust_limit;
        status_broken("TX %s can't afford minimal feerate"
                  "; setting output to %s",
                  eltoo_tx_type_name(*tx_type),
                  type_to_string(tmpctx, struct amount_sat,
                         &amt));
    }
    bitcoin_tx_output_set_amount(tx, 0, amt);
    bitcoin_tx_finalize(tx);


    if (!wire_sync_write(HSM_FD, take(hsm_sign_msg(NULL, tx, tapscript))))
        status_failed(STATUS_FAIL_HSM_IO, "Writing sign request to hsm");
    msg = wire_sync_read(tmpctx, HSM_FD);
    if (!msg || !fromwire_hsmd_sign_eltoo_tx_reply(msg, &sig)) {
        status_failed(STATUS_FAIL_HSM_IO,
                  "Reading sign_tx_reply: %s",
                  tal_hex(tmpctx, msg));
    }

    if (tx_type_copy == ELTOO_HTLC_TIMEOUT || tx_type_copy == ELTOO_HTLC_SUCCESS) {
        witness = bitcoin_witness_bip340sig_and_element(tx, &sig, elem,
                          elem_size, tapscript, control_block);
    } else {
        /* Should only be called for HTLC resolutions for now */
        abort();
    }

    bitcoin_tx_input_set_witness(tx, 0 /* innum */, take(witness));

    return tx;
}

static u8 **derive_htlc_success_scripts(const tal_t *ctx, const struct htlc_stub *htlcs, const struct pubkey *our_htlc_pubkey, const struct pubkey *their_htlc_pubkey)
{
    size_t i;
    u8 **htlc_scripts = tal_arr(ctx, u8 *, tal_count(htlcs));

    for (i = 0; i < tal_count(htlcs); i++) {
        htlc_scripts[i] = make_eltoo_htlc_success_script(htlc_scripts,
                                   htlcs[i].owner == LOCAL ? their_htlc_pubkey : our_htlc_pubkey,
                                   &htlcs[i].ripemd);
		status_debug("HTLC success script %lu: %s", i, tal_hex(NULL, htlc_scripts[i]));
    }
    return htlc_scripts;
}

static u8 **derive_htlc_timeout_scripts(const tal_t *ctx, const struct htlc_stub *htlcs, const struct pubkey *our_htlc_pubkey, const struct pubkey *their_htlc_pubkey)
{
    size_t i;
    u8 **htlc_scripts = tal_arr(ctx, u8 *, tal_count(htlcs));

    for (i = 0; i < tal_count(htlcs); i++) {
        htlc_scripts[i] = make_eltoo_htlc_timeout_script(htlc_scripts,
                                   htlcs[i].owner == LOCAL ? our_htlc_pubkey : their_htlc_pubkey,
                                   htlcs[i].cltv_expiry);
		status_debug("HTLC timeout script %lu: %s", i, tal_hex(NULL, htlc_scripts[i]));
    }
    return htlc_scripts;
}

/*
static size_t resolve_htlc_timeouts(struct tracked_output *out,
                     const struct htlc_stub htlc,
                     u8 *htlc_success_script,
                     u8 *htlc_timeout_script)

{
    return 0;
}*/

/* They must all be in the same direction, since the scripts are different for
 * each dir.  Unless, of course, they've found a sha256 clash. */
static enum side matches_direction(const size_t *matches,
                   const struct htlc_stub *htlcs)
{
    for (size_t i = 1; i < tal_count(matches); i++) {
        assert(matches[i] < tal_count(htlcs));
        assert(htlcs[matches[i]].owner == htlcs[matches[i-1]].owner);
    }
    return htlcs[matches[0]].owner;
}

/* Return tal_arr of htlc indexes. Should be length 0 or 1 since CLTV is in script. */
static const size_t *eltoo_match_htlc_output(const tal_t *ctx,
                       const struct wally_tx_output *out,
                       u8 **htlc_success_scripts,
                       u8 **htlc_timeout_scripts,
                       int *parity_bit)
{
    size_t *matches = tal_arr(ctx, size_t, 0);
    const u8 *script = tal_dup_arr(tmpctx, u8, out->script, out->script_len,
                       0);
    /* Must be a p2tr output */
    if (!is_p2tr(script, NULL)) {
		/* FIXME do something better than crash */
		abort();
	}
    for (size_t i = 0; i < tal_count(htlc_success_scripts); i++) {
        struct sha256 tap_merkle_root;
        const struct pubkey *funding_pubkey_ptrs[2];
        struct pubkey taproot_pubkey;
        secp256k1_musig_keyagg_cache keyagg_cache;
        unsigned char tap_tweak_out[32];
        u8 *htlc_scripts[2];
        u8 *taproot_script;
		//u8 *success_annex;
        htlc_scripts[0] = htlc_success_scripts[i];
        htlc_scripts[1] = htlc_timeout_scripts[i];

        funding_pubkey_ptrs[0] = &keyset->self_funding_key;
        funding_pubkey_ptrs[1] = &keyset->other_funding_key;

        if (!htlc_success_scripts[i] || !htlc_timeout_scripts[i])
            continue;

		compute_taptree_merkle_root(&tap_merkle_root, htlc_scripts, /* num_scripts */ 2);
		//success_annex = make_annex_from_script(tmpctx, htlc_success_scripts[i]);
		//compute_taptree_merkle_root_with_hint(&tap_merkle_root_annex, htlc_timeout_scripts[i], success_annex);
        bipmusig_finalize_keys(&taproot_pubkey, &keyagg_cache, funding_pubkey_ptrs, /* n_pubkeys */ 2,
               &tap_merkle_root, tap_tweak_out, NULL);
        taproot_script = scriptpubkey_p2tr(ctx, &taproot_pubkey);

		status_debug("Reconstructed HTLC script %s for comparison with output: %s", tal_hex(NULL, taproot_script), tal_hex(NULL, script));

        if (memeq(taproot_script, tal_count(taproot_script), script, tal_count(script))) {
			status_debug("Matched!");
            tal_arr_expand(&matches, i);
            *parity_bit = pubkey_parity(&taproot_pubkey);
        }
    }
    return matches;
}

static struct tracked_output *
new_tracked_output(struct tracked_output ***outs,
		   const struct bitcoin_outpoint *outpoint,
		   u32 tx_blockheight,
		   enum eltoo_tx_type tx_type,
		   struct amount_sat sat,
		   enum output_type output_type,
		   u8 *scriptPubKey,
           u32 locktime,
		   const struct htlc_stub *htlc,
		   const u8 *htlc_success_tapscript TAKES,
		   const u8 *htlc_timeout_tapscript TAKES)
{
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_debug("Tracking output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint, outpoint),
		     eltoo_tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->outpoint = *outpoint;
	out->tx_blockheight = tx_blockheight;
	out->depth = 0;
	out->sat = sat;
	out->output_type = output_type;
    out->locktime = locktime;
	out->proposal = NULL;
	out->resolved = NULL;
	if (scriptPubKey) 
		out->scriptPubKey = tal_dup_talarr(out, u8, scriptPubKey);
	if (htlc)
		out->htlc = *htlc;
	out->htlc_success_tapscript = tal_steal(out, htlc_success_tapscript);
	out->htlc_timeout_tapscript = tal_steal(out, htlc_timeout_tapscript);

	tal_arr_expand(outs, out);

	return out;
}

/* Marks a utxo as resolved. The utxo still needs to be buried >>==100 to be
 * irrevocably resolved
 */
static void ignore_output(struct tracked_output *out)
{
	status_debug("Ignoring output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint,
				    &out->outpoint),
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->outpoint.txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = ELTOO_SELF;
}

static enum wallet_tx_type onchain_txtype_to_wallet_txtype(enum eltoo_tx_type t)
{
    /* FIXME Need to distinguish TX_THEIRS when possible (SUCCESS/TIMEOUT)  */
	switch (t) {
	case ELTOO_FUNDING_TRANSACTION:
		return TX_CHANNEL_FUNDING;
	case ELTOO_MUTUAL_CLOSE:
		return TX_CHANNEL_CLOSE;
    case ELTOO_UPDATE:
    case ELTOO_INVALIDATED_UPDATE:
    case ELTOO_SETTLE:
    case ELTOO_INVALIDATED_SETTLE:
		return TX_CHANNEL_UNILATERAL;
    case ELTOO_HTLC_SUCCESS:
		return TX_CHANNEL_HTLC_SUCCESS;
    case ELTOO_HTLC_TIMEOUT:
	case ELTOO_HTLC_TIMEOUT_TO_THEM:
		return TX_CHANNEL_HTLC_TIMEOUT;
    case ELTOO_SELF:
		return TX_CHANNEL_SWEEP;
    case ELTOO_IGNORING_TINY_PAYMENT:
    case ELTOO_UNKNOWN_TXTYPE:
		return TX_UNKNOWN;
	}
	abort();
}

/** eltoo_proposal_is_rbfable
 *
 * @brief returns true if the given proposal
 * would be RBFed if the output it is tracking
 * increases in depth without being spent.
 */
static bool eltoo_proposal_is_rbfable(const struct proposed_resolution *proposal)
{
	/* We may fee bump anything time-sensitive
	 */
	return proposal->tx_type == ELTOO_UPDATE ||
            proposal->tx_type == ELTOO_SETTLE ||
            proposal->tx_type == ELTOO_HTLC_SUCCESS ||
            proposal->tx_type == ELTOO_HTLC_TIMEOUT;
}

/** proposal_should_rbf
 *
 * @brief the given output just increased its depth,
 * so the proposal for it should be RBFed and
 * rebroadcast.
 *
 * @desc precondition: the given output must have an
 * rbfable proposal as per `eltoo_proposal_is_rbfable`.
 */
static void eltoo_proposal_should_rbf(struct tracked_output *out)
{
	struct bitcoin_tx *tx = NULL;
	u32 depth;

	assert(out->proposal);
	assert(eltoo_proposal_is_rbfable(out->proposal));

	depth = out->depth;

	/* Do not RBF at depth 1.
	 *
	 * Since we react to *onchain* events, whatever proposal we made,
	 * the output for that proposal is already at depth 1.
	 *
	 * Since our initial proposal was broadcasted with the output at
	 * depth 1, we should not RBF until a new block arrives, which is
	 * at depth 2.
	 */
	if (depth <= 1)
		return;

	/* Add other RBF-able proposals here.  */

	/* Broadcast the transaction.  */
	if (tx) {
		enum wallet_tx_type wtt;

		status_debug("Broadcasting RBF %s (%s) to resolve %s/%s "
			     "depth=%"PRIu32"",
			     eltoo_tx_type_name(out->proposal->tx_type),
			     type_to_string(tmpctx, struct bitcoin_tx, tx),
			     eltoo_tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);

		wtt = onchain_txtype_to_wallet_txtype(out->proposal->tx_type);
		wire_sync_write(REQ_FD,
				take(towire_onchaind_broadcast_tx(NULL, tx,
								 wtt,
								 true)));
	}
}

static void eltoo_proposal_meets_depth(struct tracked_output *out)
{
	bool is_rbf = eltoo_proposal_is_rbfable(out->proposal);

	/* Some transactions can be constructed just-in-time to have better fees if updated */
	if (out->proposal->tx_type == ELTOO_HTLC_TIMEOUT) {
		if (!out->proposal->tx) {
			status_broken("Proposal tx already exists for HTLC timeout when it should be null. Stumbling through.");
		} else {
			status_debug("Creating HTLC timeout sweep transaction to be signed");
			out->proposal->tx = bip340_tx_to_us(out,
				htlc_timeout_to_us,
				out,
				out->htlc.cltv_expiry,
				out->htlc_timeout_tapscript,
				compute_control_block(out, out->htlc_success_tapscript /* other_script */, NULL /* annex_hint*/, &keyset->inner_pubkey, out->parity_bit),
				&out->proposal->tx_type, /* over-written if too small to care */
				htlc_feerate,
				NULL /* elem */, 0 /* elem_size */);
		}
	} else if (out->proposal->tx_type == ELTOO_HTLC_TIMEOUT_TO_THEM) {
		// Not going to do anything to resolve this proposal here,
		// instead we'll keep waiting for HTLC preimage
		return;
	}

	status_debug("Broadcasting %s (%s) to resolve %s/%s",
		     eltoo_tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_tx, out->proposal->tx),
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	wire_sync_write(
	    REQ_FD,
	    take(towire_onchaind_broadcast_tx(
		 NULL, out->proposal->tx,
		 onchain_txtype_to_wallet_txtype(out->proposal->tx_type),
		 is_rbf)));

	/* Don't wait for this if we're ignoring the tiny payment. */
	if (out->proposal->tx_type == ELTOO_IGNORING_TINY_PAYMENT) {
		ignore_output(out);
	}

	/* Otherwise we will get a callback when it's in a block. */
}

static bool is_valid_sig(const u8 *e)
{
	struct bitcoin_signature sig;
	return signature_from_der(e, tal_count(e), &sig);
}

/* We ignore things which look like signatures. */
static bool input_similar(const struct wally_tx_input *i1,
			  const struct wally_tx_input *i2)
{
	u8 *s1, *s2;

	if (!memeq(i1->txhash, WALLY_TXHASH_LEN, i2->txhash, WALLY_TXHASH_LEN))
		return false;

	if (i1->index != i2->index)
		return false;

	if (!scripteq(i1->script, i2->script))
		return false;

	if (i1->sequence != i2->sequence)
		return false;

	if (i1->witness->num_items != i2->witness->num_items)
		return false;

	for (size_t i = 0; i < i1->witness->num_items; i++) {
		/* Need to wrap these in `tal_arr`s since the primitives
		 * except to be able to call tal_bytelen on them */
		s1 = tal_dup_arr(tmpctx, u8, i1->witness->items[i].witness,
				 i1->witness->items[i].witness_len, 0);
		s2 = tal_dup_arr(tmpctx, u8, i2->witness->items[i].witness,
				 i2->witness->items[i].witness_len, 0);

		if (scripteq(s1, s2))
			continue;

		if (is_valid_sig(s1) && is_valid_sig(s2))
			continue;
		return false;
	}

	return true;
}

/* This simple case: true if this was resolved by our proposal. */
static bool resolved_by_proposal(struct tracked_output *out,
				 const struct tx_parts *tx_parts)
{
	/* If there's no TX associated, it's not us. */
	if (!out->proposal->tx)
		return false;

	/* Our proposal can change as feerates change.  Input
	 * comparison (ignoring signatures) works pretty well. */
	if (tal_count(tx_parts->inputs) != out->proposal->tx->wtx->num_inputs)
		return false;

	for (size_t i = 0; i < tal_count(tx_parts->inputs); i++) {
		if (!input_similar(tx_parts->inputs[i],
				   &out->proposal->tx->wtx->inputs[i]))
			return false;
	}

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	status_debug("Resolved %s/%s by our proposal %s (%s)",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid,
				    &out->resolved->txid));

	out->resolved->depth = 0;
	out->resolved->tx_type = out->proposal->tx_type;
	return true;
}

/* Otherwise, we figure out what happened and then call this. */
static void resolved_by_other(struct tracked_output *out,
			      const struct bitcoin_txid *txid,
			      enum eltoo_tx_type tx_type)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = *txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = tx_type;

	status_debug("Resolved %s/%s by %s (%s)",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid, txid));
}

static bool is_mutual_close(u32 locktime)
{
    /* If we mask update number, this needs to change */
    return locktime == 0;
}

/* BOLT #5:
 *
 * Outputs that are *resolved* are considered *irrevocably resolved*
 * once the remote's *resolving* transaction is included in a block at least 100
 * deep, on the most-work blockchain.
 */
static size_t num_not_irrevocably_resolved(struct tracked_output **outs)
{
	size_t i, num = 0;

	for (i = 0; i < tal_count(outs); i++) {
        /* FIXME If an output gets reorged out, what do we do? */
		if (!outs[i]->resolved || outs[i]->resolved->depth < 100)
			num++;
	}
	return num;
}

static u32 prop_blockheight(const struct tracked_output *out)
{
	return out->tx_blockheight + out->proposal->depth_required;
}

static void billboard_update(struct tracked_output **outs)
{
	const struct tracked_output *best = NULL;

	/* Highest priority is to report on proposals we have */
	for (size_t i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->proposal || outs[i]->resolved)
			continue;
		if (!best || prop_blockheight(outs[i]) < prop_blockheight(best))
			best = outs[i];
	}

	if (best) {
		/* If we've broadcast and not seen yet, this happens */
		if (best->proposal->depth_required <= best->depth) {
			peer_billboard(false,
				       "%u outputs unresolved: waiting confirmation that we spent %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       eltoo_tx_type_name(best->proposal->tx_type));
		} else {
			peer_billboard(false,
				       "%u outputs unresolved: in %u blocks will spend %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       best->proposal->depth_required - best->depth,
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       eltoo_tx_type_name(best->proposal->tx_type));
		}
		return;
	}

	/* Now, just report on the last thing we're waiting out. */
	for (size_t i = 0; i < tal_count(outs); i++) {
		/* FIXME: Can this happen?  No proposal, no resolution? */
		if (!outs[i]->resolved)
			continue;
		if (!best || outs[i]->resolved->depth < best->resolved->depth)
			best = outs[i];
	}

	if (best) {
		peer_billboard(false,
			       "All outputs resolved:"
			       " waiting %u more blocks before forgetting"
			       " channel",
			       best->resolved->depth < 100
			       ? 100 - best->resolved->depth : 0);
		return;
	}

	/* Not sure this can happen, but take last one (there must be one!) */
	best = outs[tal_count(outs)-1];
	peer_billboard(false, "%u outputs unresolved: %s is one (depth %u)",
		       num_not_irrevocably_resolved(outs),
		       output_type_name(best->output_type), best->depth);
}

static void propose_resolution(struct tracked_output *out,
                   const struct bitcoin_tx *tx,
                   unsigned int depth_required,
                   enum eltoo_tx_type tx_type)
{
    status_debug("Propose handling %s/%s by %s (%s) after %u blocks",
             eltoo_tx_type_name(out->tx_type),
             output_type_name(out->output_type),
             eltoo_tx_type_name(tx_type),
             tx ? type_to_string(tmpctx, struct bitcoin_tx, tx):"IGNORING",
             depth_required);

    out->proposal = tal(out, struct proposed_resolution);
    out->proposal->tx = tal_steal(out->proposal, tx);
    out->proposal->depth_required = depth_required;
    out->proposal->tx_type = tx_type;

    if (depth_required == 0)
        eltoo_proposal_meets_depth(out);
}

/* HTLC resolution won't have tx pre-built */
static void propose_htlc_timeout_resolution(struct tracked_output *out,
                   unsigned int depth_required,
				   enum eltoo_tx_type tx_type)
{
    status_debug("Propose handling %s/%s by %s after %u blocks",
             eltoo_tx_type_name(out->tx_type),
             output_type_name(out->output_type),
             eltoo_tx_type_name(tx_type),
             depth_required);

    out->proposal = tal(out, struct proposed_resolution);
    out->proposal->depth_required = depth_required;
    out->proposal->tx_type = tx_type;

    if (depth_required == 0)
        eltoo_proposal_meets_depth(out);
}

/* HTLC resolution won't have tx pre-built */
static void propose_htlc_resolution_at_block(struct tracked_output *out,
                    u32 block_required,
                    enum eltoo_tx_type tx_type)
{
    u32 depth;

    /* Expiry could be in the past! */
    if (block_required < out->tx_blockheight)
        depth = 0;
    else /* Note that out->tx_blockheight is already at depth 1 */
        depth = block_required - out->tx_blockheight + 1;
    propose_htlc_timeout_resolution(out, depth, tx_type);
}

static void unwatch_txid(const struct bitcoin_txid *txid)
{
	u8 *msg;

	msg = towire_onchaind_unwatch_tx(NULL, txid);
	wire_sync_write(REQ_FD, take(msg));
}


static void handle_eltoo_htlc_onchain_fulfill(struct tracked_output *out,
					const struct tx_parts *tx_parts,
					const struct bitcoin_outpoint *htlc_outpoint)
{
	const struct wally_tx_witness_item *preimage_item;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* Our HTLC, they filled (must be an HTLC-success tx). */
	if (out->tx_type == ELTOO_SETTLE
		|| out->tx_type == ELTOO_INVALIDATED_SETTLE) {
        /* BOLTXX
         *   The recipient node can redeem the HTLC with the witness:
         *
         *      <payment_preimage> <recipient_settlement_pubkey_signature>
         */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 4) /* +2 for script/control block */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      eltoo_tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[0];
	} else
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "onchain_fulfill for %s/%s?",
			      eltoo_tx_type_name(out->tx_type),
			      output_type_name(out->output_type));

	memcpy(&preimage, preimage_item->witness, sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	if (!ripemd160_eq(&ripemd, &out->htlc.ripemd))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad preimage %s (ripemd not %s)",
			      eltoo_tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      type_to_string(tmpctx, struct preimage, &preimage),
			      type_to_string(tmpctx, struct ripemd160,
					     &out->htlc.ripemd));

	/* we stash the payment_hash into the tracking_output so we
	 * can pass it along, if needbe, to the coin movement tracker */
	out->payment_hash = sha;

	/* Tell master we found a preimage. */
	status_debug("%s/%s gave us preimage %s",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct preimage, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_extracted_preimage(NULL,
							       &preimage)));
}

static void onchain_annotate_txin(const struct bitcoin_txid *txid, u32 innum,
				  enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txin(
				    tmpctx, txid, innum, type)));
}

struct htlcs_info {
	struct htlc_stub *htlcs;
	bool *tell_if_missing;
	bool *tell_immediately;
};

static void track_settle_outputs(struct tracked_output ***outs,
			 const struct tx_parts *tx_parts,
			 u32 tx_blockheight,
             u8 **htlc_success_scripts,
             u8 **htlc_timeout_scripts,
             struct htlcs_info *htlcs_info)
{
    /* Settlement transaction has 5 types of outputs it's looking for  */
    for (size_t j = 0; j < tal_count(tx_parts->outputs); j++) {
        struct wally_tx_output *settle_out = tx_parts->outputs[j];
        struct tracked_output *out;
        struct amount_sat satoshis = amount_sat(settle_out->satoshi);
        int parity_bit;

		status_debug("Output script: %s", tal_hex(tmpctx, settle_out->script));


        /* (1) Ephemeral Anchor */
        if (is_ephemeral_anchor(settle_out->script)) {
            /* Anchor is lightningd's problem */
            continue;
        }

		if (!is_p2tr(settle_out->script, NULL)) {
			/* Everything should be taproot FIXME what do */
			abort();
		}

		/* Balance outputs are self-resolving in the settle tx */
		u8 *to_us = scriptpubkey_p2tr(tmpctx, &keyset->self_settle_key);
		status_debug("to_us script: %s", tal_hex(tmpctx, to_us));
		if (memcmp(settle_out->script, to_us, tal_count(to_us)) == 0) {
			continue;
		}

		u8 *to_them = scriptpubkey_p2tr(tmpctx, &keyset->other_settle_key);
		status_debug("to_them script: %s", tal_hex(tmpctx, to_them));
		if (memcmp(settle_out->script, to_them, tal_count(to_them)) == 0) {
			continue;
		}

        const size_t *matches = eltoo_match_htlc_output(tmpctx, settle_out, htlc_success_scripts, htlc_timeout_scripts, &parity_bit);
        struct bitcoin_outpoint outpoint;
        outpoint.txid = tx_parts->txid;
        outpoint.n = j;
        if (tal_count(matches) == 0) {
            /* Update we don't recognise :( FIXME what do */
            /* This can hit if it was a "future" settlement transaction, which terminates the process with an error */
            status_failed(STATUS_FAIL_INTERNAL_ERROR, "Couldn't match settlement output script to known output type");
        } else {
            if (matches_direction(matches, htlcs_info->htlcs) == REMOTE) {
                /* (4) HTLC they own (to us) */
                out = new_tracked_output(outs, &outpoint,
                    tx_blockheight,
                    ELTOO_SETTLE,
                    satoshis,
                    THEIR_HTLC,
					settle_out->script,
                    0 /* locktime (unused by settle logic) */,
                    &htlcs_info->htlcs[matches[0]] /* htlc */,
                    htlc_success_scripts[matches[0]] /* htlc_success_tapscript */,
                    htlc_timeout_scripts[matches[0]] /* htlc_timeout_tapscript */);
                out->parity_bit = parity_bit;
				/* We set a resolution we won't trigger ourselves, ideally we sweep via preimage
				 * I do this mostly to satisfy the billboard notification of pending resolutions
			     * in billboard_update
				 */
                propose_htlc_resolution_at_block(out, htlcs_info->htlcs[matches[0]].cltv_expiry, ELTOO_HTLC_TIMEOUT_TO_THEM);
            } else {
                /* (5) HTLC we own (to them) */
                out = new_tracked_output(outs, &outpoint,
                    tx_blockheight,
                    ELTOO_SETTLE,
                    satoshis,
                    OUR_HTLC,
					settle_out->script,
                    0 /* locktime (unused by settle logic) */,
                    &htlcs_info->htlcs[matches[0]] /* htlc */,
                    htlc_success_scripts[matches[0]] /* htlc_success_tapscript */,
                    htlc_timeout_scripts[matches[0]] /* htlc_timeout_tapscript */);
                out->parity_bit = parity_bit;
                /* We'd like to propose a reasonable feerate tx at the time needed, not before */
                propose_htlc_resolution_at_block(out, htlcs_info->htlcs[matches[0]].cltv_expiry, ELTOO_HTLC_TIMEOUT);
            }
            assert(out);
            continue;
        }
    }
}

/* BOLT #XX:
 * FIXME add BOLT text
 */
/* Master makes sure we only get told preimages once other node is committed. */
static void eltoo_handle_preimage(struct tracked_output **outs,
			    const struct preimage preimage)
{
	size_t i;
	struct sha256 sha;
	struct ripemd160 ripemd;

	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	for (i = 0; i < tal_count(outs); i++) {
        struct bitcoin_tx *tx;
        enum eltoo_tx_type tx_type = ELTOO_HTLC_SUCCESS;

		if (outs[i]->output_type != THEIR_HTLC)
			continue;

		if (!ripemd160_eq(&outs[i]->htlc.ripemd, &ripemd))
			continue;

		/* Too late? */
		if (outs[i]->resolved) {
			status_broken("HTLC already resolved by %s"
				     " when we found preimage",
				     eltoo_tx_type_name(outs[i]->resolved->tx_type));
			return;
		}

		/* stash the payment_hash so we can track this coin movement */
		outs[i]->payment_hash = sha;

		/* Discard any previous resolution.  Could be a timeout,
		 * could be due to multiple identical rhashes in tx. */
		outs[i]->proposal = tal_free(outs[i]->proposal);

		status_debug("Creating HTLC success sweep transaction to be signed");
        tx = bip340_tx_to_us(outs[i],
            htlc_success_to_us,
            outs[i],
            0 /* locktime */,
            outs[i]->htlc_success_tapscript,
            compute_control_block(outs[i], outs[i]->htlc_timeout_tapscript /* other_script */, NULL /* annex_hint*/, &keyset->inner_pubkey, outs[i]->parity_bit),
            &tx_type, /* over-written if too small to care */
            htlc_feerate,
			&preimage,
			sizeof(preimage));

        propose_resolution(outs[i], tx, 0 /* depth_required */, tx_type);
	}
}

static void eltoo_handle_cached_preimages(struct tracked_output **outs,
			    struct preimage *cached_preimages)
{
	status_debug("Processing cached preimages now that we have settle tx confirmed");
    for (int j=0; j<tal_count(cached_preimages); j++) {
        eltoo_handle_preimage(outs, cached_preimages[j]);
    }
    tal_free(cached_preimages);
}

/* An output has been spent: see if it resolves something we care about. */
static void output_spent(struct tracked_output ***outs,
			 const struct tx_parts *tx_parts,
			 u32 input_num,
			 u32 tx_blockheight,
             u32 locktime,
             u8 **htlc_success_scripts,
             u8 **htlc_timeout_scripts,
             struct htlcs_info *htlcs_info)
{
    assert(tal_count(htlc_success_scripts) == tal_count(htlc_timeout_scripts));
	for (size_t i = 0; i < tal_count(*outs); i++) {
		struct tracked_output *out = (*outs)[i];
        struct bitcoin_outpoint htlc_outpoint;

		if (out->resolved)
			continue;

		if (!wally_tx_input_spends(tx_parts->inputs[input_num],
					   &out->outpoint))
			continue;

        /* This output spend was either ours, or someone else's. Output is resolved either way */
        if (!resolved_by_proposal(out, tx_parts)) {
            ignore_output(out);
        }

        /* (1) Settlement transaction */
        if (locktime == out->locktime && update_phase) {
            /* Update phase ends with repeating locktime, which should be settle tx */
            update_phase = false;

            /* Should be (any) settlement transaction! Process new outputs */
            track_settle_outputs(outs, tx_parts, tx_blockheight, htlc_success_scripts, htlc_timeout_scripts, htlcs_info);

            /* Now that we've left update phase and know settlement outputs, process cached preimages */
            eltoo_handle_cached_preimages(*outs, cached_preimages);

        } else if (locktime != out->locktime && update_phase) {
        /* (2) Update transaction*/

            /* New state output will be on same index as tx input spending state */
            struct bitcoin_outpoint outpoint;
            struct amount_asset asset;
            struct amount_sat amt;
            struct tracked_output *new_state_out;

            asset = wally_tx_output_get_amount(tx_parts->outputs[input_num]);
            amt = amount_asset_to_sat(&asset);
            outpoint.txid = tx_parts->txid;
            outpoint.n = input_num;

            new_state_out = new_tracked_output(outs, &outpoint, tx_blockheight, ELTOO_UPDATE, amt, DELAYED_OUTPUT_TO_US, tx_parts->outputs[input_num]->script, locktime,
                NULL /* htlcs */, NULL /* htlc_success_tapscript */, NULL /* htlc_timeout_tapscript */);

            if (locktime == complete_update_tx->wtx->locktime) {
                bind_settle_tx(tx_parts->txid, input_num, complete_settle_tx);
                propose_resolution(new_state_out, complete_settle_tx,  complete_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);
            } else if (committed_update_tx && locktime == committed_update_tx->wtx->locktime) {
                bind_settle_tx(tx_parts->txid, input_num, committed_settle_tx);
                propose_resolution(new_state_out, committed_settle_tx, committed_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);
            } else if ((committed_update_tx && locktime > committed_update_tx->wtx->locktime) ||
                (!committed_update_tx && locktime > complete_update_tx->wtx->locktime)) {
                /* If we get lucky the settle transaction will hit chain and we can get balance back */
                /* FIXME Should we give up after a long time? */
                status_debug("Uh-oh, update from the future!");
            } else {
                /* FIXME probably should assert something here even though we checked for index already? */
                struct wally_tx_witness_stack *wit_stack = tx_parts->inputs[input_num]->witness;
                u8 *invalidated_annex_hint = wit_stack->items[wit_stack->num_items - 1].witness;  /* Annex is last witness item! */
                struct bip340sig sig;
                u32 invalidated_update_num = locktime - 500000000;
                bipmusig_partial_sigs_combine_state(&keyset->last_complete_state, &sig);
                /* Need to propose our last complete update */
                bind_update_tx_to_update_outpoint(complete_update_tx,
                            complete_settle_tx,
                            &outpoint,
                            keyset,
                            invalidated_annex_hint,
                            invalidated_update_num,
                            &keyset->inner_pubkey,
                            &sig);
                propose_resolution(new_state_out, complete_update_tx, 0 /* depth_required */, ELTOO_UPDATE);

                /* Inform master of latest known state output to rebind to over RPC responses
                 * We don't send complete/committed_tx state outputs or future ones */
                wire_sync_write(REQ_FD,
                        take(towire_eltoo_onchaind_new_state_output(out, &outpoint, invalidated_update_num, invalidated_annex_hint)));
            }
        } else {
            /* (3) Any transaction after settlement */

            htlc_outpoint.txid = tx_parts->txid;
            htlc_outpoint.n = input_num;

            /* We are only tracking HTLC outputs */
            switch (out->output_type) {
            case OUR_HTLC:
                /* They swept(and revealed HTLC), or we swept via timeout */

                /* They revealed HTLC (sig+htlc+script+control block) */
                if (tx_parts->inputs[htlc_outpoint.n]->witness->num_items == 4) {
                    handle_eltoo_htlc_onchain_fulfill(out, tx_parts, &htlc_outpoint);
                }

                /* We swept ¯\_(ツ)_/¯ (sig+script+control block only) */
                break;
            case THEIR_HTLC:
                /* We fulfilled and swept, or they timed out and we already swept.
                 * Either way we're done.
                 */
                break;
            /* We don't track these; should never hit! */
            case OUTPUT_TO_US:
            case DELAYED_OUTPUT_TO_THEM:
            case DELAYED_CHEAT_OUTPUT_TO_THEM:
            case DELAYED_OUTPUT_TO_US:
            case OUTPUT_TO_THEM:
            case ELEMENTS_FEE:
            case ANCHOR_TO_US:
            case ANCHOR_TO_THEM:
            case FUNDING_OUTPUT:
                status_failed(STATUS_FAIL_INTERNAL_ERROR,
                          "Tracked spend of %s/%s?",
                          eltoo_tx_type_name(out->tx_type),
                          output_type_name(out->output_type));
            }
        }
        /* If we got this far, we found the matching output, stop */
        return;
    }

    /* Otherwise... */
    struct bitcoin_txid txid;
    wally_tx_input_get_txid(tx_parts->inputs[input_num], &txid);
    /* Not interesting to us, so unwatch the tx and all its outputs */
    status_debug("Notified about tx %s output %u spend, but we don't care",
             type_to_string(tmpctx, struct bitcoin_txid, &txid),
             tx_parts->inputs[input_num]->index);

    unwatch_txid(&tx_parts->txid);
}

static void eltoo_update_resolution_depth(struct tracked_output *out, u32 depth)
{
	bool reached_reasonable_depth;

	status_debug("%s/%s->%s depth %u",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(out->resolved->tx_type),
		     depth);

	/* We only set this once. */
	reached_reasonable_depth = (out->resolved->depth < reasonable_depth
				    && depth >= reasonable_depth);

	/* BOLT #XX:
     *
     *  - if the settlement transaction HTLC output has *timed out* and hasn't been
     *    *resolved*:
     *    - MUST *resolve* the output by spending it using their own `settlement_pubkey` to
     *     any address deemed necessary.
     *            vvvvvvvvvvv
     *    - once the resolving transaction has reached reasonable depth:
     *      - MUST fail the corresponding incoming HTLC (if any).
     *    - for any committed HTLC that has been trimmed:
     *      - once the update transaction that spent the funding output has reached reasonable depth:
     *        - MUST fail the corresponding incoming HTLC (if any).
     */
	if (out->resolved->tx_type == ELTOO_HTLC_TIMEOUT && reached_reasonable_depth) {
		u8 *msg;
		status_debug("%s/%s reached reasonable depth %u",
			     eltoo_tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);
		msg = towire_onchaind_htlc_timeout(out, &out->htlc);
		wire_sync_write(REQ_FD, take(msg));
	}
	out->resolved->depth = depth;
}

static void eltoo_tx_new_depth(struct tracked_output **outs,
			 const struct bitcoin_txid *txid, u32 depth)
{
	size_t i;

    /* Special handling for funding-spending update tx reaching depth */
    /* FIXME re-add note_missing_htlcs for TRIMMED ONLY here... should this b
     * done immediately, not at "reasonable depth"?
     */
    if (bitcoin_txid_eq(&outs[0]->resolved->txid, txid)
        && depth >= reasonable_depth
        && missing_htlc_msgs) {
        status_debug("Sending %zu missing htlc messages",
                 tal_count(missing_htlc_msgs));
        for (i = 0; i < tal_count(missing_htlc_msgs); i++)
            wire_sync_write(REQ_FD, missing_htlc_msgs[i]);
        /* Don't do it again. */
        missing_htlc_msgs = tal_free(missing_htlc_msgs);
    }

	for (i = 0; i < tal_count(outs); i++) {
		/* Update output depth. */
		if (bitcoin_txid_eq(&outs[i]->outpoint.txid, txid))
			outs[i]->depth = depth;

		/* Is this tx resolving an output? (Also, send
         * off timed out notification once ELTOO_HTLC_TIMEOUT
         * reaches reasonable depth) */
		if (outs[i]->resolved) {
			if (bitcoin_txid_eq(&outs[i]->resolved->txid, txid)) {
				eltoo_update_resolution_depth(outs[i], depth);
			}
			continue;
		}

		/* Otherwise, is this something we have a pending
		 * proposal resolution for? */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
            && depth >= outs[i]->proposal->depth_required) {
			eltoo_proposal_meets_depth(outs[i]);
		}

		/* Otherwise, is this an output whose proposed resolution
		 * we should RBF?  */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
		    && eltoo_proposal_is_rbfable(outs[i]->proposal))
			eltoo_proposal_should_rbf(outs[i]);

	}
}


#if DEVELOPER
static void memleak_remove_globals(struct htable *memtable, const tal_t *topctx)
{
	if (keyset)
		memleak_remove_region(memtable, keyset, sizeof(*keyset));
	memleak_remove_pointer(memtable, topctx);
	memleak_remove_region(memtable,
			      missing_htlc_msgs, tal_bytelen(missing_htlc_msgs));
	memleak_remove_region(memtable,
			      queued_msgs, tal_bytelen(queued_msgs));
}

static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	if (!fromwire_onchaind_dev_memleak(msg))
		return false;

	memtable = memleak_find_allocations(tmpctx, msg, msg);
	/* Top-level context is parent of outs */
	memleak_remove_globals(memtable, tal_parent(outs));
	memleak_remove_region(memtable, outs, tal_bytelen(outs));

	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(REQ_FD,
			take(towire_onchaind_dev_memleak_reply(NULL,
							      found_leak)));
	return true;
}
#else
static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	return false;
}
#endif /* !DEVELOPER */

static void wait_for_mutual_resolved(struct tracked_output **outs)
{
	billboard_update(outs);

	while (num_not_irrevocably_resolved(outs) != 0) {
		u8 *msg;
		struct bitcoin_txid txid;
		u32 depth;

		if (tal_count(queued_msgs)) {
			msg = tal_steal(outs, queued_msgs[0]);
			tal_arr_remove(&queued_msgs, 0);
		} else
			msg = wire_sync_read(outs, REQ_FD);

		status_debug("Got new message %s",
			     onchaind_wire_name(fromwire_peektype(msg)));

        /* Should only be getting updates on the funding output spend getting buried */
		if (fromwire_onchaind_depth(msg, &txid, &depth)) {
			eltoo_tx_new_depth(outs, &txid, depth);
        } else if (!handle_dev_memleak(outs, msg)) {
			master_badmsg(-1, msg);
        }

		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchaind_all_irrevocably_resolved(outs)));
}

static void wait_for_resolved(struct tracked_output **outs, struct htlcs_info *htlcs_info)
{
	billboard_update(outs);

    /* Calculate all the HTLC scripts so we can match them */
    u8 **htlc_success_scripts = derive_htlc_success_scripts(outs, htlcs_info->htlcs, &keyset->self_settle_key, &keyset->other_settle_key);
    u8 **htlc_timeout_scripts = derive_htlc_timeout_scripts(outs, htlcs_info->htlcs, &keyset->self_settle_key, &keyset->other_settle_key);

	while (num_not_irrevocably_resolved(outs) != 0) {
		u8 *msg;
		struct bitcoin_txid txid;
		u32 input_num, depth, tx_blockheight;
		struct preimage preimage;
		struct tx_parts *tx_parts;
        u32 locktime;

		if (tal_count(queued_msgs)) {
			msg = tal_steal(outs, queued_msgs[0]);
			tal_arr_remove(&queued_msgs, 0);
		} else
			msg = wire_sync_read(outs, REQ_FD);

		status_debug("Got new message %s",
			     onchaind_wire_name(fromwire_peektype(msg)));

		if (fromwire_onchaind_depth(msg, &txid, &depth)) {
			eltoo_tx_new_depth(outs, &txid, depth);
        } else if (fromwire_onchaind_spent(msg, msg, &tx_parts, &locktime, &input_num,
						&tx_blockheight)) {
			output_spent(&outs, tx_parts, input_num, tx_blockheight, locktime, htlc_success_scripts, htlc_timeout_scripts, htlcs_info);
		} else if (fromwire_onchaind_known_preimage(msg, &preimage))
            /* We don't know the final set of settlement utxos yet */
            if (update_phase) {
                tal_arr_expand(&cached_preimages, preimage);
            } else {
			    eltoo_handle_preimage(outs, preimage);
            }
		else if (!handle_dev_memleak(outs, msg))
			master_badmsg(-1, msg);

		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchaind_all_irrevocably_resolved(outs)));
}

struct htlc_with_tells {
	struct htlc_stub htlc;
	bool tell_if_missing, tell_immediately;
};

static int cmp_htlc_with_tells_cltv(const struct htlc_with_tells *a,
                    const struct htlc_with_tells *b, void *unused)
{
    if (a->htlc.cltv_expiry < b->htlc.cltv_expiry)
        return -1;
    else if (a->htlc.cltv_expiry > b->htlc.cltv_expiry)
        return 1;
    return 0; 
}

/* sends eltoo reply to be handled properly, otherwise the same */
static struct htlcs_info *eltoo_init_reply(const tal_t *ctx, const char *what)
{
    struct htlcs_info *htlcs_info = tal(ctx, struct htlcs_info);
    u8 *msg;
    struct htlc_with_tells *htlcs;

    /* Send init_reply first, so billboard gets credited to ONCHAIND */
    wire_sync_write(REQ_FD,
            take(towire_eltoo_onchaind_init_reply(NULL)));

    peer_billboard(true, what);

    /* Read in htlcs */
    for (;;) {
        msg = wire_sync_read(queued_msgs, REQ_FD);
        if (fromwire_onchaind_htlcs(tmpctx, msg,
                        &htlcs_info->htlcs,
                        &htlcs_info->tell_if_missing,
                        &htlcs_info->tell_immediately)) {
            tal_free(msg);
            break;
        }

        /* Process later */
        tal_arr_expand(&queued_msgs, msg);
    }

    /* One convenient structure, so we sort them together! */
    htlcs = tal_arr(tmpctx, struct htlc_with_tells, tal_count(htlcs_info->htlcs));
    for (size_t i = 0; i < tal_count(htlcs); i++) {
        htlcs[i].htlc = htlcs_info->htlcs[i];
        htlcs[i].tell_if_missing = htlcs_info->tell_if_missing[i];
        htlcs[i].tell_immediately = htlcs_info->tell_immediately[i];
    }

    /* Sort by CLTV, so matches are in CLTV order (and easy to skip dups) */
    asort(htlcs, tal_count(htlcs), cmp_htlc_with_tells_cltv, NULL);

    /* Now put them back (prev were allocated off tmpctx) */
    htlcs_info->htlcs = tal_arr(htlcs_info, struct htlc_stub, tal_count(htlcs));
    htlcs_info->tell_if_missing = tal_arr(htlcs_info, bool, tal_count(htlcs));
    htlcs_info->tell_immediately = tal_arr(htlcs_info, bool, tal_count(htlcs));
    for (size_t i = 0; i < tal_count(htlcs); i++) {
        htlcs_info->htlcs[i] = htlcs[i].htlc;
        htlcs_info->tell_if_missing[i] = htlcs[i].tell_if_missing;
        htlcs_info->tell_immediately[i] = htlcs[i].tell_immediately;
    }

	status_debug("Handling %lu HTLC scripts for possible resolution", tal_count(htlcs_info->htlcs));

    return htlcs_info;
}

/* We always assume funding input is first index in outs */
static int funding_input_num(struct tracked_output **outs, const struct tx_parts *tx)
{
    int i;
    /* Annotate the input that matches the funding outpoint as close. We can currently only have a
     * single input for these. */
    for (i=0; i<tal_count(tx->inputs); i++) {
        if (tx->inputs[i]->index == outs[0]->outpoint.n &&
            !memcmp(tx->inputs[i]->txhash, &outs[0]->outpoint.txid, 32)) {
            break;
        }
    }
    assert(i != tal_count(tx->inputs));
    return i;
}

static void eltoo_handle_mutual_close(struct tracked_output **outs,
                const struct tx_parts *tx)
{

    /* In this case, we don't care about htlcs: there are none. */
    eltoo_init_reply(tmpctx, "Tracking mutual close transaction");

    onchain_annotate_txin(&tx->txid, funding_input_num(outs, tx), TX_CHANNEL_CLOSE);

    /* BOLT #5:
     *
     * A closing transaction *resolves* the funding transaction output.
     *
     * In the case of a mutual close, a node need not do anything else, as it has
     * already agreed to the output, which is sent to its specified `scriptpubkey`
     */
    resolved_by_other(outs[0], &tx->txid, MUTUAL_CLOSE);
    wait_for_mutual_resolved(outs);
}

static void handle_unilateral(const struct tx_parts *tx,
                  u32 tx_blockheight,
                  struct tracked_output **outs,
                  u32 locktime)
{
    struct htlcs_info *htlcs_info;
    struct bitcoin_outpoint outpoint;
    struct amount_asset asset;
    struct amount_sat amt;
    struct tracked_output *out;
    const struct pubkey *funding_pubkey_ptrs[2];
    secp256k1_musig_keyagg_cache keyagg_cache;

    /* State output will match index */
    int state_index = funding_input_num(outs, tx);

    outpoint.txid = tx->txid;
    outpoint.n = state_index;

    asset = wally_tx_output_get_amount(tx->outputs[state_index]);
    amt = amount_asset_to_sat(&asset);

	/* HTLCs have to be stored until program termination */
    htlcs_info = eltoo_init_reply(outs, "Tracking update transactions");

    onchain_annotate_txin(&tx->txid, state_index, TX_CHANNEL_UNILATERAL);

    resolved_by_other(outs[0], &tx->txid, ELTOO_UPDATE);

    out = new_tracked_output(&outs,
                 &outpoint, tx_blockheight,
                 ELTOO_UPDATE,
                 amt,
                 DELAYED_OUTPUT_TO_US,
				 tx->outputs[state_index]->script,
                 locktime,
                 NULL /* htlc */, NULL /* htlc_success_tapscript */, NULL /* htlc_timeout_tapscript */);

    /* Fill out inner pubkey to complete re-binding of update transactions going forward */
    funding_pubkey_ptrs[0] = &keyset->self_funding_key;
    funding_pubkey_ptrs[1] = &keyset->other_funding_key;
    bipmusig_inner_pubkey(&keyset->inner_pubkey,
           &keyagg_cache,
           funding_pubkey_ptrs,
           /* n_pubkeys */ 2);

    /* FIXME I think this logic will be the same in main loop under output_spent  */

    /* Proposed resolution is the matching settlement tx */
    if (locktime == complete_update_tx->wtx->locktime) {
        status_debug("Handling the final complete update transaction.");
        bind_settle_tx(tx->txid, state_index, complete_settle_tx);
        propose_resolution(out, complete_settle_tx,  complete_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);
    } else if (committed_update_tx && locktime == committed_update_tx->wtx->locktime) {
        u8 *empty_hint = tal_arr(tmpctx, u8, 0); /* Make sure this doesn't sit around forever */
        status_debug("Handling the final committed update transaction.");
        bind_settle_tx(tx->txid, state_index, committed_settle_tx);
        propose_resolution(out, committed_settle_tx, committed_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);

        /* Give hint to how to rebind the committed settle tx */
        wire_sync_write(REQ_FD,
                take(towire_eltoo_onchaind_new_state_output(out, &outpoint, 0 /* invalidated_update_num */, empty_hint)));
    } else if ((committed_update_tx && locktime > committed_update_tx->wtx->locktime) ||
        (!committed_update_tx && locktime > complete_update_tx->wtx->locktime)) {
        /* If we get lucky the settle transaction will hit chain and we can get balance back */
        status_debug("Uh-oh, update from the future!");
    } else {
        /* FIXME probably should assert something here even though we checked for index already? */
        struct wally_tx_witness_stack *wit_stack = tx->inputs[state_index]->witness;
        u8 *invalidated_annex_hint = wit_stack->items[wit_stack->num_items - 1].witness;  /* Annex is last witness item! */
        struct bip340sig sig;
        u32 invalidated_update_num = locktime - 500000000;
        bipmusig_partial_sigs_combine_state(&keyset->last_complete_state, &sig);
        /* Need to propose our last complete update */
        bind_update_tx_to_update_outpoint(complete_update_tx,
                    complete_settle_tx,
                    &outpoint,
                    keyset,
                    invalidated_annex_hint,
                    invalidated_update_num,
                    &keyset->inner_pubkey,
                    &sig);
        propose_resolution(out, complete_update_tx, 0 /* depth_required */, ELTOO_UPDATE);

        /* Inform master of latest known state output to rebind to over RPC responses
         * We don't send complete/committed_tx state outputs or future ones */
        wire_sync_write(REQ_FD,
                take(towire_eltoo_onchaind_new_state_output(out, &outpoint, invalidated_update_num, invalidated_annex_hint)));

    }

    wait_for_resolved(outs, htlcs_info);

    tal_free(htlcs_info);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
    struct tx_parts *spending_tx;
    struct tracked_output **outs;
    struct bitcoin_outpoint funding;
    struct amount_sat funding_sats;
    u32 locktime, tx_blockheight;
	/* UNUSED */
    u8 *scriptpubkey[NUM_SIDES];

    keyset = tal(ctx, struct eltoo_keyset);

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

    missing_htlc_msgs = tal_arr(ctx, u8 *, 0);
    queued_msgs = tal_arr(ctx, u8 *, 0);
    /* Since eltoo is not "one shot", we have to wait to process
     * preimage notifications until settlement tx is mined or
     * we switch how we track settlement outputs prior to mining.
     */
    cached_preimages = tal_arr(ctx, struct preimage, 0);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_eltoo_onchaind_init(tmpctx,
        msg,
        &chainparams,
        &funding,
        &funding_sats,
        &spending_tx,
        &locktime,
        /* Transactions are global for ease of access */
        &complete_update_tx,
        &complete_settle_tx,
        &committed_update_tx,
        &committed_settle_tx,
        &tx_blockheight,
        &our_msat,
        &htlc_feerate,
        &dust_limit,
        &scriptpubkey[LOCAL],
        &scriptpubkey[REMOTE],
        &keyset->self_funding_key,
        &keyset->other_funding_key,
        &keyset->self_settle_key,
        &keyset->other_settle_key,
        &keyset->last_complete_state.self_psig,
        &keyset->last_complete_state.other_psig,
        &keyset->last_complete_state.session)) {
		master_badmsg(WIRE_ELTOO_ONCHAIND_INIT, msg);
	}

    update_phase = true;

    // It's not configurable for ln-penalty, just set it here?
    reasonable_depth = 3;

	status_debug("lightningd_eltoo_onchaind is alive!");
	/* We need to keep tx around, but there's only a constant number: not really a leak */
	tal_steal(ctx, notleak(spending_tx));
	tal_steal(ctx, notleak(complete_update_tx));
	tal_steal(ctx, notleak(complete_settle_tx));

    status_debug("Unbound update and settle transactions to potentially broadcast: %s, %s",
        type_to_string(tmpctx, struct bitcoin_tx, complete_update_tx),
        type_to_string(tmpctx, struct bitcoin_tx, complete_settle_tx));

    if (committed_update_tx) {
	    tal_steal(ctx, notleak(committed_update_tx));
	    tal_steal(ctx, notleak(committed_settle_tx));
        status_debug("Unbound update and settle transactions committed but incomplete: %s, %s",
            type_to_string(tmpctx, struct bitcoin_tx, committed_update_tx),
            type_to_string(tmpctx, struct bitcoin_tx, committed_settle_tx));
    }

    /* These are the utxos we are interested in */
    outs = tal_arr(ctx, struct tracked_output *, 0);

    /* Tracking funding output which is spent already */
    new_tracked_output(&outs, &funding,
               0, /* We don't care about funding blockheight */
               FUNDING_TRANSACTION,
               funding_sats,
               FUNDING_OUTPUT,
			   NULL /* scriptPubKey*/,
               locktime, NULL /* htlc */, NULL /* htlc_success_tapscript */, NULL /* htlc_timeout_tapscript */);

    /* Record funding output spent */
    send_coin_mvt(take(new_coin_channel_close(NULL, &spending_tx->txid,
                          &funding, tx_blockheight,
                          our_msat,
                          funding_sats,
                          tal_count(spending_tx->outputs))));

    /* Committed state should be one step further max */
    if (committed_update_tx) {
        assert(complete_update_tx->wtx->locktime == committed_update_tx->wtx->locktime ||
                complete_update_tx->wtx->locktime == committed_update_tx->wtx->locktime + 1);
    }

    if (is_mutual_close(locktime)) {
        status_debug("Handling mutual close!");
        eltoo_handle_mutual_close(outs, spending_tx);
    } else {
        status_debug("Handling unilateral close!");
        handle_unilateral(spending_tx, tx_blockheight, outs, locktime);
    }

 	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
