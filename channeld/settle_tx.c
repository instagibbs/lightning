#include "config.h"
#include <bitcoin/script.h>
#include <channeld/settle_tx.h>
#include <common/htlc_trim.h>
#include <common/htlc_tx.h>
#include <common/initial_settlement_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

/* These are 0-fee, require anchors, so we override useless options */
static bool trim(const struct htlc *htlc,
		 struct amount_sat dust_limit)
{
	return htlc_is_trimmed(htlc_owner(htlc), htlc->amount,
			       /* feerate_per_kw */ 0, dust_limit, /* side */ LOCAL,
			       /* option_anchor_outputs */ true);
}

size_t settle_tx_num_untrimmed(const struct htlc **htlcs,
			       struct amount_sat dust_limit)
{
	size_t i, n;

	for (i = n = 0; i < tal_count(htlcs); i++)
		n += !trim(htlcs[i], dust_limit);

	return n;
}

bool settle_tx_amount_trimmed(const struct htlc **htlcs,
			      struct amount_sat dust_limit,
			      struct amount_msat *amt)
{
	for (size_t i = 0; i < tal_count(htlcs); i++) {
		if (trim(htlcs[i], dust_limit))
			if (!amount_msat_add(amt, *amt, htlcs[i]->amount))
				return false;
	}
	return true;
}

static void add_eltoo_htlc_out(struct bitcoin_tx *tx,
				  const struct htlc *htlc,
				  const struct eltoo_keyset *eltoo_keyset,
                  enum side receiver_side)
{
	struct ripemd160 ripemd;
    u8 *htlc_scripts[2];
    u8 *taproot_script;
    struct sha256 tap_merkle_root;
    const struct pubkey *sender_pubkey, *receiver_pubkey;
    const struct pubkey *pubkey_ptrs[2];
   	struct amount_sat amount;
    secp256k1_musig_keyagg_cache keyagg_cache;
    struct pubkey taproot_pubkey;
    unsigned char tap_tweak_out[32];

    if (receiver_side == LOCAL) {
        receiver_pubkey = &(eltoo_keyset->self_settle_key);
        sender_pubkey = &(eltoo_keyset->other_settle_key);
    } else {
        receiver_pubkey = &(eltoo_keyset->other_settle_key);
        sender_pubkey = &(eltoo_keyset->self_settle_key);
    }

    pubkey_ptrs[0] = receiver_pubkey;
    pubkey_ptrs[1] = sender_pubkey;

	ripemd160(&ripemd, htlc->rhash.u.u8, sizeof(htlc->rhash.u.u8));

    htlc_scripts[0] = make_eltoo_htlc_success_script(tx, receiver_pubkey, htlc->rhash.u.u8);
    htlc_scripts[1] = make_eltoo_htlc_timeout_script(tx, sender_pubkey, htlc->expiry.locktime);
    compute_taptree_merkle_root(&tap_merkle_root, htlc_scripts, /* num_scripts */ 2);
    bipmusig_finalize_keys(&taproot_pubkey, &keyagg_cache, pubkey_ptrs, /* n_pubkeys */ 1,
           &tap_merkle_root, tap_tweak_out);
    taproot_script = scriptpubkey_p2tr(tx, &taproot_pubkey);

	amount = amount_msat_to_sat_round_down(htlc->amount);

	bitcoin_tx_add_output(tx, taproot_script, /* wscript */ NULL, amount);

	SUPERVERBOSE("# HTLC #%"PRIu64" received amount %"PRIu64" success_script %s timeout_script %s\n",
		     htlc->id,
		     amount.satoshis, /* Raw: BOLT 3 output match */
		     tal_hex(htlc_scripts[0], htlc_scripts[0]),
             tal_hex(htlc_scripts[1], htlc_scripts[1]));

	tal_free(htlc_scripts[0]);
	tal_free(htlc_scripts[1]);
}

struct bitcoin_tx *settle_tx(const tal_t *ctx,
                 const struct bitcoin_outpoint *update_outpoint,
			     struct amount_sat update_outpoint_sats,
			     u16 shared_delay,
			     const struct eltoo_keyset *eltoo_keyset,
			     struct amount_sat dust_limit,
			     struct amount_msat self_pay,
			     struct amount_msat other_pay,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     struct wally_tx_output *direct_outputs[NUM_SIDES],
			     u64 obscured_update_number)
{
	struct amount_msat total_pay;
	struct bitcoin_tx *tx;
	size_t i, n, num_untrimmed;
	u32 *cltvs;
	bool to_local, to_remote;
	struct htlc *dummy_to_local = (struct htlc *)0x01,
		*dummy_to_remote = (struct htlc *)0x02;
    secp256k1_xonly_pubkey inner_pubkey;
    const struct pubkey *pubkey_ptrs[2];
    /* For non-initial settlement tx, we cannot safely
     * predict prevout, we will rebind this last second,
     * so just put something in to satisfy PSBT et al
     */
    struct bitcoin_outpoint dummy_update_outpoint;
    memset(dummy_update_outpoint.txid.shad.sha.u.u8, 0, 32);
    dummy_update_outpoint.n = 0;

   /* For MuSig aggregation for outputs */
    pubkey_ptrs[0] = &(eltoo_keyset->self_funding_key);
    pubkey_ptrs[1] = &(eltoo_keyset->other_funding_key);

    /* Channel-wide inner public key computed here */
    bipmusig_inner_pubkey(&inner_pubkey,
           /* keyagg_cache */ NULL,
           pubkey_ptrs,
           /* n_pubkeys */ 2);


	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, update_outpoint_sats));

	/* BOLT #3:
	 *
	 * 1. Calculate which settleted HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	num_untrimmed = settle_tx_num_untrimmed(htlcs,
					    dust_limit);


	/* Worst-case sizing: both to-local and to-remote outputs, and single anchor. */
	tx = bitcoin_tx(ctx, chainparams, 1, num_untrimmed + NUM_SIDES + 1, 0);

	/* We keep track of which outputs have which HTLCs */
	*htlcmap = tal_arr(tx, const struct htlc *, tx->wtx->outputs_allocation_len);

	/* We keep cltvs for tie-breaking HTLC outputs; we use the same order
	 * for sending the htlc txs, so it may matter. */
	cltvs = tal_arr(tmpctx, u32, tx->wtx->outputs_allocation_len);

	/* This could be done in a single loop, but we follow the BOLT
	 * literally to make comments in test vectors clearer. */

	n = 0;
	/* BOLT #??:
	 *
	 * 4. For every HTLC, if it is not trimmed, add an
	 *    [HTLC output](#htlc-outputs).
	 */
	for (i = 0; i < tal_count(htlcs); i++) {
		if (trim(htlcs[i], dust_limit))
			continue;
		add_eltoo_htlc_out(tx, htlcs[i], eltoo_keyset,
				     htlc_owner(htlcs[i]));
		(*htlcmap)[n] = htlcs[i];
		cltvs[n] = abs_locktime_to_blocks(&htlcs[i]->expiry);
		n++;
	}

	/* BOLT #3:
	 *
	 * 6. If the `to_local` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_local`
	 *    output](#to_local-output).
	 */
	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
        int pos = tx_add_to_node_output(tx, eltoo_keyset, self_pay, LOCAL);
        assert(pos == n);
		/* Add a dummy entry to the htlcmap so we can recognize it later */
		(*htlcmap)[n] = direct_outputs ? dummy_to_local : NULL;
		n++;
		to_local = true;
	} else
		to_local = false;

	/* BOLT #3:
	 *
	 * 7. If the `to_remote` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_remote`
	 *    output](#to_remote-output).
	 */
	if (amount_msat_greater_eq_sat(other_pay, dust_limit)) {
        int pos = tx_add_to_node_output(tx, eltoo_keyset, other_pay, REMOTE);
		assert(pos == n);
		(*htlcmap)[n] = direct_outputs ? dummy_to_remote : NULL;
		n++;

		to_remote = true;
	} else {
		to_remote = false;
	}

    if (to_local || to_remote || num_untrimmed != 0) {
        tx_add_ephemeral_anchor_output(tx);
        (*htlcmap)[n] = NULL;
        n++;
    }

	/* BOLT #2:
	 *
	 *  - MUST set `channel_reserve_satoshis` greater than or equal to
	 *    `dust_limit_satoshis`.
	 */
	/* This means there must be at least one output. */
	assert(n > 0);

	assert(n <= tx->wtx->outputs_allocation_len);
	tal_resize(htlcmap, n);

	/* BOLT #3:
	 *
	 * 9. Sort the outputs into [BIP 69+CLTV
	 *    order](#transaction-input-and-output-ordering)
	 */
	permute_outputs(tx, cltvs, (const void **)*htlcmap);

	/* BOLT #3:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->wtx->version == 2);

	bitcoin_tx_set_locktime(tx, obscured_update_number + 500000000);

	/* BOLT #3:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 */
	/* BOLT #3:
	 *
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured settlement number
	 */
    add_settlement_input(tx, &dummy_update_outpoint, update_outpoint_sats, shared_delay, &inner_pubkey, obscured_update_number, pubkey_ptrs);

	/* Identify the direct outputs (to_us, to_them). */
	if (direct_outputs != NULL) {
		direct_outputs[LOCAL] = direct_outputs[REMOTE] = NULL;
		for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
			if ((*htlcmap)[i] == dummy_to_local) {
				(*htlcmap)[i] = NULL;
				direct_outputs[LOCAL] = tx->wtx->outputs + i;
			} else if ((*htlcmap)[i] == dummy_to_remote) {
				(*htlcmap)[i] = NULL;
				direct_outputs[REMOTE] = tx->wtx->outputs + i;
			}
		}
	}

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));

	return tx;
}
