#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <common/initial_settlement_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/type_to_string.h>


void tx_add_ephemeral_anchor_output(struct bitcoin_tx *tx)
{
	u8 *spk = bitcoin_spk_ephemeral_anchor(tmpctx);
	bitcoin_tx_add_output(tx, spk, /* wscript */ NULL, AMOUNT_SAT(0));
}

struct bitcoin_tx *initial_settlement_tx(const tal_t *ctx,
				     const struct bitcoin_outpoint *update_output,
				     struct amount_sat update_output_sats,
				     const struct pubkey funding_key[NUM_SIDES],
				     u32 shared_delay,
				     const struct eltoo_keyset *eltoo_keyset,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     struct amount_sat self_reserve,
				     u32 obscured_update_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES],
				     char** err_reason)
{
	struct bitcoin_tx *tx;
	size_t output_index, num_untrimmed;
	bool to_local, to_remote;
	struct amount_msat total_pay;
	struct amount_sat amount;
	void *dummy_local = (void *)LOCAL, *dummy_remote = (void *)REMOTE;
	/* There is a direct output and possibly a shared anchor output */
	const void *output_order[NUM_SIDES + 1];
    struct pubkey *pubkey_ptrs[2];

   /* For MuSig aggregation for outputs */
    pubkey_ptrs[0] = &funding_key[0];
    pubkey_ptrs[1] = &funding_key[1];

	if (!amount_msat_add(&total_pay, self_pay, other_pay))
		abort();
	assert(!amount_msat_greater_sat(total_pay, update_output_sats));

	/* BOLT #3:
	 *
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	num_untrimmed = 0;

	/* FIXME, should be in #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - both `to_local` and `to_remote` amounts for the initial
	 *   commitment transaction are less than or equal to
	 *   `channel_reserve_satoshis`.
	 */
	if (!amount_msat_greater_sat(self_pay, self_reserve)
	    && !amount_msat_greater_sat(other_pay, self_reserve)) {
		*err_reason = "Neither self amount nor other amount exceed reserve on "
				   "initial commitment transaction";
		status_unusual("Neither self amount %s"
			       " nor other amount %s"
			       " exceed reserve %s"
			       " on initial commitment transaction",
			       type_to_string(tmpctx, struct amount_msat,
					      &self_pay),
			       type_to_string(tmpctx, struct amount_msat,
					      &other_pay),
			       type_to_string(tmpctx, struct amount_sat,
					      &self_reserve));
		return NULL;
	}


	/* Worst-case sizing: both to-local and to-remote outputs + single anchor. */
	tx = bitcoin_tx(ctx, chainparams, 1, num_untrimmed + NUM_SIDES + 1, 0);

	/* This could be done in a single loop, but we follow the BOLT
	 * literally to make comments in test vectors clearer. */

	output_index = 0;
	/* BOLT #3:
	 *
	 * 4. For every offered HTLC, if it is not trimmed, add an
	 *    [offered HTLC output](#offered-htlc-outputs).
	 */

	/* BOLT #3:
	 *
	 * 5. For every received HTLC, if it is not trimmed, add an
	 *    [received HTLC output](#received-htlc-outputs).
	 */

	/* BOLT #3:
	 *
	 * 6. If the `to_node` amount is greater or equal to
	 *    `dust_limit_satoshis`, add a [`to_node`
	 *    output](#to_node-output).
	 */
	if (amount_msat_greater_eq_sat(self_pay, dust_limit)) {
        struct pubkey agg_pk;
        secp256k1_musig_keyagg_cache keyagg_cache;
        struct sha256 tap_merkle_root;
        struct sha256 tap_tweak_out;

        u8 *tapleaf_script = bitcoin_tapscript_to_node(ctx, eltoo_keyset.self_payment_key);
        /* FIXME compute taptree merkle root */
        bipmusig_finalize_keys(&agg_pk, &keyagg_cache, pubkey_ptrs, /* n_pubkeys */ 2,
           &tap_merkle_root, tap_tweak_out.u.u8)

		amount = amount_msat_to_sat_round_down(self_pay);
		int pos = bitcoin_tx_add_output(
		    tx, scriptpubkey_p2wsh(tx, wscript), wscript, amount);
		assert(pos == output_index);
		output_order[output_index] = dummy_local;
		output_index++;
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
		/* BOLT #???:
		 *
		 * If `option_anchors` applies to the commitment
		 * transaction, the `to_remote` output is encumbered by a one
		 * block csv lock.
		 *    <remote_pubkey> OP_CHECKSIGVERIFY 1 OP_CHECKSEQUENCEVERIFY
		 *
		 */
        struct pubkey agg_pk;
        secp256k1_musig_keyagg_cache keyagg_cache;
        struct sha256 tap_merkle_root;
        struct sha256 tap_tweak_out;

        u8 *tapleaf_script = bitcoin_tapscript_to_node(ctx, eltoo_keyset.other_payment_key);
        /* FIXME compute taptree merkle root */
        bipmusig_finalize_keys(&agg_pk, &keyagg_cache, pubkey_ptrs, /* n_pubkeys */ 2,
           &tap_merkle_root, tap_tweak_out.u.u8)

		amount = amount_msat_to_sat_round_down(self_pay);
		int pos = bitcoin_tx_add_output(
		    tx, scriptpubkey_p2wsh(tx, wscript), wscript, amount);
		assert(pos == n);
		output_order[n] = dummy_remote;
		n++;
		to_remote = true;
	} else
		to_remote = false;

	/* BOLT #???:
	 */
    if (to_local || to_remote || num_untrimmed != 0) {
        tx_add_ephemeral_anchor_output(tx);
        output_order[output_index] = NULL;
        output_index++;
    }

	assert(output_index <= tx->wtx->num_outputs);
	assert(output_index <= ARRAY_SIZE(output_order));

	/* BOLT #???:
	 *
	 * 9. Sort the outputs into [BIP 69+CLTV
	 *    order](#transaction-input-and-output-ordering)
	 */
    /* FIXME? */
	permute_outputs(tx, NULL, output_order);

	/* BOLT #???:
	 *
	 * ## Commitment Transaction
	 *
	 * * version: 2
	 */
	assert(tx->wtx->version == 2);

	/* BOLT #???:
	 *
	 * * locktime: upper 8 bits are 0x20, lower 24 bits are the
	 * lower 24 bits of the obscured commitment number
	 */
	bitcoin_tx_set_locktime(tx,
	    obscured_update_number);

	/* BOLT #???:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 *    * `txin[0]` script bytes: 0
	 */
	bitcoin_tx_add_input(tx, update_output, shared_delay,
			     /* scriptSig */ NULL, update_output_sats, /* scriptPubKey */ NULL, /* input_wscript */ /* FIXME */);

    /* Now the the transaction itself is determined, we must compute the APO sighash to inject it
      into the inputs' tapscript, then attach the information to the PSBT */

	if (direct_outputs != NULL) {
		direct_outputs[LOCAL] = direct_outputs[REMOTE] = NULL;
		for (size_t i = 0; i < tx->wtx->num_outputs; i++) {
			if (output_order[i] == dummy_local)
				direct_outputs[LOCAL] = &tx->wtx->outputs[i];
			else if (output_order[i] == dummy_remote)
				direct_outputs[REMOTE] = &tx->wtx->outputs[i];
		}
	}

	/* This doesn't reorder outputs, so we can do this after mapping outputs. */
	bitcoin_tx_finalize(tx);

	return tx;
}
