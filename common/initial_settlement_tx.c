#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <common/initial_settlement_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

int tx_add_to_node_output(struct bitcoin_tx *tx, const struct eltoo_keyset *eltoo_keyset, struct amount_msat pay, enum side receiver)
{
    struct pubkey taproot_pk;
    secp256k1_musig_keyagg_cache keyagg_cache;
    struct sha256 tap_merkle_root;
    struct sha256 tap_tweak_out;
    u8 *tapleaf_scripts[1];
    struct pubkey const *receiver_pubkey;
    struct pubkey const *pubkey_ptrs[2];
	struct amount_sat amount;

    if (receiver == LOCAL) {
        receiver_pubkey = &eltoo_keyset->self_settle_key;
    } else {
        receiver_pubkey = &eltoo_keyset->other_settle_key;
    }

    pubkey_ptrs[0] = &eltoo_keyset->self_funding_key;
    pubkey_ptrs[1] = &eltoo_keyset->other_funding_key;

    tapleaf_scripts[0] = bitcoin_tapscript_to_node(tmpctx, receiver_pubkey);
    SUPERVERBOSE("SELF TO NODE: %s\n", tal_hexstr(tmpctx, tapleaf_scripts[0], tal_count(tapleaf_scripts[0])));
    compute_taptree_merkle_root(&tap_merkle_root, tapleaf_scripts, /* num_scripts */ 1);
    bipmusig_finalize_keys(&taproot_pk, &keyagg_cache, pubkey_ptrs, /* n_pubkeys */ 2,
       &tap_merkle_root, tap_tweak_out.u.u8);

    amount = amount_msat_to_sat_round_down(pay);
    return bitcoin_tx_add_output(
        tx, scriptpubkey_p2tr(tmpctx, &taproot_pk), /* wscript */ NULL, amount /* FIXME pass in psbt fields for tap outputs */);
}

void tx_add_ephemeral_anchor_output(struct bitcoin_tx *tx)
{
	u8 *spk = bitcoin_spk_ephemeral_anchor(tmpctx);
	bitcoin_tx_add_output(tx, spk, /* wscript */ NULL, AMOUNT_SAT(0));
}

void add_settlement_input(struct bitcoin_tx *tx, const struct bitcoin_outpoint *update_outpoint,
    struct amount_sat update_outpoint_sats, u32 shared_delay, const struct pubkey *inner_pubkey, u32 obscured_update_number, const struct pubkey *pubkey_ptrs[2])
{
    u8 *dummy_script;
    int input_num;
    u8 *settle_and_update_tapscripts[2];
    struct sha256 update_merkle_root;
    struct pubkey update_agg_pk;
    secp256k1_musig_keyagg_cache update_keyagg_cache;
    unsigned char update_tap_tweak[32];
    int parity_bit;
    u8 *control_block;
    u8 *script_pubkey;
    u8 **witness; /* settle_and_update_tapscripts[0] script and control_block */

    /* 
     * We do not know what scriptPubKey, tap_tree look like yet because we're computing
     * a sighash to then put into the input script. We pass in dummies
     * where necessary for now.
     */
    dummy_script = bitcoin_spk_ephemeral_anchor(tmpctx);
	input_num = bitcoin_tx_add_input(tx, update_outpoint, shared_delay,
			     /* scriptSig */ NULL, update_outpoint_sats, dummy_script, /* input_wscript */ NULL, inner_pubkey, /* tap_tree */ NULL);
    assert(input_num == 0);

    /* Now the the transaction itself is determined, we must compute the APO sighash to inject it
      into the inputs' tapscript, then attach the information to the PSBT */
    settle_and_update_tapscripts[0] = make_eltoo_settle_script(tmpctx, tx, input_num);

    /* update number is one more for the update path, which isn't being taken */
    settle_and_update_tapscripts[1] = make_eltoo_update_script(tmpctx, obscured_update_number + 1);

    assert(settle_and_update_tapscripts[0]);
    assert(settle_and_update_tapscripts[1]);

    /* We need to calculate the merkle root to figure the parity bit */
    compute_taptree_merkle_root(&update_merkle_root, settle_and_update_tapscripts, /* num_scripts */ 2);
    bipmusig_finalize_keys(&update_agg_pk,
           &update_keyagg_cache,
           pubkey_ptrs,
           /* n_pubkeys */ 2,
           &update_merkle_root,
           update_tap_tweak);

    parity_bit = pubkey_parity(&update_agg_pk);
    control_block = compute_control_block(tmpctx, settle_and_update_tapscripts[1], /* annex_hint */ NULL, inner_pubkey, parity_bit);
    script_pubkey = scriptpubkey_p2tr(tmpctx, &update_agg_pk);

    /* Remove and re-add with updated information */
    bitcoin_tx_remove_input(tx, input_num);
	input_num = bitcoin_tx_add_input(tx, update_outpoint, shared_delay,
			     /* scriptSig */ NULL, update_outpoint_sats, script_pubkey, /* input_wscript */ NULL, inner_pubkey, /* tap_tree */ NULL);
    assert(input_num == 0);

    /* We have the complete witness for this transaction already, just add it
     * the second-to-last stack element s, the script.
     * last stack element is called the control block
     */ 
    witness = tal_arr(tmpctx, u8 *, 2);
    witness[0] = settle_and_update_tapscripts[0];
    witness[1] = control_block;
    bitcoin_tx_input_set_witness(tx, input_num, witness);
}


struct bitcoin_tx *initial_settlement_tx(const tal_t *ctx,
				     const struct bitcoin_outpoint *update_outpoint,
				     struct amount_sat update_outpoint_sats,
				     u32 shared_delay,
				     const struct eltoo_keyset *eltoo_keyset,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     u32 obscured_update_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES],
				     char** err_reason)
{
	struct bitcoin_tx *tx;
	size_t output_index, num_untrimmed;
	bool to_local, to_remote;
	struct amount_msat total_pay;
	void *dummy_local = (void *)LOCAL, *dummy_remote = (void *)REMOTE;
	/* There is a direct output and possibly a shared anchor output */
	const void *output_order[NUM_SIDES + 1];
    const struct pubkey *pubkey_ptrs[2];
    struct pubkey inner_pubkey;

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
	 * 1. Calculate which committed HTLCs need to be trimmed (see
	 * [Trimmed Outputs](#trimmed-outputs)).
	 */
	num_untrimmed = 0;

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
        int pos = tx_add_to_node_output(tx, eltoo_keyset, self_pay, LOCAL);
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
        int pos = tx_add_to_node_output(tx, eltoo_keyset, other_pay, REMOTE);
		assert(pos == output_index);
		output_order[output_index] = dummy_remote;
		output_index++;
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
	    obscured_update_number + 500000000);

	/* BOLT #???:
	 *
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from
	 *      `funding_created` message
	 *    * `txin[0]` sequence: upper 8 bits are 0x80, lower 24 bits are upper 24 bits of the obscured commitment number
	 *    * `txin[0]` script bytes: 0
	 */

    add_settlement_input(tx, update_outpoint, update_outpoint_sats, shared_delay, &inner_pubkey, obscured_update_number, pubkey_ptrs);

    /* Transaction is now ready for broadcast! */

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
