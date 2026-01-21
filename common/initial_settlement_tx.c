#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <common/initial_settlement_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <stdio.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

int tx_add_to_node_output(struct bitcoin_tx *tx, const struct eltoo_keyset *eltoo_keyset, struct amount_msat pay, enum side receiver)
{
    return bitcoin_tx_add_output(
        tx, scriptpubkey_p2tr(tmpctx,
            receiver == LOCAL ? &eltoo_keyset->self_settle_key : &eltoo_keyset->other_settle_key),
            /* wscript */ NULL,
            amount_msat_to_sat_round_down(pay));
}

void tx_add_ephemeral_anchor_output(struct bitcoin_tx *tx, struct amount_sat amt)
{
	u8 *spk = bitcoin_spk_ephemeral_anchor(tmpctx);
	bitcoin_tx_add_output(tx, spk, /* wscript */ NULL, amt);
}

void add_settlement_input(struct bitcoin_tx *tx, const struct bitcoin_outpoint *update_outpoint,
    struct amount_sat update_outpoint_sats, u32 shared_delay, const struct pubkey *inner_pubkey, u32 obscured_update_number, const struct pubkey *funding_pubkey_ptrs[2])
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
     * a template hash to then build the settlement script. We use a P2TR scriptpubkey from the
     * inner_pubkey here; OP_TEMPLATEHASH excludes prevouts/scriptPubKeys/amounts from
     * the hash so any valid P2TR script works as a placeholder.
     */
    dummy_script = scriptpubkey_p2tr(tmpctx, inner_pubkey);
	input_num = bitcoin_tx_add_input(tx, update_outpoint, shared_delay,
			     /* scriptSig */ NULL, update_outpoint_sats, dummy_script, /* input_wscript */ NULL, inner_pubkey, /* tap_tree */ NULL);
    assert(input_num == 0);

    /* Now the transaction itself is determined, we compute the template hash
     * of this settlement tx. The settle script uses OP_TEMPLATEHASH to verify
     * that the spending tx matches this expected template. */
    {
        struct sha256 expected_template_hash;
        compute_template_hash(tx, input_num, /* annex */ NULL, &expected_template_hash);
        settle_and_update_tapscripts[0] = make_eltoo_settle_script(tmpctx, &expected_template_hash);
    }

    /* update number is one more for the update path, which isn't being taken */
    settle_and_update_tapscripts[1] = make_eltoo_update_script(tmpctx, obscured_update_number + 1);

    assert(settle_and_update_tapscripts[0]);
    assert(settle_and_update_tapscripts[1]);

    /* We need to calculate the merkle root to figure the parity bit */
    compute_taptree_merkle_root(&update_merkle_root, settle_and_update_tapscripts, /* num_scripts */ 2);
    bipmusig_finalize_keys(&update_agg_pk,
           &update_keyagg_cache,
           funding_pubkey_ptrs,
           /* n_pubkeys */ 2,
           &update_merkle_root,
           update_tap_tweak,
		   NULL);

    parity_bit = pubkey_parity(&update_agg_pk);
    control_block = compute_control_block(tmpctx, settle_and_update_tapscripts[1], /* opreturn_hint */ NULL, inner_pubkey, parity_bit);

    /* Create scriptPubKey directly from the already-tweaked pubkey.
     * Do NOT use scriptpubkey_p2tr() as it applies another tweak!
     * P2TR scriptPubKey format: OP_1 (0x51) + push32 (0x20) + 32-byte x-coordinate */
    {
        unsigned char key_bytes[33];
        size_t out_len = sizeof(key_bytes);

        secp256k1_ec_pubkey_serialize(secp256k1_ctx, key_bytes, &out_len,
                                      &update_agg_pk.pubkey, SECP256K1_EC_COMPRESSED);

        script_pubkey = tal_arr(tmpctx, u8, 34);
        script_pubkey[0] = 0x51;  /* OP_1 (witness version 1) */
        script_pubkey[1] = 0x20;  /* push 32 bytes */
        memcpy(script_pubkey + 2, key_bytes + 1, 32);  /* x-coordinate (skip 02/03 prefix) */
    }

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
				     struct amount_sat update_outpoint_sats,
				     u32 shared_delay,
				     const struct eltoo_keyset *eltoo_keyset,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     u32 obscured_update_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES])
{
	struct bitcoin_tx *tx;
	size_t output_index, num_untrimmed;
	bool to_local, to_remote;
	struct amount_msat total_pay;
	struct amount_msat trimmed_msat = AMOUNT_MSAT(0);
	void *dummy_local = (void *)LOCAL, *dummy_remote = (void *)REMOTE;
	/* There is a direct output and possibly a shared anchor output */
	const void *output_order[NUM_SIDES + 1];
    const struct pubkey *funding_pubkey_ptrs[2];
    struct pubkey inner_pubkey;
    secp256k1_musig_keyagg_cache keyagg_cache;

    /* PSBTs insist that a utxo is "real", insert garbage so we have value later */
    struct bitcoin_outpoint fake_outpoint;
    memset(fake_outpoint.txid.shad.sha.u.u8, 0xff, sizeof(fake_outpoint.txid.shad.sha.u.u8));
    fake_outpoint.n = 0;

   /* For MuSig aggregation for outputs */
    funding_pubkey_ptrs[0] = &(eltoo_keyset->self_funding_key);
    funding_pubkey_ptrs[1] = &(eltoo_keyset->other_funding_key);

    /* Channel-wide inner public key computed here */
    bipmusig_inner_pubkey(&inner_pubkey,
           &keyagg_cache,
           funding_pubkey_ptrs,
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
	} else {
		to_local = false;
		/* Trimmed to_local goes to anchor */
		if (!amount_msat_add(&trimmed_msat, trimmed_msat, self_pay))
			abort();
	}

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
	} else {
		to_remote = false;
		/* Trimmed to_remote goes to anchor */
		if (!amount_msat_add(&trimmed_msat, trimmed_msat, other_pay))
			abort();
	}

	/* BOLT XX-eltoo-transactions:
	 * Output value: the sum of all trimmed output values, minimum 0 satoshis
	 */
    if (to_local || to_remote || num_untrimmed != 0) {
        struct amount_sat trimmed_sat = amount_msat_to_sat_round_down(trimmed_msat);
        tx_add_ephemeral_anchor_output(tx, trimmed_sat);
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
	 * ## Settlement Transaction
	 *
	 * * version: 3 (TRUC/BIP431 for anti-pinning)
	 */
	bitcoin_tx_set_version(tx, BITCOIN_TX_VERSION_TRUC);
	assert(tx->wtx->version == BITCOIN_TX_VERSION_TRUC);

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

    add_settlement_input(tx, &fake_outpoint, update_outpoint_sats, shared_delay, &inner_pubkey, obscured_update_number, funding_pubkey_ptrs);

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
