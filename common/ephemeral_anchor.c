#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <common/ephemeral_anchor.h>
#include <common/psbt_keypath.h>
#include <common/utils.h>
#include <hsmd/hsmd_wiregen.h>
#include <lightningd/chaintopology.h>
#include <lightningd/hsm_control.h>
#include <lightningd/lightningd.h>
#include <wallet/wallet.h>
#include <wally_psbt.h>

/* is_ephemeral_anchor is implemented in bitcoin/script.c */

bool find_ephemeral_anchor_output(const struct bitcoin_tx *tx,
				  struct bitcoin_outpoint *outpoint)
{
	for (outpoint->n = 0; outpoint->n < tx->wtx->num_outputs; outpoint->n++) {
		const struct wally_tx_output *out = &tx->wtx->outputs[outpoint->n];
		if (is_ephemeral_anchor(out->script, out->script_len)) {
			bitcoin_txid(tx, &outpoint->txid);
			return true;
		}
	}
	return false;
}

struct amount_sat calculate_cpfp_fee(size_t parent_weight,
				     struct amount_sat parent_fee,
				     u32 target_feerate,
				     size_t cpfp_weight)
{
	struct amount_sat total_fee, cpfp_fee;
	size_t total_weight = parent_weight + cpfp_weight;

	/* Calculate total fee needed for target feerate */
	total_fee = amount_tx_fee(target_feerate, total_weight);

	/* CPFP must pay: total_fee - parent_fee */
	if (!amount_sat_sub(&cpfp_fee, total_fee, parent_fee))
		cpfp_fee = AMOUNT_SAT(0);

	return cpfp_fee;
}

struct bitcoin_tx *create_ephemeral_anchor_cpfp(
	const tal_t *ctx,
	struct lightningd *ld,
	const struct bitcoin_tx *parent_tx,
	const struct bitcoin_outpoint *anchor_outpoint,
	size_t parent_weight,
	u32 target_feerate,
	const struct pubkey *final_key,
	u64 final_key_idx)
{
	struct wally_psbt *psbt;
	struct utxo **utxos;
	const struct hsm_utxo **hsm_utxos;
	struct amount_sat cpfp_fee, change;
	size_t cpfp_weight;
	struct bitcoin_tx *cpfp_tx;
	struct ext_key final_wallet_ext_key;
	const u8 *msg;
	bool insufficient_funds;

	/* Estimate CPFP tx weight:
	 * - 1 input: ephemeral anchor (anyone-can-spend, very small witness)
	 * - 1 output: P2TR change
	 * Plus any wallet UTXOs we add for fees
	 */
	cpfp_weight = bitcoin_tx_core_weight(1, 1)
		+ bitcoin_tx_input_weight(true, 1)  /* P2A witness is tiny */
		+ change_weight();

	/* Get UTXOs to cover fees for entire package */
	utxos = wallet_utxo_boost(tmpctx,
				  ld->wallet,
				  get_block_height(ld->topology),
				  AMOUNT_SAT(0),  /* No existing fee */
				  chainparams->dust_limit,
				  target_feerate,
				  &cpfp_weight,
				  &insufficient_funds);

	if (tal_count(utxos) == 0) {
		log_unusual(ld->log,
			    "No UTXOs available for ephemeral anchor CPFP");
		return NULL;
	}

	/* Create PSBT with our UTXOs */
	psbt = psbt_using_utxos(tmpctx, ld->wallet, utxos,
				default_locktime(ld->topology),
				BITCOIN_TX_RBF_SEQUENCE, NULL);

	/* Add the ephemeral anchor input (zero-value, anyone-can-spend) */
	psbt_append_input(psbt, anchor_outpoint, BITCOIN_TX_RBF_SEQUENCE,
			  NULL, NULL, NULL);
	/* Set witness_utxo for the ephemeral anchor (0 sats, P2A scriptpubkey) */
	psbt_input_set_wit_utxo(psbt, psbt->num_inputs - 1,
				bitcoin_spk_ephemeral_anchor(tmpctx),
				AMOUNT_SAT(0));

	/* Calculate fee we need to pay */
	cpfp_fee = calculate_cpfp_fee(parent_weight, AMOUNT_SAT(0),
				      target_feerate, cpfp_weight);

	/* Calculate change = input_total - cpfp_fee */
	change = psbt_compute_fee(psbt);
	if (!amount_sat_sub(&change, change, cpfp_fee)
	    || amount_sat_less(change, chainparams->dust_limit)) {
		if (insufficient_funds) {
			log_unusual(ld->log,
				    "Insufficient funds for ephemeral anchor CPFP: "
				    "need %s, have %s",
				    fmt_amount_sat(tmpctx, cpfp_fee),
				    fmt_amount_sat(tmpctx, psbt_compute_fee(psbt)));
		} else {
			log_broken(ld->log,
				   "CPFP fee estimation error: need %s from %s",
				   fmt_amount_sat(tmpctx, cpfp_fee),
				   fmt_amount_sat(tmpctx, psbt_compute_fee(psbt)));
		}
		return NULL;
	}

	/* Add P2TR change output */
	if (bip32_key_from_parent(ld->bip86_base ? ld->bip86_base : ld->bip32_base,
				  final_key_idx,
				  BIP32_FLAG_KEY_PUBLIC,
				  &final_wallet_ext_key) != WALLY_OK) {
		log_broken(ld->log, "Could not derive final_wallet_ext_key");
		return NULL;
	}

	psbt_append_output(psbt,
			   scriptpubkey_p2tr(tmpctx, final_key),
			   change);

	log_debug(ld->log,
		  "Creating ephemeral anchor CPFP: fee %s, change %s, "
		  "parent_weight %zu, cpfp_weight %zu, feerate %u",
		  fmt_amount_sat(tmpctx, cpfp_fee),
		  fmt_amount_sat(tmpctx, change),
		  parent_weight, cpfp_weight, target_feerate);

	/* Sign the CPFP transaction via HSM
	 * The ephemeral anchor input is anyone-can-spend, so we only need
	 * to sign our wallet UTXO inputs */
	hsm_utxos = utxos_to_hsm_utxos(tmpctx, utxos);
	msg = towire_hsmd_sign_withdrawal(NULL, hsm_utxos, psbt);
	msg = hsm_sync_req(tmpctx, ld, take(msg));

	if (!fromwire_hsmd_sign_withdrawal_reply(tmpctx, msg, &psbt)) {
		log_broken(ld->log, "HSM failed to sign CPFP: %s",
			   tal_hex(tmpctx, msg));
		return NULL;
	}

	/* The ephemeral anchor input needs an empty witness (anyone-can-spend).
	 * Create an empty witness stack for the anchor input.
	 * P2A (Pay to Anchor) requires no witness data to spend. */
	{
		struct wally_psbt_input *anchor_input = &psbt->inputs[psbt->num_inputs - 1];
		struct wally_tx_witness_stack *empty_stack;

		tal_wally_start();
		if (wally_tx_witness_stack_init_alloc(0, &empty_stack) != WALLY_OK) {
			tal_wally_end(psbt);
			log_broken(ld->log, "Could not create empty witness stack");
			return NULL;
		}
		if (wally_psbt_input_set_final_witness(anchor_input, empty_stack) != WALLY_OK) {
			wally_tx_witness_stack_free(empty_stack);
			tal_wally_end(psbt);
			log_broken(ld->log, "Could not set empty witness for anchor input");
			return NULL;
		}
		wally_tx_witness_stack_free(empty_stack);
		tal_wally_end(psbt);
	}

	if (!psbt_finalize(psbt)) {
		log_broken(ld->log, "Non-final CPFP PSBT from HSM: %s",
			   fmt_wally_psbt(tmpctx, psbt));
		return NULL;
	}

	cpfp_tx = tal(ctx, struct bitcoin_tx);
	cpfp_tx->chainparams = chainparams;
	cpfp_tx->wtx = psbt_final_tx(cpfp_tx, psbt);
	if (!cpfp_tx->wtx) {
		log_broken(ld->log, "Could not extract final tx from CPFP PSBT");
		return tal_free(cpfp_tx);
	}
	cpfp_tx->psbt = tal_steal(cpfp_tx, psbt);

	return cpfp_tx;
}
