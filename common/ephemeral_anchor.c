#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <common/ephemeral_anchor.h>

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
