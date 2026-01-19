#ifndef LIGHTNING_COMMON_EPHEMERAL_ANCHOR_H
#define LIGHTNING_COMMON_EPHEMERAL_ANCHOR_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>

struct bitcoin_outpoint;

/* Note: is_ephemeral_anchor() is declared in bitcoin/script.h */

/**
 * find_ephemeral_anchor_output - Find ephemeral anchor output in a transaction
 * @tx: The transaction to search
 * @outpoint: Set to the anchor outpoint if found
 *
 * Returns true if found, false otherwise.
 */
bool find_ephemeral_anchor_output(const struct bitcoin_tx *tx,
				  struct bitcoin_outpoint *outpoint);

/**
 * calculate_cpfp_fee - Calculate fee needed for CPFP transaction
 * @parent_weight: Weight of the parent transaction
 * @parent_fee: Fee already paid by parent (0 for zero-fee parent)
 * @target_feerate: Target feerate in sat/kw for the package
 * @cpfp_weight: Weight of the CPFP transaction
 *
 * Returns the fee the CPFP transaction must pay to achieve target_feerate
 * for the combined package.
 */
struct amount_sat calculate_cpfp_fee(size_t parent_weight,
				     struct amount_sat parent_fee,
				     u32 target_feerate,
				     size_t cpfp_weight);

#endif /* LIGHTNING_COMMON_EPHEMERAL_ANCHOR_H */
