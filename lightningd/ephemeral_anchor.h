#ifndef LIGHTNING_LIGHTNINGD_EPHEMERAL_ANCHOR_H
#define LIGHTNING_LIGHTNINGD_EPHEMERAL_ANCHOR_H
#include "config.h"
#include <bitcoin/tx.h>
#include <ccan/short_types/short_types.h>
#include <common/amount.h>

struct bitcoin_outpoint;
struct lightningd;
struct pubkey;

/**
 * create_ephemeral_anchor_cpfp - Create a CPFP transaction spending an ephemeral anchor
 * @ctx: Allocation context
 * @ld: lightningd pointer (for wallet access and HSM)
 * @parent_tx: The parent transaction containing the ephemeral anchor
 * @anchor_outpoint: The outpoint of the ephemeral anchor
 * @parent_weight: Weight of the parent transaction
 * @target_feerate: Target feerate in sat/kw for the package
 * @final_key: Pubkey for the change output
 * @final_key_idx: Key index for wallet derivation
 *
 * Creates a CPFP transaction that:
 * 1. Spends the zero-value ephemeral anchor (anyone-can-spend)
 * 2. Adds wallet UTXOs to pay fees for both parent and CPFP tx
 * 3. Outputs change to a P2TR address
 *
 * Returns signed CPFP transaction, or NULL on failure.
 */
struct bitcoin_tx *create_ephemeral_anchor_cpfp(
	const tal_t *ctx,
	struct lightningd *ld,
	const struct bitcoin_tx *parent_tx,
	const struct bitcoin_outpoint *anchor_outpoint,
	size_t parent_weight,
	u32 target_feerate,
	const struct pubkey *final_key,
	u64 final_key_idx);

#endif /* LIGHTNING_LIGHTNINGD_EPHEMERAL_ANCHOR_H */
