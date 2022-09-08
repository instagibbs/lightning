/* Commit tx without HTLC support; needed for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_SETTLEMENT_TX_H
#define LIGHTNING_COMMON_INITIAL_SETTLEMENT_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <common/htlc.h>
#include <common/utils.h>

struct bitcoin_outpoint;
struct eltoo_keyset;
struct wally_tx_output;


/**
 * initial_settlement_tx: create (unsigned) update tx to spend the first update tx
 * @ctx: context to allocate transaction and @htlc_map from.
 * @shared_delay: delay before this settlement transaction can be included in a block
 * @eltoo_keyset: keys for the update and settlement outputs.
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @obscured_update_number: obscured update number "o+k"
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 *
 */
struct bitcoin_tx *initial_settlement_tx(const tal_t *ctx,
				     struct amount_sat update_outpoint_sats,
				     u32 shared_delay,
				     const struct eltoo_keyset *eltoo_keyset,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     u32 obscured_update_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES]);


/* We always add a single ephemeral anchor output to settlement transactions */
void tx_add_ephemeral_anchor_output(struct bitcoin_tx *tx);

int tx_add_to_node_output(struct bitcoin_tx *tx, const struct eltoo_keyset *eltoo_keyset, struct amount_msat pay, enum side receiver);

void add_settlement_input(struct bitcoin_tx *tx, const struct bitcoin_outpoint *update_outpoint, struct amount_sat update_outpoint_sats, u32 shared_delay, const struct pubkey *inner_pubkey, u32 obscured_update_number, const struct pubkey *pubkey_ptrs[2]);

#endif /* LIGHTNING_COMMON_INITIAL_SETTLEMENT_TX_H */
