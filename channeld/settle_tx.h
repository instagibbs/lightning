#ifndef LIGHTNING_CHANNELD_COMMIT_TX_H
#define LIGHTNING_CHANNELD_COMMIT_TX_H
#include "config.h"
#include <channeld/channeld_htlc.h>
#include <common/initial_settlement_tx.h>

struct keyset;

/**
 * settle_tx_num_untrimmed: how many of these htlc outputs will settle tx have?
 * @htlcs: tal_arr of HTLCs
 * @dust_limit: dust limit below which to trim outputs.
 *
 */
size_t settle_tx_num_untrimmed(const struct htlc **htlcs,
			       struct amount_sat dust_limit);

/**
 * settle_tx_amount_trimmed: what's the sum of trimmed htlc amounts?
 * @htlcs: tal_arr of HTLCs
 * @dust_limit: dust limit below which to trim outputs.
 * @amt: returned, total value trimmed from this settlement
 *
 * We need @side because HTLC fees are different for offered and
 * received HTLCs.
 *
 * Returns false if unable to calculate amount trimmed.
 */
bool settle_tx_amount_trimmed(const struct htlc **htlcs,
			      struct amount_sat dust_limit,
			      struct amount_msat *amt);

static void add_eltoo_htlc_out(struct bitcoin_tx *tx,
                  const struct htlc *htlc,
                  const struct eltoo_keyset *eltoo_keyset,
                  enum side receiver_side);

/**
 * settle_tx: create (unsigned) settlement tx to spend the funding tx output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @update_outpoint, @update_outpoint_sats: funding outpoint and amount
 * @shared_delay: delay before this settlement transaction can be included in a block
 * @eltoo_keyset: keys derived for this settle tx.
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @htlcs: tal_arr of htlcs settleted by transaction (some may be trimmed)
 * @htlc_map: outputed map of outnum->HTLC (NULL for direct outputs).
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @obscured_settlement_number: number to encode in settlement transaction for update number
 *
 * This does not support liquidity ads (yet)
 */
struct bitcoin_tx *settle_tx(const tal_t *ctx,
			     const struct bitcoin_outpoint *update_outpoint,
			     struct amount_sat update_outpoint_sats,
			     u16 to_shared_delay,
			     const struct eltoo_keyset *eltoo_keyset,
			     struct amount_sat dust_limit,
			     struct amount_msat self_pay,
			     struct amount_msat other_pay,
			     const struct htlc **htlcs,
			     const struct htlc ***htlcmap,
			     struct wally_tx_output *direct_outputs[NUM_SIDES],
			     u64 obscured_update_number);

#endif /* LIGHTNING_CHANNELD_COMMIT_TX_H */
