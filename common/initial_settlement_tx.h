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
struct keyset;
struct wally_tx_output;

/**
 * initial_settlement_tx: create (unsigned) commitment tx to spend the first update tx
 * @ctx: context to allocate transaction and @htlc_map from.
 * @funding, @funding_sats: funding outpoint and amount
 * @funding_wscript: scriptPubkey of the funding output
 * @funding_keys: funding bitcoin keys
 * @opener: is the LOCAL or REMOTE paying the fee?
 * @keyset: keys derived for this commit tx.
 * @feerate_per_kw: feerate to use
 * @dust_limit: dust limit below which to trim outputs.
 * @self_pay: amount to pay directly to self
 * @other_pay: amount to pay directly to the other side
 * @self_reserve: reserve the other side insisted we have
 * @obscured_commitment_number: number to encode in commitment transaction
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @side: side to generate commitment transaction for.
 * @option_anchor_outputs: does option_anchor_outputs apply to this channel?
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * We need to be able to generate the remote side's tx to create signatures,
 * but the BOLT is expressed in terms of generating our local commitment
 * transaction, so we carefully use the terms "self" and "other" here.
 */
struct bitcoin_tx *initial_settlement_tx(const tal_t *ctx,
				     const struct bitcoin_outpoint *funding,
				     struct amount_sat funding_sats,
				     const struct pubkey funding_key[NUM_SIDES],
				     enum side opener,
				     u16 to_self_delay,
				     const struct keyset *keyset,
				     u32 feerate_per_kw,
				     struct amount_sat dust_limit,
				     struct amount_msat self_pay,
				     struct amount_msat other_pay,
				     struct amount_sat self_reserve,
				     u64 obscured_commitment_number,
				     struct wally_tx_output *direct_outputs[NUM_SIDES],
				     enum side side,
				     u32 csv_lock,
				     bool option_anchor_outputs,
				     char** err_reason);


/* To-other is simply: scriptpubkey_p2wpkh(tx, keyset->other_payment_key) */

/* We always add a single ephemeral anchor output to settlement transactions */
void tx_add_ephemeral_anchor_output(struct bitcoin_tx *tx);

#endif /* LIGHTNING_COMMON_INITIAL_SETTLEMENT_TX_H */
