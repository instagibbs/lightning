/* Commit tx without HTLC support; needed for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_UPDATE_TX_H
#define LIGHTNING_COMMON_INITIAL_UPDATE_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <common/htlc.h>
#include <common/utils.h>
#include <common/initial_settlement_tx.h>

struct bitcoin_outpoint;

int tx_add_settlement_output(struct bitcoin_tx *update_tx, const struct bitcoin_tx *settle_tx);

u8 *make_eltoo_annex(const tal_t *ctx, const struct bitcoin_tx *settle_tx);

void tx_add_funding_input(struct bitcoin_tx *update_tx,
                    const struct bitcoin_tx *settle_tx,
                    const struct bitcoin_outpoint *funding_outpoint,
                    struct amount_sat funding_outpoint_sats,
                    const struct eltoo_keyset *eltoo_keyset);

/**
 * initial_update_tx: create (unsigned) update tx to spend the funding output
 * @ctx: context to allocate transaction and @htlc_map from.
 * @settlement_tx: initial settlement tx created via `initial_settlement_tx`
 * @funding_outpoint, @funding_outpoint_sats: funding outpoint and amount
 * @eltoo_keyset: set of keys for deriving inner public key
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 */
struct bitcoin_tx *initial_update_tx(const tal_t *ctx,
                     const struct bitcoin_tx *settle_tx,
				     const struct bitcoin_outpoint *funding_outpoint,
				     struct amount_sat funding_outpoint_sats,
                     const struct eltoo_keyset *eltoo_keyset,
				     char** err_reason);

#endif /* LIGHTNING_COMMON_INITIAL_UPDATE_TX_H */
