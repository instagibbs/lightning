#ifndef LIGHTNING_COMMON_ELTOO_CLOSE_TX_H
#define LIGHTNING_COMMON_ELTOO_CLOSE_TX_H
#include "config.h"
#include <bitcoin/tx.h>
#include <common/amount.h>

struct bitcoin_outpoint;
struct chainparams;
struct pubkey;

/* ELTOO_DUST_LIMIT: Fixed dust limit for eltoo taproot outputs (330 sats) */
#define ELTOO_DUST_LIMIT AMOUNT_SAT(330)

/**
 * create_eltoo_close_tx - Create a mutual close transaction for an eltoo channel
 * @ctx: tal context for allocation
 * @chainparams: chain parameters
 * @funding: the funding outpoint to spend
 * @funding_sats: total funding amount
 * @local_funding_key: local funding pubkey (for computing funding scriptPubKey)
 * @remote_funding_key: remote funding pubkey (for computing funding scriptPubKey)
 * @local_scriptpubkey: scriptpubkey for local output
 * @remote_scriptpubkey: scriptpubkey for remote output
 * @to_local: amount going to local
 * @to_remote: amount going to remote
 *
 * Creates a close transaction that spends the funding output directly.
 * Uses version 3 (TRUC), locktime 0, and BIP69 output ordering.
 * Outputs below the dust limit (330 sats) are trimmed.
 * Returns NULL if both outputs would be below dust.
 *
 * The transaction requires a MuSig2 key-path signature using SIGHASH_ALL.
 */
struct bitcoin_tx *create_eltoo_close_tx(const tal_t *ctx,
					 const struct chainparams *chainparams,
					 const struct bitcoin_outpoint *funding,
					 struct amount_sat funding_sats,
					 const struct pubkey *local_funding_key,
					 const struct pubkey *remote_funding_key,
					 const u8 *local_scriptpubkey,
					 const u8 *remote_scriptpubkey,
					 struct amount_sat to_local,
					 struct amount_sat to_remote);

#endif /* LIGHTNING_COMMON_ELTOO_CLOSE_TX_H */
