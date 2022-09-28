#ifndef LIGHTNING_COMMON_UPDATE_TX_H
#define LIGHTNING_COMMON_UPDATE_TX_H
#include "config.h"
#include <bitcoin/chainparams.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/tx.h>
#include <common/htlc.h>
#include <common/utils.h>
#include <common/initial_settlement_tx.h>

struct bitcoin_outpoint;

/* Generates the "state" output for eltoo update transaction, based on the settlement tx */
int tx_add_state_output(struct bitcoin_tx *update_tx, const struct bitcoin_tx *settle_tx);

u8 *make_eltoo_annex(const tal_t *ctx, const struct bitcoin_tx *settle_tx);

/* Appends a tx input to the update transaction, without
 * binding it to a particular outpoint or script */
void tx_add_unbound_input(struct bitcoin_tx *update_tx,
                    struct amount_sat funding_sats,
                    const struct pubkey *inner_pubkey);

/* Called just in time before broadcasting to spend expired
   update output.
 * @update_tx: the update transaction that has reached enough
 * confirmations to spend via settle path
 * @output_index: which output index is to be spent
 * @settle_tx: the settlement transaction to rebind
 **/
void bind_settle_tx(const struct bitcoin_tx *update_tx,
                    int output_index,
                    struct bitcoin_tx *settle_tx);

/* Used to bind the update transaction to the funding outpoint
 * of the eltoo contract, and also re-binds the settle transaction.
 * This is the expected (non-malicious)
 * failure mode of a channel. Also finalizes the witness data.
 * @update_tx: The transaction being re-binded
 * @settle_tx: The corresponding settlement transaction, also re-binded
 * @funding_outpoint: The outpoint to be spend on chain
 * @eltoo_keyset: Set of keys to derive inner public key
 * @psbt_inner_pubkey: Inner pubkey for the state input
 * @sig: bip340 signature to be put into witness
 */
void bind_tx_to_funding_outpoint(struct bitcoin_tx *update_tx,
                    struct bitcoin_tx *settle_tx,
                    const struct bitcoin_outpoint *funding_outpoint,
                    const struct eltoo_keyset *eltoo_keyset,
                    const struct pubkey *psbt_inner_pubkey,
                    const struct bip340sig *sig);

/* Used to bind the update transaction to the non-funding outpoints
 * of the eltoo contract. This only occurs if invalidated update
 * transactions are published, e.g. faulty watchtower, or malicious
 * counter-party.
 * @update_tx: The transaction being re-binded
 * @settle_tx: The corresponding settlement transaction, also re-binded
 * @funding_outpoint: The outpoint to be spend on chain
 * @eltoo_keyset: Set of keys to derive inner public key
 * @invalidated_annex_hint: The annex data of the update transaction
 *   which is having its outpoint spent by @update_tx
 * @invalidated_update_number: The locktime of the update transaction
 *   which is having its outpoint spent by @update_tx
 * @psbt_inner_pubkey: Inner pubkey for the state input
 * @sig: bip340 signature to put into witness
 */
void bind_update_tx_to_update_outpoint(struct bitcoin_tx *update_tx,
                    struct bitcoin_tx *settle_tx,
                    const struct bitcoin_outpoint *outpoint,
                    const struct eltoo_keyset *eltoo_keyset,
                    const u8 *invalidated_annex_hint,
                    u32 invalidated_update_number,
                    struct pubkey *psbt_inner_pubkey,
                    const struct bip340sig *sig);

/**
 * unbound_update_tx: create (unsigned) update tx to spend a yet-to-decided ouutpoint
 * FIXME return annex here too(or include as proprietary field in PSBT?)
 * @ctx: context to allocate transaction and @htlc_map from.
 * @settlement_tx: initial settlement tx created via `initial_settlement_tx`
 * @funding_sats: funding amount
 * @inner_pubkey: inner public key for the eltoo channel
 *
 */
struct bitcoin_tx *unbound_update_tx(const tal_t *ctx,
                     const struct bitcoin_tx *settle_tx,
				     struct amount_sat funding_sats,
                     const struct pubkey *inner_pubkey);


#endif /* LIGHTNING_COMMON_UPDATE_TX_H */
