/* This represents a channel with no HTLCs: all that's required for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_ELTOO_CHANNEL_H
#define LIGHTNING_COMMON_INITIAL_ELTOO_CHANNEL_H
#include "config.h"

#include <bitcoin/tx.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/htlc.h>
#include <common/initial_channel.h>
#include <common/keyset.h>
#include <wire/channel_type_wiregen.h>

struct signature;
struct added_htlc;
struct failed_htlc;
struct fulfilled_htlc;

/**
 * new_initial_channel: Given initial funding, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @cid: The channel's id.
 * @funding: The commitment transaction id/outnum
 * @minimum_depth: The minimum confirmations needed for funding transaction.
 * @funding_sats: The commitment transaction amount.
 * @local_msatoshi: The amount for the local side (remainder goes to remote)
 * @local: local channel configuration
 * @remote: remote channel configuration
 * @local_funding_pubkey: local funding key
 * @remote_funding_pubkey: remote funding key
 * @local_settle_pubkey: local settlement key
 * @remote_settle_key: remote settlement key
 * @self_psig: local partial signature for reestablishment only
 * @other_psig: remote partial signature for reestablishment only
 * @session: musig session for reestablishment only
 * @type: type for this channel
 * @option_wumbo: has peer currently negotiated wumbo?
 * @opener: which side initiated it.
 *
 * Returns channel, or NULL if malformed.
 */
struct channel *new_initial_eltoo_channel(const tal_t *ctx,
				    const struct channel_id *cid,
				    const struct bitcoin_outpoint *funding,
				    u32 minimum_depth,
				    struct amount_sat funding_sats,
				    struct amount_msat local_msatoshi,
				    const struct channel_config *local,
				    const struct channel_config *remote,
				    const struct pubkey *local_funding_pubkey,
				    const struct pubkey *remote_funding_pubkey,
				    const struct pubkey *local_settle_pubkey,
				    const struct pubkey *remote_settle_pubkey,
                    const struct partial_sig *self_psig,
                    const struct partial_sig *other_psig,
                    const struct musig_session *session,
				    const struct channel_type *type TAKES,
				    bool option_wumbo,
				    enum side opener);

/**
 * initial_settle_channel_tx: Get the current settlement tx for the *empty* channel.
 * @ctx: tal context to allocate return value from.
 * @channel: The channel to evaluate
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 *
 * Returns the fully signed settlement transaction, or NULL
 * if the channel size was insufficient to cover reserves.
 */
struct bitcoin_tx *initial_settle_channel_tx(const tal_t *ctx,
				      const struct channel *channel,
				      struct wally_tx_output *direct_outputs[NUM_SIDES]);

/**
 * initial_update_channel_tx: Get the current update tx for the *empty* channel. Must be called
 * *after* initial_settle_channel_tx.
 * @ctx: tal context to allocate return value from.
 * @settle_tx: The settlement transaction to commit to
 * @channel: The channel to evaluate
 *
  */
struct bitcoin_tx *initial_update_channel_tx(const tal_t *ctx,
                      const struct bitcoin_tx *settle_tx,
                      const struct channel *channel);

#endif /* LIGHTNING_COMMON_INITIAL_ELTOO_CHANNEL_H */
