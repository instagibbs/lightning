/* This represents a channel with no HTLCs: all that's required for openingd. */
#ifndef LIGHTNING_COMMON_INITIAL_CHANNEL_H
#define LIGHTNING_COMMON_INITIAL_CHANNEL_H
#include "config.h"

#include <bitcoin/tx.h>
#include <common/channel_config.h>
#include <common/channel_id.h>
#include <common/derive_basepoints.h>
#include <common/htlc.h>

struct signature;
struct added_htlc;
struct failed_htlc;
struct fulfilled_htlc;

/* View from each side */
struct channel_view {
	/* How much is owed to each side (includes pending changes) */
	struct amount_msat owed[NUM_SIDES];
};

struct eltoo_channel {

	/* The id for this channel */
	struct channel_id cid;

	/* Funding txid and output. */
	struct bitcoin_outpoint funding;

    /* Keys used for the lifetime of the channel */
    struct eltoo_keyset;

	/* satoshis in from commitment tx */
	struct amount_sat funding_sats;

	/* confirmations needed for locking funding */
	u32 minimum_depth;

	/* Who is paying fees. */
	enum side opener;

	/* Limits and settings on this channel. */
	struct channel_config config;

	/* Mask for obscuring the encoding of the update number. */
	u32 update_number_obscurer;

	/* All live HTLCs for this channel */
	struct htlc_map *htlcs;

	/* What it looks like to nodes. */
	struct channel_view view;

	/* Features which apply to this channel. */
	struct channel_type *type;

	/* Are we using big channels? */
	bool option_wumbo;

};

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
				    const struct channel_type *type TAKES,
				    bool option_wumbo,
				    enum side opener);

/**
 * initial_settle_channel_tx: Get the current settlement tx for the *empty* channel.
 * @ctx: tal context to allocate return value from.
 * @channel: The channel to evaluate
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * Returns the fully signed settlement transaction, or NULL
 * if the channel size was insufficient to cover reserves.
 */
struct bitcoin_tx *initial_eltoo_channel_tx(const tal_t *ctx,
				      const struct eltoo_channel *channel,
				      struct wally_tx_output *direct_outputs[NUM_SIDES],
				      char** err_reason);

/**
 * initial_update_channel_tx: Get the current update tx for the *empty* channel. Must be called
 * *after* initial_eltoo_channel_tx.
 * @ctx: tal context to allocate return value from.
 * @settle_tx: The settlement transaction to commit to
 * @channel: The channel to evaluate
 * @err_reason: When NULL is returned, this will point to a human readable reason.
 *
 * Returns the fully signed settlement transaction, or NULL
 * if the channel size was insufficient to cover reserves.
 */
struct bitcoin_tx *initial_update_channel_tx(const tal_t *ctx,
                      const struct bitcoin_tx *settle_tx,
                      const struct eltoo_channel *channel,
                      char** err_reason);

#endif /* LIGHTNING_COMMON_INITIAL_CHANNEL_H */
