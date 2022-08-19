/* This is the full channel routines, with HTLC support. */
#ifndef LIGHTNING_CHANNELD_ELTOO_FULL_CHANNEL_H
#define LIGHTNING_CHANNELD_ELTOO_FULL_CHANNEL_H
#include "config.h"
#include <channeld/channeld_htlc.h>
#include <channeld/full_channel_error.h>
#include <common/initial_eltoo_channel.h>
#include <common/sphinx.h>

struct channel_id;
struct existing_htlc;

/**
 * new_full_channel: Given initial fees and funding, what is initial state?
 * @ctx: tal context to allocate return value from.
 * @cid: The channel id.
 * @funding: The commitment transaction id/output number.
 * @minimum_depth: The minimum confirmations needed for funding transaction.
 * @funding_sats: The commitment transaction amount.
 * @local_msat: The amount for the local side (remainder goes to remote)
 * @local: local channel configuration
 * @remote: remote channel configuration
 * @local_fundingkey: local funding key
 * @remote_fundingkey: remote funding key
 * @local_settle_pubkey: local settlement key
 * @remote_settle_pubkey: remote settlement key
 * @type: type for this channel
 * @option_wumbo: large channel negotiated.
 * @opener: which side initiated it.
 *
 * Returns state, or NULL if malformed.
 */
struct channel *new_full_eltoo_channel(const tal_t *ctx,
				 const struct channel_id *cid,
				 const struct bitcoin_outpoint *funding,
				 u32 minimum_depth,
				 struct amount_sat funding_sats,
				 struct amount_msat local_msat,
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
 * channel_txs: Get the current commitment and htlc txs for the channel.
 * @ctx: tal context to allocate return value from.
 * @channel: The channel to evaluate
 * @htlc_map: Pointer to htlcs for each tx output (allocated off @ctx).
 * @direct_outputs: If non-NULL, fill with pointers to the direct (non-HTLC) outputs (or NULL if none).
 * @funding_wscript: Pointer to wscript for the funding tx output
 * @per_commitment_point: Per-commitment point to determine keys
 * @commitment_number: The index of this commitment.
 * @side: which side to get the commitment transaction for
 *
 * Returns the unsigned commitment transaction for the committed state
 * for @side, followed by the htlc transactions in output order and
 * fills in @htlc_map, or NULL on key derivation failure.
 */
struct bitcoin_tx **eltoo_channel_txs(const tal_t *ctx,
                const struct htlc ***htlcmap,
                struct wally_tx_output *direct_outputs[NUM_SIDES],
                const struct channel *channel,
                u64 update_number,
                enum side side);

/**
 * eltoo_channel_add_htlc: append an HTLC to channel if it can afford it
 * @channel: The channel
 * @offerer: the side offering the HTLC (to the other side).
 * @id: unique HTLC id.
 * @amount: amount in millisatoshi.
 * @cltv_expiry: block number when HTLC can no longer be redeemed.
 * @payment_hash: hash whose preimage can redeem HTLC.
 * @routing: routing information (copied)
 * @blinding: optional blinding information for this HTLC.
 * @htlcp: optional pointer for resulting htlc: filled in if and only if CHANNEL_ERR_NONE.
 * @err_immediate_failures: in some cases (dusty htlcs) we want to immediately
 *                          fail the htlc; for peer incoming don't want to
 *                          error, but rather mark it as failed and fail after
 *                          it's been committed to (so set this to false)
 *
 * If this returns CHANNEL_ERR_NONE, the fee htlc was added and
 * the output amounts adjusted accordingly.  Otherwise nothing
 * is changed.
 */
enum channel_add_err eltoo_channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      struct amount_msat msatoshi,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
				      const struct pubkey *blinding TAKES,
				      struct htlc **htlcp,
				      bool err_immediate_failures);

/**
 * eltoo_channel_get_htlc: find an HTLC
 * @channel: The channel
 * @offerer: the side offering the HTLC.
 * @id: unique HTLC id.
 */
struct htlc *eltoo_channel_get_htlc(struct channel *channel, enum side sender, u64 id);

/**
 * channel_fail_htlc: remove an HTLC, funds to the side which offered it.
 * @channel: The channel state
 * @owner: the side who offered the HTLC (opposite to that failing it)
 * @id: unique HTLC id.
 * @htlcp: optional pointer for failed htlc: filled in if and only if CHANNEL_ERR_REMOVE_OK.
 *
 * This will remove the htlc and credit the value of the HTLC (back)
 * to its offerer.
 */
enum channel_remove_err channel_fail_htlc(struct channel *channel,
					  enum side owner, u64 id,
					  struct htlc **htlcp);

/**
 * channel_fulfill_htlc: remove an HTLC, funds to side which accepted it.
 * @channel: The channel state
 * @owner: the side who offered the HTLC (opposite to that fulfilling it)
 * @id: unique HTLC id.
 * @htlcp: optional pointer for resulting htlc: filled in if and only if CHANNEL_ERR_FULFILL_OK.
 *
 * If the htlc exists, is not already fulfilled, the preimage is correct and
 * HTLC committed at the recipient, this will add a pending change to
 * remove the htlc and give the value of the HTLC to its recipient,
 * and return CHANNEL_ERR_FULFILL_OK.  Otherwise, it will return another error.
 */
enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					     enum side owner,
					     u64 id,
					     const struct preimage *preimage,
					     struct htlc **htlcp);

/**
 * channel_sending_update: commit all remote outstanding changes.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 * This is where we commit to pending changes we've added; returns true if
 * anything changed for the remote side (if not, don't send!) */
bool channel_sending_update(struct channel *channel,
			    const struct htlc ***htlcs);

/**
 * channel_rcvd_update_sign_ack: accept ack on update.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 */
bool channel_rcvd_update_sign_ack(struct channel *channel,
				 const struct htlc ***htlcs);

/**
 * channel_rcvd_update: commit all outstanding changes.
 * @channel: the channel
 * @htlcs: initially-empty tal_arr() for htlcs which changed state.
 *
 */
bool channel_rcvd_update(struct channel *channel,
			 const struct htlc ***htlcs);

/**
 * num_channel_htlcs: how many (live) HTLCs at all in channel?
 * @channel: the channel
 */
size_t num_channel_htlcs(const struct channel *channel);

/**
 * channel_force_htlcs: force these htlcs into the (new) channel
 * @channel: the channel
 * @htlcs: the htlcs to add (tal_arr) elements stolen.
 *
 * This is used for restoring a channel state.
 */
bool channel_force_htlcs(struct channel *channel,
			 const struct existing_htlc **htlcs);

/**
 * dump_htlcs: debugging dump of all HTLCs
 * @channel: the channel
 * @prefix: the prefix to prepend to each line.
 *
 * Uses status_debug() on every HTLC.
 */
void dump_htlcs(const struct channel *channel, const char *prefix);

/**
 * pending_updates: does this side have updates pending in channel?
 * @channel: the channel
 * @side: the side who is offering or failing/fulfilling HTLC, or feechange
 * @uncommitted_ok: don't count uncommitted changes.
 */
bool pending_updates(const struct channel *channel, enum side side,
		     bool uncommitted_ok);

const char *channel_add_err_name(enum channel_add_err e);
const char *channel_remove_err_name(enum channel_remove_err e);

#endif /* LIGHTNING_CHANNELD_ELTOO_FULL_CHANNEL_H */
