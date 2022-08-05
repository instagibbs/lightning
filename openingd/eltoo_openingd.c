/*~ Welcome to the opening daemon: gateway to channels!
 *
 * This daemon handles a single peer.  It's happy to trade gossip with the
 * peer until either lightningd asks it to fund a channel, or the peer itself
 * asks to fund a channel.  Then it goes through with the channel opening
 * negotiations.  It's important to note that until this negotiation is complete,
 * there's nothing permanent about the channel: lightningd will only have to
 * commit to the database once openingd succeeds.
 */
#include "config.h"
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <ccan/breakpoint/breakpoint.h>
#include <ccan/tal/str/str.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/gossip_rcvd_filter.h>
#include <common/gossip_store.h>
#include <common/initial_eltoo_channel.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <hsmd/hsmd_eltoo_wiregen.h>
#include <openingd/common.h>
#include <openingd/eltoo_openingd_wiregen.h>
#include <wire/eltoo_wiregen.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == lightningd, 3 == peer, 4 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 4

#if DEVELOPER
/* If --dev-force-tmp-channel-id is set, it ends up here */
static struct channel_id *dev_force_tmp_channel_id;
#endif /* DEVELOPER */

/* Global state structure.  This is only for the one specific peer and channel */
struct eltoo_state {
	struct per_peer_state *pps;

	/* Features they offered */
	u8 *their_features;

	/* Constraints on a channel they open. */
	u32 minimum_depth;
	u32 min_feerate, max_feerate;
	struct amount_msat min_effective_htlc_capacity;

	/* Limits on what remote config we accept. */
	u32 max_shared_delay;

	/* These are the points lightningd told us to use when accepting or
	 * opening a channel. */
	struct pubkey our_funding_pubkey;
    struct pubkey our_settlement_pubkey;

	/* Information we need between funding_start and funding_complete */
	struct pubkey their_funding_pubkey;
    struct pubkey their_settlement_pubkey;

	/* Initially temporary, then final channel id. */
	struct channel_id channel_id;

	/* Funding and feerate: set by opening peer. */
	struct amount_sat funding_sats;
	struct amount_msat push_msat;
	/* u32 feerate_per_kw; pretty sure this is commit tx feerate? */
	struct bitcoin_outpoint funding;

	/* If non-NULL, this is the scriptpubkey we/they *must* close with */
	u8 *upfront_shutdown_script[NUM_SIDES];

	/* If non-NULL, the wallet index for the LOCAL script */
	u32 *local_upfront_shutdown_wallet_index;

	/* This is a cluster of fields in open_channel and accept_channel which
	 * indicate the restrictions each side places on the channel.
     * FIXME do we need just the one?
     */
	struct eltoo_channel_config localconf, remoteconf;

	/* The channel structure, as defined in common/initial_channel.h.  While
	 * the structure has room for HTLCs, those routines are channeld-specific
	 * as initial channels never have HTLCs. */
	struct eltoo_channel *channel;

	/* Channel type we agreed on (even before channel populated) */
	struct channel_type *channel_type;

	struct feature_set *our_features;

    /* Nonces used for the next signing operation */
    struct nonce our_next_nonce;
    struct nonce their_next_nonce;
};

/*~ If we can't agree on parameters, we fail to open the channel.
 *  Tell lightningd why. */
static void NORETURN negotiation_aborted(struct eltoo_state *state, const char *why)
{
	status_debug("aborted opening negotiation: %s", why);
	/*~ The "billboard" (exposed as "status" in the JSON listpeers RPC
	 * call) is a transient per-channel area which indicates important
	 * information about what is happening.  It has a "permanent" area for
	 * each state, which can be used to indicate what went wrong in that
	 * state (such as here), and a single transient area for current
	 * status. */
	peer_billboard(true, why);

	/* Tell master that funding failed. */
	wire_sync_write(REQ_FD, take(towire_openingd_eltoo_failed(NULL, why)));
	exit(0);
}

/*~ For negotiation failures: we tell them the parameter we didn't like. */
static void NORETURN negotiation_failed(struct eltoo_state *state,
					const char *fmt, ...)
{
	va_list ap;
	const char *errmsg;
	u8 *msg;

	va_start(ap, fmt);
	errmsg = tal_vfmt(tmpctx, fmt, ap);
	va_end(ap);

	msg = towire_errorfmt(NULL, &state->channel_id,
			      "You gave bad parameters: %s", errmsg);
	peer_write(state->pps, take(msg));

	negotiation_aborted(state, errmsg);
}

/*~ Handle random messages we might get during opening negotiation, (eg. gossip)
 * returning the first non-handled one, or NULL if we aborted negotiation. */
static u8 *opening_negotiate_msg(const tal_t *ctx, struct eltoo_state *state,
				 const struct channel_id *alternate)
{
	/* This is an event loop of its own.  That's generally considered poor
	 * form, but we use it in a very limited way. */
	for (;;) {
		u8 *msg;
		char *err;
		bool warning;
		struct channel_id actual;

		/* The event loop is responsible for freeing tmpctx, so our
		 * temporary allocations don't grow unbounded. */
		clean_tmpctx();

		/* This helper routine polls both the peer and gossipd. */
		msg = peer_read(ctx, state->pps);

		/* BOLT #1:
		 *
		 * A receiving node:
		 *   - upon receiving a message of _odd_, unknown type:
		 *     - MUST ignore the received message.
		 */
		if (is_unknown_msg_discardable(msg))
			continue;

		/* A helper which decodes an error. */
		if (is_peer_error(tmpctx, msg, &state->channel_id,
				  &err, &warning)) {
			/* BOLT #1:
			 *
			 *  - if no existing channel is referred to by `channel_id`:
			 *    - MUST ignore the message.
			 */
			/* In this case, is_peer_error returns true, but sets
			 * err to NULL */
			if (!err) {
				tal_free(msg);
				continue;
			}
			negotiation_aborted(state,
					    tal_fmt(tmpctx, "They sent %s",
						    err));
			/* Return NULL so caller knows to stop negotiating. */
			return NULL;
		}

		/*~ We do not support multiple "live" channels, though the
		 * protocol has a "channel_id" field in all non-gossip messages
		 * so it's possible.  Our one-process-one-channel mechanism
		 * keeps things simple: if we wanted to change this, we would
		 * probably be best with another daemon to de-multiplex them;
		 * this could be connectd itself, in fact. */
		if (is_wrong_channel(msg, &state->channel_id, &actual)
		    && is_wrong_channel(msg, alternate, &actual)) {
			status_debug("Rejecting %s for unknown channel_id %s",
				     peer_wire_name(fromwire_peektype(msg)),
				     type_to_string(tmpctx, struct channel_id,
						    &actual));
			peer_write(state->pps,
				   take(towire_errorfmt(NULL, &actual,
							"Multiple channels"
							" unsupported")));
			tal_free(msg);
			continue;
		}

		/* If we get here, it's an interesting message. */
		return msg;
	}
}

static bool setup_channel_funder(struct eltoo_state *state)
{

#if DEVELOPER
	/* --dev-force-tmp-channel-id specified */
	if (dev_force_tmp_channel_id)
		state->channel_id = *dev_force_tmp_channel_id;
#endif
	/* BOLT #2:
	 *
	 * The sending node:
	 *...
	 *  - if both nodes advertised `option_support_large_channel`:
	 *    - MAY set `funding_satoshis` greater than or equal to 2^24 satoshi.
	 *  - otherwise:
	 *    - MUST set `funding_satoshis` to less than 2^24 satoshi.
	 */
	if (!feature_negotiated(state->our_features,
				state->their_features, OPT_LARGE_CHANNELS)
	    && amount_sat_greater(state->funding_sats,
				  chainparams->max_funding)) {
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding_satoshis must be < %s, not %s",
			      type_to_string(tmpctx, struct amount_sat,
					     &chainparams->max_funding),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding_sats));
		return false;
	}

	return true;
}

static void set_remote_upfront_shutdown(struct eltoo_state *state,
					u8 *shutdown_scriptpubkey STEALS)
{
	bool anysegwit = feature_negotiated(state->our_features,
					    state->their_features,
					    OPT_SHUTDOWN_ANYSEGWIT);
	bool anchors = feature_negotiated(state->our_features,
					  state->their_features,
					  OPT_ANCHOR_OUTPUTS)
		|| feature_negotiated(state->our_features,
				      state->their_features,
				      OPT_ANCHORS_ZERO_FEE_HTLC_TX);

	/* BOLT #2:
	 *
	 * - MUST include `upfront_shutdown_script` with either a valid
         *   `shutdown_scriptpubkey` as required by `shutdown` `scriptpubkey`,
         *   or a zero-length `shutdown_scriptpubkey` (ie. `0x0000`).
	 */
	/* We turn empty into NULL. */
	if (tal_bytelen(shutdown_scriptpubkey) == 0)
		shutdown_scriptpubkey = tal_free(shutdown_scriptpubkey);

	state->upfront_shutdown_script[REMOTE]
		= tal_steal(state, shutdown_scriptpubkey);

	if (shutdown_scriptpubkey
	    && !valid_shutdown_scriptpubkey(shutdown_scriptpubkey, anysegwit, anchors))
		peer_failed_err(state->pps,
				&state->channel_id,
				"Unacceptable upfront_shutdown_script %s",
				tal_hex(tmpctx, shutdown_scriptpubkey));
}

/* We start the 'open a channel' negotation with the supplied peer, but
 * stop when we get to the part where we need the funding txid */
static u8 *funder_channel_start(struct eltoo_state *state, u8 channel_flags)
{
	u8 *msg;
	u8 *funding_output_script;
	struct channel_id id_in;
	struct tlv_open_channel_eltoo_tlvs *open_tlvs;
	struct tlv_accept_channel_eltoo_tlvs *accept_tlvs;
    char *err_reason;

	status_debug("funder_channel_start");
	if (!setup_channel_funder(state))
		return NULL;

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state,
						     state->our_features,
						     state->their_features);

	state->channel_type = default_channel_type(state,
						   state->our_features,
						   state->their_features);

	open_tlvs = tlv_open_channel_eltoo_tlvs_new(tmpctx);
	open_tlvs->upfront_shutdown_script
		= state->upfront_shutdown_script[LOCAL];

	/* BOLT #2:
	 *  - if it includes `channel_type`:
	 *     - MUST set it to a defined type representing the type it wants.
	 *     - MUST use the smallest bitmap possible to represent the channel
	 *       type.
	 *     - SHOULD NOT set it to a type containing a feature which was not
	 *       negotiated.
	 */
	open_tlvs->channel_type = state->channel_type->features;

    /* Fetch MuSig nonce */
    msg = towire_hsmd_get_nonce(NULL, &state->channel_id);
	peer_write(state->pps, take(msg));

	msg = wire_sync_read(tmpctx, HSM_FD);
    if (!fromwire_hsmd_get_nonce_reply(msg, &state->our_next_nonce)) {
		peer_failed_err(state->pps,
				&state->channel_id,
				"Failed to get nonce for channel: %s", tal_hex(msg, msg));
    }

	msg = towire_open_channel_eltoo(NULL,
				  &chainparams->genesis_blockhash,
				  &state->channel_id,
				  state->funding_sats,
				  state->push_msat,
				  state->localconf.dust_limit,
				  state->localconf.max_htlc_value_in_flight,
				  state->localconf.htlc_minimum,
				  state->localconf.shared_delay,
				  state->localconf.max_accepted_htlcs,
				  &state->our_funding_pubkey,
				  &state->our_settlement_pubkey,
				  channel_flags,
                  &state->our_next_nonce,
				  open_tlvs);
	peer_write(state->pps, take(msg));

	/* This is usually a very transient state... */
	peer_billboard(false,
		       "Funding channel start: offered, now waiting for accept_channel");

	/* ... since their reply should be immediate. */
	msg = opening_negotiate_msg(tmpctx, state, NULL);
	if (!msg)
		return NULL;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not
	 *    valid secp256k1 pubkeys in compressed format.
	 */
	if (!fromwire_accept_channel_eltoo(tmpctx, msg, &id_in,
				     &state->remoteconf.dust_limit,
				     &state->remoteconf.max_htlc_value_in_flight,
				     &state->remoteconf.htlc_minimum,
				     &state->minimum_depth,
				     &state->remoteconf.shared_delay,
				     &state->remoteconf.max_accepted_htlcs,
				     &state->their_funding_pubkey,
				     &state->their_settlement_pubkey,
                     &state->their_next_nonce,
				     &accept_tlvs)) {
		peer_failed_err(state->pps,
				&state->channel_id,
				"Parsing accept_channel %s", tal_hex(msg, msg));
	}
	set_remote_upfront_shutdown(state, accept_tlvs->upfront_shutdown_script);

	/* BOLT #2:
	 * - if `channel_type` is set, and `channel_type` was set in
	 *   `open_channel`, and they are not equal types:
	 *    - MUST reject the channel.
	 */
	if (accept_tlvs->channel_type
	    && !featurebits_eq(accept_tlvs->channel_type,
			       state->channel_type->features)) {
		negotiation_failed(state,
				   "Return unoffered channel_type: %s",
				   fmt_featurebits(tmpctx,
						   accept_tlvs->channel_type));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message. */
	if (!channel_id_eq(&id_in, &state->channel_id))
		/* In this case we exit, since we don't know what's going on. */
		peer_failed_err(state->pps, &id_in,
				"accept_channel ids don't match: sent %s got %s",
				type_to_string(msg, struct channel_id, &id_in),
				type_to_string(msg, struct channel_id,
					       &state->channel_id));

	if (!check_eltoo_config_bounds(tmpctx, state->funding_sats,
				 state->max_shared_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return NULL;
	}

	funding_output_script = scriptpubkey_eltoo_funding(tmpctx,
                               &state->our_funding_pubkey,
						       &state->their_funding_pubkey);

	/* Update the billboard with our infos */
	peer_billboard(false,
		       "Funding channel start: awaiting funding_txid with output to %s",
		       tal_hex(tmpctx, funding_output_script));

	return towire_openingd_eltoo_funder_start_reply(state,
						  funding_output_script,
						  feature_negotiated(
							  state->our_features,
							  state->their_features,
							  OPT_UPFRONT_SHUTDOWN_SCRIPT),
						  state->channel_type);
}

static bool funder_finalize_channel_setup(struct eltoo_state *state,
					  struct amount_msat local_msat,
					  struct bip340sig *sig,
					  struct bitcoin_tx **update_tx)
{
	u8 *msg;
	struct channel_id id_in;
	struct channel_id cid;
	char *err_reason;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
    struct bitcoin_tx *settle_tx;
    struct partial_sig our_update_psig, their_update_psig;

	/*~ Channel is ready; Report the channel parameters to the signer. */
	msg = towire_hsmd_ready_eltoo_channel(NULL,
				       /* is_outbound */ true,
				       state->funding_sats,
				       state->push_msat,
				       &state->funding.txid,
				       state->funding.n,
				       state->localconf.shared_delay,
				       state->upfront_shutdown_script[LOCAL],
				       state->local_upfront_shutdown_wallet_index,
				       &state->their_funding_pubkey,
				       &state->their_settlement_pubkey,
				       state->upfront_shutdown_script[REMOTE],
				       state->channel_type);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_ready_eltoo_channel_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO, "Bad ready_channel_reply %s",
			      tal_hex(tmpctx, msg));

	/*~ Now we can initialize the `struct channel`.  This represents
	 * the current channel state and is how we can generate the current
	 * commitment transaction.
	 *
	 * The routines to support `struct channel` are split into a common
	 * part (common/initial_channel) which doesn't support HTLCs and is
	 * enough for us here, and the complete channel support required by
	 * `channeld` which lives in channeld/full_channel. */
	derive_channel_id(&cid, &state->funding);

	state->channel = new_initial_eltoo_channel(state,
					     &cid,
					     &state->funding,
					     state->minimum_depth,
					     state->funding_sats,
					     local_msat,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_funding_pubkey,
					     &state->their_funding_pubkey,
					     &state->our_settlement_pubkey,
					     &state->their_settlement_pubkey,
					     state->channel_type,
					     feature_offered(state->their_features,
							     OPT_LARGE_CHANNELS),
					     /* Opener is local */
					     LOCAL);
	/* We were supposed to do enough checks above, but just in case,
	 * new_initial_channel will fail to create absurd channels */
	if (!state->channel)
		peer_failed_err(state->pps,
				&state->channel_id,
				"could not create channel with given config");

	/* BOLT #2:
	 *
	 * ### The `funding_created` Message
	 *
	 * This message describes the outpoint which the funder has created
	 * for the initial commitment transactions.  After receiving the
	 * peer's signature, via `funding_signed`, it will broadcast the funding
	 * transaction.
	 */
	settle_tx = initial_settle_channel_tx(tmpctx, state->channel,
                    direct_outputs, &err_reason);
	if (!settle_tx) {
		negotiation_failed(state,
				   "Could not make settle tx: %s", err_reason);
		return false;
	}

    *update_tx = initial_update_channel_tx(tmpctx, settle_tx, state->channel, &err_reason);

	if (!*update_tx) {
		negotiation_failed(state,
				   "Could not make update tx: %s", err_reason);
		return false;
	}

	/* We ask the HSM to sign the update transaction for us: it knows
	 * our funding key, it just needs the remote funding key to create the
	 * tapscripts. */
	struct simple_htlc **htlcs = tal_arr(tmpctx, struct simple_htlc *, 0);
	msg = towire_hsmd_psign_update_tx(NULL,
                           &state->channel_id,
						   *update_tx,
                           settle_tx,
						   &state->channel->eltoo_keyset.other_funding_key,
						    (const struct simple_htlc **) htlcs);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_psign_update_tx_reply(msg, &our_update_psig, &state->our_next_nonce))
		status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
			      tal_hex(tmpctx, msg));

	/* You can tell this has been a problem before, since there's a debug
	 * message here: */
    /* FIXME stringify partial sigs
	status_debug("signature %s on tx %s using key %s",
		     type_to_string(tmpctx, struct partial_sig, sig),
		     type_to_string(tmpctx, struct bitcoin_tx, *update_tx),
		     type_to_string(tmpctx, struct pubkey,
				    &state->our_funding_pubkey));
    */

	/* Now we give our peer the partial signature for the first update
	 * transaction. */
	msg = towire_funding_created_eltoo(state, &state->channel_id,
				     &state->funding.txid,
				     state->funding.n,
				     &our_update_psig,
                     &state->our_next_nonce);
	peer_write(state->pps, msg);

	/* BOLT #2:
	 *
	 * ### The `funding_signed_eltoo` Message
	 *
	 * This message gives the funder the partial signature it needs for the first
	 * update transaction, so it can broadcast the transaction knowing
	 * that funds can be redeemed, if need be.
	 */
	peer_billboard(false,
		       "Funding channel: create first tx, now waiting for their signature");

	/* Now they send us their signature for that first commitment
	 * transaction.  Note that errors may refer to the temporary channel
	 * id (state->channel_id), but success should refer to the new
	 * "cid" */
	msg = opening_negotiate_msg(tmpctx, state, &cid);
	if (!msg)
		return false;

	// FIXME ? sig->sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_signed_eltoo(msg, &id_in, &their_update_psig, &state->their_next_nonce))
		peer_failed_err(state->pps, &state->channel_id,
				"Parsing funding_signed_eltoo: %s", tal_hex(msg, msg));
	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the channel.
	 * It's derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index`, using big-endian
	 * exclusive-OR (i.e. `funding_output_index` alters the last 2
	 * bytes).
	 */

	/*~ Back in Milan, we chose to allow multiple channels between peers in
	 * the protocol.  I insisted that we multiplex these over the same
	 * socket, and (even though I didn't plan on implementing it anytime
	 * soon) that we put it into the first version of the protocol
	 * because it would be painful to add in later.
	 *
	 * My logic seemed sound: we treat new connections as an implication
	 * that the old connection has disconnected, which happens more often
	 * than you'd hope on modern networks.  However, supporting multiple
	 * channels via multiple connections would be far easier for us to
	 * support with our (introduced-since) separate daemon model.
	 *
	 * Let this be a lesson: beware premature specification, even if you
	 * suspect "we'll need it later!". */
	state->channel_id = cid;

	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed_err(state->pps, &id_in,
				"funding_signed ids don't match: expected %s got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &id_in));

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect OR non-compliant with LOW-S-standard rule...:
	 *     - MUST fail the channel
	 */
	/* So we create the initial update transaction, and check the
	 * signature they sent against that. */

    /* VLS type checks can go here... */
	// validate_initial_update_signature(HSM_FD, *update_tx, &their_update_psig, &our_update_psig);

    /* Combine psigs and validate here */

    /* FIXME check psig
	if (!check_tx_sig(*tx, 0, NULL, wscript, &state->their_funding_pubkey, sig)) {
		peer_failed_err(state->pps, &state->channel_id,
				"Bad signature %s on tx %s using key %s (channel_type=%s)",
				type_to_string(tmpctx, struct bitcoin_signature,
					       sig),
				type_to_string(tmpctx, struct bitcoin_tx, *tx),
				type_to_string(tmpctx, struct pubkey,
					       &state->their_funding_pubkey),
				fmt_featurebits(tmpctx,
						state->channel->type->features));
	}*/

	/* We save their sig to our first commitment tx */
    /* FIXME as a partial sig... how is this stored?
	if (!psbt_input_set_signature((*update_tx)->psbt, 0,
				      &state->their_funding_pubkey,
				      sig))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Unable to set signature internally");
    */
	peer_billboard(false, "Funding channel: opening negotiation succeeded");

	return true;
}

static u8 *funder_channel_complete(struct eltoo_state *state)
{
	/* Remote commitment tx */
	struct bitcoin_tx *tx;
	struct bip340sig sig;
	struct amount_msat local_msat;

	/* Update the billboard about what we're doing*/
	peer_billboard(false,
		       "Funding channel con't: continuing with funding_txid %s",
		       type_to_string(tmpctx, struct bitcoin_txid, &state->funding.txid));

	/* We recalculate the local_msat from cached values; should
	 * succeed because we checked it earlier */
	if (!amount_sat_sub_msat(&local_msat, state->funding_sats, state->push_msat))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "push_msat %s > funding %s?",
			      type_to_string(tmpctx, struct amount_msat,
					     &state->push_msat),
			      type_to_string(tmpctx, struct amount_sat,
					     &state->funding_sats));

	if (!funder_finalize_channel_setup(state, local_msat, &sig, &tx))
		return NULL;

	return towire_openingd_eltoo_funder_reply(state,
					   &state->remoteconf,
					   tx,
					   &sig,
					   state->minimum_depth,
					   &state->their_funding_pubkey,
					   &state->their_settlement_pubkey,
					   &state->funding,
					   state->upfront_shutdown_script[REMOTE],
					   state->channel_type);
}

/*~ The peer sent us an `open_channel`, that means we're the fundee. */
static u8 *fundee_channel(struct eltoo_state *state, const u8 *open_channel_msg)
{
	struct channel_id id_in;
    /* FIXME Can't these just be read into eltoo_keyset? */
	struct pubkey their_funding_pubkey;
    struct pubkey their_settlement_pubkey;
	struct bip340sig theirsig;
	struct bitcoin_tx *settle_tx, *update_tx;
	struct bitcoin_blkid chain_hash;
	u8 *msg;
	u8 channel_flags;
	u16 funding_txout;
	char* err_reason;
	struct tlv_accept_channel_eltoo_tlvs *accept_tlvs;
	struct tlv_open_channel_eltoo_tlvs *open_tlvs;
	struct wally_tx_output *direct_outputs[NUM_SIDES];
    struct partial_sig our_update_psig, their_update_psig;

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 *  - `funding_pubkey`, `revocation_basepoint`, `htlc_basepoint`,
	 *    `payment_basepoint`, or `delayed_payment_basepoint` are not valid
	 *     secp256k1 pubkeys in compressed format.
	 */
	if (!fromwire_open_channel_eltoo(tmpctx, open_channel_msg, &chain_hash,
			    &state->channel_id,
			    &state->funding_sats,
			    &state->push_msat,
			    &state->remoteconf.dust_limit,
			    &state->remoteconf.max_htlc_value_in_flight,
			    &state->remoteconf.htlc_minimum,
			    &state->remoteconf.shared_delay,
			    &state->remoteconf.max_accepted_htlcs,
			    &their_funding_pubkey,
			    &their_settlement_pubkey,
			    &channel_flags,
                &state->their_next_nonce,
			    &open_tlvs))
		    peer_failed_err(state->pps,
				    &state->channel_id,
				    "Parsing open_channel %s", tal_hex(tmpctx, open_channel_msg));
	set_remote_upfront_shutdown(state, open_tlvs->upfront_shutdown_script);

	/* BOLT #2:
	 * The receiving node MUST fail the channel if:
	 *...
	 *   - It supports `channel_type`, `channel_type` was set, and the
	 *     `type` is not suitable.
	 */
	if (open_tlvs->channel_type) {
		state->channel_type =
			channel_type_accept(state,
					    open_tlvs->channel_type,
					    state->our_features,
					    state->their_features);
		if (!state->channel_type) {
			negotiation_failed(state,
					   "Did not support channel_type %s",
					   fmt_featurebits(tmpctx,
							   open_tlvs->channel_type));
			return NULL;
		}
	} else
		state->channel_type
			= default_channel_type(state,
					       state->our_features,
					       state->their_features);

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *  - the `chain_hash` value is set to a hash of a chain
	 *  that is unknown to the receiver.
	 */
	if (!bitcoin_blkid_eq(&chain_hash, &chainparams->genesis_blockhash)) {
		negotiation_failed(state,
				   "Unknown chain-hash %s",
				   type_to_string(tmpctx,
						  struct bitcoin_blkid,
						  &chain_hash));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 *...
	 * - `funding_satoshis` is greater than or equal to 2^24 and the receiver does not support
	 *   `option_support_large_channel`. */
	/* We choose to require *negotiation*, not just support! */
	if (!feature_negotiated(state->our_features, state->their_features,
				OPT_LARGE_CHANNELS)
	    && amount_sat_greater(state->funding_sats, chainparams->max_funding)) {
		negotiation_failed(state,
				   "funding_satoshis %s too large",
				   type_to_string(tmpctx, struct amount_sat,
						  &state->funding_sats));
		return NULL;
	}

	/* BOLT #2:
	 *
	 * The receiving node MUST fail the channel if:
	 * ...
	 *   - `push_msat` is greater than `funding_satoshis` * 1000.
	 */
	if (amount_msat_greater_sat(state->push_msat, state->funding_sats)) {
		peer_failed_err(state->pps, &state->channel_id,
				"Their push_msat %s"
				" would be too large for funding_satoshis %s",
				type_to_string(tmpctx, struct amount_msat,
					       &state->push_msat),
				type_to_string(tmpctx, struct amount_sat,
					       &state->funding_sats));
		return NULL;
	}

	/* These checks are the same whether we're opener or accepter... */
	if (!check_eltoo_config_bounds(tmpctx, state->funding_sats,
				 state->max_shared_delay,
				 state->min_effective_htlc_capacity,
				 &state->remoteconf,
				 &state->localconf,
				 &err_reason)) {
		negotiation_failed(state, "%s", err_reason);
		return NULL;
	}

	/* If they give us a reason to reject, do so. */
	if (err_reason) {
		negotiation_failed(state, "%s", err_reason);
		tal_free(err_reason);
		return NULL;
	}

	if (!state->upfront_shutdown_script[LOCAL])
		state->upfront_shutdown_script[LOCAL]
			= no_upfront_shutdown_script(state,
						     state->our_features,
						     state->their_features);

	/* OK, we accept! */
	accept_tlvs = tlv_accept_channel_eltoo_tlvs_new(tmpctx);
	accept_tlvs->upfront_shutdown_script
		= state->upfront_shutdown_script[LOCAL];
	/* BOLT #2:
	 * - if it sets `channel_type`:
	 *    - MUST set it to the `channel_type` from `open_channel`
	 */
	accept_tlvs->channel_type = state->channel_type->features;

    /* FIXME Fetch our first public nonce */

    /* FIXME we can't actually know channel_id ??? */
	msg = towire_accept_channel_eltoo(NULL, &state->channel_id,
				    state->localconf.dust_limit,
				    state->localconf.max_htlc_value_in_flight,
				    state->localconf.htlc_minimum,
				    state->minimum_depth,
				    state->localconf.shared_delay,
				    state->localconf.max_accepted_htlcs,
				    &state->our_funding_pubkey,
				    &state->our_settlement_pubkey,
                    &state->our_next_nonce,
				    accept_tlvs);
	peer_write(state->pps, take(msg));

	peer_billboard(false,
		       "Incoming channel: accepted, now waiting for them to create funding tx");

	/* This is a loop which handles gossip until we get a non-gossip msg */
	msg = opening_negotiate_msg(tmpctx, state, NULL);
	if (!msg)
		return NULL;

	/* The message should be "funding_created" which tells us what funding
	 * tx they generated; the sighash type is implied, so we set it here. */
	// FIXME ? theirsig.sighash_type = SIGHASH_ALL;
	if (!fromwire_funding_created_eltoo(msg, &id_in,
				      &state->funding.txid,
				      &funding_txout,
				      &their_update_psig,
                      &state->their_next_nonce))
		peer_failed_err(state->pps, &state->channel_id,
			    "Parsing funding_created");
	/* We only allow 16 bits for this on the wire. */
	state->funding.n = funding_txout;

	/* BOLT #2:
	 *
	 * The `temporary_channel_id` MUST be the same as the
	 * `temporary_channel_id` in the `open_channel` message.
	 */
	if (!channel_id_eq(&id_in, &state->channel_id))
		peer_failed_err(state->pps, &id_in,
				"funding_created ids don't match: sent %s got %s",
				type_to_string(msg, struct channel_id,
					       &state->channel_id),
				type_to_string(msg, struct channel_id, &id_in));

	/*~ Channel is ready; Report the channel parameters to the signer. */
	msg = towire_hsmd_ready_eltoo_channel(NULL,
				       /* is_outbound */ false,
				       state->funding_sats,
				       state->push_msat,
				       &state->funding.txid,
				       state->funding.n,
				       state->localconf.shared_delay,
				       state->upfront_shutdown_script[LOCAL],
				       state->local_upfront_shutdown_wallet_index,
				       &their_funding_pubkey,
                       &their_settlement_pubkey,
				       state->upfront_shutdown_script[REMOTE],
				       state->channel_type);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_ready_eltoo_channel_reply(msg))
		status_failed(STATUS_FAIL_HSM_IO, "Bad ready_channel_reply %s",
			      tal_hex(tmpctx, msg));

	/* Now we can create the channel structure. */
	state->channel = new_initial_eltoo_channel(state,
					     &state->channel_id,
					     &state->funding,
					     state->minimum_depth,
					     state->funding_sats,
					     state->push_msat,
					     &state->localconf,
					     &state->remoteconf,
					     &state->our_funding_pubkey,
					     &their_funding_pubkey,
					     &state->our_settlement_pubkey,
					     &their_settlement_pubkey,
					     state->channel_type,
					     feature_offered(state->their_features,
							     OPT_LARGE_CHANNELS),
					     REMOTE);
	/* We don't expect this to fail, but it does do some additional
	 * internal sanity checks. */
	if (!state->channel)
		peer_failed_err(state->pps, &state->channel_id,
				"We could not create channel with given config");

	/* BOLT #2:
	 *
	 * The recipient:
	 *   - if `signature` is incorrect OR non-compliant with LOW-S-standard
	 *     rule...:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	settle_tx = initial_settle_channel_tx(tmpctx, state->channel,
                    direct_outputs, &err_reason);
	/* This shouldn't happen either, AFAICT. */
	if (!settle_tx) {
		negotiation_failed(state,
				   "Failed to make settle tx: %s", err_reason);
		return NULL;
	}

    update_tx = initial_update_channel_tx(tmpctx, settle_tx, state->channel, &err_reason);
	/* Nor this */
	if (!update_tx) {
		negotiation_failed(state,
				   "Failed to make update tx: %s", err_reason);
		return NULL;
	}

    /* FIXME Sign and bind update tx */

	validate_initial_update_signature(HSM_FD, update_tx, &their_update_psig);
    /* FIXME check psig?
	if (!check_tx_sig(update_tx, 0, NULL, wscript, &their_funding_pubkey,
			  &theirsig)) {
		peer_failed_err(state->pps, &state->channel_id,
				"Bad signature %s on tx %s using key %s",
				type_to_string(tmpctx, struct bitcoin_signature,
					       &theirsig),
				type_to_string(tmpctx, struct bitcoin_tx, update_tx),
				type_to_string(tmpctx, struct pubkey,
					       &their_funding_pubkey));
	}
    */
	/* BOLT #2:
	 *
	 * This message introduces the `channel_id` to identify the
	 * channel. It's derived from the funding transaction by combining the
	 * `funding_txid` and the `funding_output_index`, using big-endian
	 * exclusive-OR (i.e. `funding_output_index` alters the last 2 bytes).
	 */
	derive_channel_id(&state->channel_id, &state->funding);

	/*~ We generate the `funding_signed` message here, since we have all
	 * the data and it's only applicable in the fundee case.
	 *
	 * FIXME: Perhaps we should have channeld generate this, so we
	 * can't possibly send before channel committed to disk?
	 */

	/* BOLT #2:
	 *
	 * ### The `funding_signed` Message
	 *
	 * This message gives the funder the signature it needs for the first
	 * commitment transaction, so it can broadcast the transaction knowing
	 * that funds can be redeemed, if need be.
	 */

	/* Make HSM sign it */
	struct simple_htlc **htlcs = tal_arr(tmpctx, struct simple_htlc *, 0);
	msg = towire_hsmd_psign_update_tx(NULL,
                           &state->channel_id,
						   update_tx,
                           settle_tx,
						   &state->channel->eltoo_keyset.other_funding_key,
						   (const struct simple_htlc **) htlcs);
	wire_sync_write(HSM_FD, take(msg));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_psign_update_tx_reply(msg, &our_update_psig, &state->our_next_nonce))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad sign_tx_reply %s", tal_hex(tmpctx, msg));

	/* We don't send this ourselves: channeld does, because master needs
	 * to save state to disk before doing so. */
	// FIXME ? assert(sig.sighash_type == SIGHASH_ALL);
	msg = towire_funding_signed_eltoo(state, &state->channel_id, &our_update_psig, &state->our_next_nonce);

	return towire_openingd_eltoo_fundee(state,
				     &state->remoteconf,
				     update_tx,
				     &theirsig,
				     &their_funding_pubkey,
				     &state->funding,
				     state->funding_sats,
				     state->push_msat,
				     channel_flags,
				     msg,
				     state->upfront_shutdown_script[LOCAL],
				     state->upfront_shutdown_script[REMOTE],
				     state->channel_type);
}

/*~ Standard "peer sent a message, handle it" demuxer.  Though it really only
 * handles one message, we use the standard form as principle of least
 * surprise. */
static u8 *handle_peer_in(struct eltoo_state *state)
{
	u8 *msg = peer_read(tmpctx, state->pps);
	enum peer_wire t = fromwire_peektype(msg);
	struct channel_id channel_id;
	bool extracted;

	if (t == WIRE_OPEN_CHANNEL)
		return fundee_channel(state, msg);

	/* Handles error cases. */
	if (handle_peer_error(state->pps, &state->channel_id, msg))
		return NULL;

	extracted = extract_channel_id(msg, &channel_id);

	peer_write(state->pps,
			  take(towire_warningfmt(NULL,
						 extracted ? &channel_id : NULL,
						 "Unexpected message %s: %s",
						 peer_wire_name(t),
						 tal_hex(tmpctx, msg))));

	/* FIXME: We don't actually want master to try to send an
	 * error, since peer is transient.  This is a hack.
	 */
	status_broken("Unexpected message %s", peer_wire_name(t));
	peer_failed_connection_lost();
}

/* Memory leak detection is DEVELOPER-only because we go to great lengths to
 * record the backtrace when allocations occur: without that, the leak
 * detection tends to be useless for diagnosing where the leak came from, but
 * it has significant overhead. */
#if DEVELOPER
static void handle_dev_memleak(struct eltoo_state *state, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	/* Populate a hash table with all our allocations (except msg, which
	 * is in use right now). */
	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete state and things it has pointers to. */
	memleak_remove_region(memtable, state, sizeof(*state));

	/* If there's anything left, dump it to logs, and return true. */
	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(REQ_FD,
			take(towire_openingd_eltoo_dev_memleak_reply(NULL,
							      found_leak)));
}
#endif /* DEVELOPER */

/* Standard lightningd-fd-is-ready-to-read demux code.  Again, we could hang
 * here, but if we can't trust our parent, who can we trust? */
static u8 *handle_master_in(struct eltoo_state *state)
{
	u8 *msg = wire_sync_read(tmpctx, REQ_FD);
	enum eltoo_openingd_wire t = fromwire_peektype(msg);
	u8 channel_flags;
	struct bitcoin_txid funding_txid;
	u16 funding_txout;

	switch (t) {
	case WIRE_OPENINGD_ELTOO_FUNDER_START:
		if (!fromwire_openingd_eltoo_funder_start(state, msg,
						    &state->funding_sats,
						    &state->push_msat,
						    &state->upfront_shutdown_script[LOCAL],
						    &state->local_upfront_shutdown_wallet_index,
						    &state->channel_id,
						    &channel_flags))
			master_badmsg(WIRE_OPENINGD_ELTOO_FUNDER_START, msg);
		msg = funder_channel_start(state, channel_flags);
		/* We want to keep openingd alive, since we're not done yet */
		if (msg)
			wire_sync_write(REQ_FD, take(msg));
		return NULL;
	case WIRE_OPENINGD_ELTOO_FUNDER_COMPLETE:
		if (!fromwire_openingd_eltoo_funder_complete(state, msg,
						       &funding_txid,
						       &funding_txout,
						       &state->channel_type))
			master_badmsg(WIRE_OPENINGD_ELTOO_FUNDER_COMPLETE, msg);
		state->funding.txid = funding_txid;
		state->funding.n = funding_txout;
		return funder_channel_complete(state);
	case WIRE_OPENINGD_ELTOO_FUNDER_CANCEL:
		/* We're aborting this, simple */
		if (!fromwire_openingd_eltoo_funder_cancel(msg))
			master_badmsg(WIRE_OPENINGD_ELTOO_FUNDER_CANCEL, msg);

		msg = towire_errorfmt(NULL, &state->channel_id, "Channel open canceled by us");
		peer_write(state->pps, take(msg));
		negotiation_aborted(state, "Channel open canceled by RPC");
		return NULL;
	case WIRE_OPENINGD_ELTOO_DEV_MEMLEAK:
#if DEVELOPER
		handle_dev_memleak(state, msg);
		return NULL;
#endif
	case WIRE_OPENINGD_ELTOO_DEV_MEMLEAK_REPLY:
	case WIRE_OPENINGD_ELTOO_INIT:
	case WIRE_OPENINGD_ELTOO_FUNDER_REPLY:
	case WIRE_OPENINGD_ELTOO_FUNDER_START_REPLY:
	case WIRE_OPENINGD_ELTOO_FUNDEE:
	case WIRE_OPENINGD_ELTOO_FAILED:
		break;
	}

	status_failed(STATUS_FAIL_MASTER_IO,
		      "Unknown msg %s", tal_hex(tmpctx, msg));
}

int main(int argc, char *argv[])
{
	setup_locale();

	u8 *msg;
	struct pollfd pollfd[2];
	struct eltoo_state *state = tal(NULL, struct eltoo_state);
	struct channel_id *force_tmp_channel_id;

	subdaemon_setup(argc, argv);

	/*~ This makes status_failed, status_debug etc work synchronously by
	 * writing to REQ_FD */
	status_setup_sync(REQ_FD);

	/*~ The very first thing we read from lightningd is our init msg */
	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_openingd_eltoo_init(state, msg,
				   &chainparams,
				   &state->our_features,
				   &state->their_features,
				   &state->localconf,
				   &state->max_shared_delay,
				   &state->min_effective_htlc_capacity,
				   &state->our_funding_pubkey,
				   &state->our_settlement_pubkey,
				   &state->minimum_depth,
				   &state->min_feerate, &state->max_feerate,
				   &force_tmp_channel_id))
		master_badmsg(WIRE_OPENINGD_ELTOO_INIT, msg);

#if DEVELOPER
	dev_force_tmp_channel_id = force_tmp_channel_id;
#endif

	/* 3 == peer, 4 = hsmd */
	state->pps = new_per_peer_state(state);
	per_peer_state_set_fd(state->pps, 3);

	/*~ Initially we're not associated with a channel, but
	 * handle_peer_gossip_or_error compares this. */
	memset(&state->channel_id, 0, sizeof(state->channel_id));
	state->channel = NULL;

	/* Default this to zero, we only ever look at the local */
	state->remoteconf.max_dust_htlc_exposure_msat = AMOUNT_MSAT(0);

	/*~ We set these to NULL, meaning no requirements on shutdown */
	state->upfront_shutdown_script[LOCAL]
		= state->upfront_shutdown_script[REMOTE]
		= NULL;

	/*~ We manually run a little poll() loop here.  With only three fds */
	pollfd[0].fd = REQ_FD;
	pollfd[0].events = POLLIN;
	pollfd[1].fd = state->pps->peer_fd;
	pollfd[1].events = POLLIN;

	/* We exit when we get a conclusion to write to lightningd: either
	 * opening_funder_reply or opening_fundee. */
	msg = NULL;
	while (!msg) {
		/*~ If we get a signal which aborts the poll() call, valgrind
		 * complains about revents being uninitialized.  I'm not sure
		 * that's correct, but it's easy to be sure. */
		pollfd[0].revents = pollfd[1].revents = 0;

		poll(pollfd, ARRAY_SIZE(pollfd), -1);
		/* Subtle: handle_master_in can do its own poll loop, so
		 * don't try to service more than one fd per loop. */
		/* First priority: messages from lightningd. */
		if (pollfd[0].revents & POLLIN)
			msg = handle_master_in(state);
		/* Second priority: messages from peer. */
		else if (pollfd[1].revents & POLLIN)
			msg = handle_peer_in(state);

		/* Since we're the top-level event loop, we clean up */
		clean_tmpctx();
	}

	/*~ Write message and hand back the peer fd.  This also means that if
	 * the peer wrote us any messages we didn't read yet, it will simply
	 * be read by the next daemon. */
	wire_sync_write(REQ_FD, msg);
	per_peer_state_fdpass_send(REQ_FD, state->pps);
	status_debug("Sent %s with fd",
		     eltoo_openingd_wire_name(fromwire_peektype(msg)));

	/* This frees the entire tal tree. */
	tal_free(state);

	/* This frees up everything else. */
	daemon_shutdown();
	return 0;
}

/*~ Note that there are no other source files in openingd: it really is a fairly
 * straight-line daemon.
 *
 * From here the channel is established: lightningd hands the peer off to
 * channeld/channeld.c which runs the normal channel routine for this peer.
 */
