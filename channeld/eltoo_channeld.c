/* Main channel operation daemon: runs from funding_locked to shutdown_complete.
 *
 * We're fairly synchronous: our main loop looks for master or
 * peer requests and services them synchronously.
 *
 * The exceptions are:
 * 1. When we've asked the master something: in that case, we queue
 *    non-response packets for later processing while we await the reply.
 * 2. We queue and send non-blocking responses to peers: if both peers were
 *    reading and writing synchronously we could deadlock if we hit buffer
 *    limits, unlikely as that is.
 */
#include "config.h"
#include <ccan/asort/asort.h>
#include <ccan/cast/cast.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <channeld/eltoo_channeld.h>
#include <channeld/channeld_wiregen.h>
#include <channeld/eltoo_full_channel.h>
#include <channeld/full_channel_error.h>
#include <channeld/watchtower.h>
#include <common/billboard.h>
#include <common/ecdh_hsmd.h>
#include <common/gossip_store.h>
#include <common/key_derive.h>
#include <common/memleak.h>
#include <common/msg_queue.h>
#include <common/onionreply.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/private_channel_announcement.h>
#include <common/read_peer_msg.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/timeout.h>
#include <common/type_to_string.h>
#include <common/wire_error.h>
#include <errno.h>
#include <fcntl.h>
#include <gossipd/gossip_store_wiregen.h>
#include <gossipd/gossipd_peerd_wiregen.h>
#include <hsmd/hsmd_wiregen.h>
#include <wally_bip32.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* stdin == requests, 3 == peer, 4 = HSM */
#define MASTER_FD STDIN_FILENO
#define HSM_FD 4

struct eltoo_peer {
	struct per_peer_state *pps;
	bool funding_locked[NUM_SIDES];
	u64 next_index;

	/* Features peer supports. */
	u8 *their_features;

	/* Features we support. */
	struct feature_set *our_features;

	/* BOLT #2:
	 *
	 * A sending node:
	 *...
	 *  - for the first HTLC it offers:
	 *    - MUST set `id` to 0.
	 */
	u64 htlc_id;

	struct channel_id channel_id;
	struct channel *channel;

	/* Messages from master: we queue them since we might be
	 * waiting for a specific reply. */
	struct msg_queue *from_master;

	struct timers timers;
	struct oneshot *commit_timer;
	u64 commit_timer_attempts;
	u32 commit_msec;

	/* Announcement related information */
	struct node_id node_ids[NUM_SIDES];
	struct short_channel_id short_channel_ids[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_node_sigs[NUM_SIDES];
	secp256k1_ecdsa_signature announcement_bitcoin_sigs[NUM_SIDES];
	bool have_sigs[NUM_SIDES];

	/* Which direction of the channel do we control? */
	u16 channel_direction;

	/* CLTV delta to announce to peers */
	u16 cltv_delta;

	/* We only really know these because we're the ones who create
	 * the channel_updates. */
	u32 fee_base;
	u32 fee_per_satoshi;
	/* Note: the real min constraint is channel->config[REMOTE].htlc_minimum:
	 * they could kill the channel if we violate that! */
	struct amount_msat htlc_minimum_msat, htlc_maximum_msat;

	/* The scriptpubkey to use for shutting down. */
	u32 *final_index;
	struct ext_key *final_ext_key;
	u8 *final_scriptpubkey;

	/* If master told us to shut down */
	bool send_shutdown;
	/* Has shutdown been sent by each side? */
	bool shutdown_sent[NUM_SIDES];
	/* If master told us to send wrong_funding */
	struct bitcoin_outpoint *shutdown_wrong_funding;

#if EXPERIMENTAL_FEATURES
	/* Do we want quiescence? */
	bool stfu;
	/* Which side is considered the initiator? */
	enum side stfu_initiator;
	/* Has stfu been sent by each side? */
	bool stfu_sent[NUM_SIDES];
	/* Updates master asked, which we've deferred while quiescing */
	struct msg_queue *update_queue;
	/* Who's turn is it? */
    enum side turn;
    /* Can we yield? i.e. have we not yet sent updates during our turn? (or not our turn at all) */
    bool can_yield;
#endif

#if DEVELOPER
	/* If set, don't fire commit counter when this hits 0 */
	u32 *dev_disable_commit;

	/* If set, send channel_announcement after 1 second, not 30 */
	bool dev_fast_gossip;
#endif
	/* Information used for reestablishment. */
    /* FIXME figure out what goes here 
	bool last_was_revoke;
	struct changed_htlc *last_sent_commit;
	u64 revocations_received;
    */
	u8 channel_flags;

    /* Number of update_signed(_ack) messages received by peer */
	u64 updates_received;

	bool announce_depth_reached;
	bool channel_local_active;

	/* Make sure timestamps move forward. */
	u32 last_update_timestamp;

	/* Additional confirmations need for local lockin. */
	u32 depth_togo;

	/* Non-empty if they specified a fixed shutdown script */
	u8 *remote_upfront_shutdown_script;

	/* Empty commitments.  Spec violation, but a minor one. */
	u64 last_empty_commitment;

	/* We allow a 'tx-sigs' message between reconnect + funding_locked */
	bool tx_sigs_allowed;

	/* Most recent channel_update message. */
	u8 *channel_update;
};

static u8 *create_channel_announcement(const tal_t *ctx, struct eltoo_peer *peer);
static void start_update_timer(struct eltoo_peer *peer);

static void billboard_update(const struct eltoo_peer *peer)
{
	const char *update = billboard_message(tmpctx, peer->funding_locked,
					       peer->have_sigs,
					       peer->shutdown_sent,
					       peer->depth_togo,
					       num_channel_htlcs(peer->channel));

	peer_billboard(false, update);
}

const u8 *hsm_req(const tal_t *ctx, const u8 *req TAKES)
{
	u8 *msg;

	/* hsmd goes away at shutdown.  That's OK. */
	if (!wire_sync_write(HSM_FD, req))
		exit(0);

	msg = wire_sync_read(ctx, HSM_FD);
	if (!msg)
		exit(0);

	return msg;
}

#if EXPERIMENTAL_FEATURES
static void maybe_send_stfu(struct eltoo_peer *peer)
{
	if (!peer->stfu)
		return;

	if (!peer->stfu_sent[LOCAL] && !pending_updates(peer->channel, LOCAL, false)) {
		u8 *msg = towire_stfu(NULL, &peer->channel_id,
				      peer->stfu_initiator == LOCAL);
		peer_write(peer->pps, take(msg));
		peer->stfu_sent[LOCAL] = true;
	}

	if (peer->stfu_sent[LOCAL] && peer->stfu_sent[REMOTE]) {
		status_unusual("STFU complete: we are quiescent");
		wire_sync_write(MASTER_FD,
				towire_channeld_dev_quiesce_reply(tmpctx));
	}
}

static void handle_stfu(struct eltoo_peer *peer, const u8 *stfu)
{
	struct channel_id channel_id;
	u8 remote_initiated;

	if (!fromwire_stfu(stfu, &channel_id, &remote_initiated))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad stfu %s", tal_hex(peer, stfu));

	if (!channel_id_eq(&channel_id, &peer->channel_id)) {
		peer_failed_err(peer->pps, &channel_id,
				"Wrong stfu channel_id: expected %s, got %s",
				type_to_string(tmpctx, struct channel_id,
					       &peer->channel_id),
				type_to_string(tmpctx, struct channel_id,
					       &channel_id));
	}

	/* Sanity check */
	if (pending_updates(peer->channel, REMOTE, false))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "STFU but you still have updates pending?");

	if (!peer->stfu) {
		peer->stfu = true;
		if (!remote_initiated)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "Unsolicited STFU but you said"
					 " you didn't initiate?");
		peer->stfu_initiator = REMOTE;
	} else {
		/* BOLT-quiescent #2:
		 *
		 * If both sides send `stfu` simultaneously, they will both
		 * set `initiator` to `1`, in which case the "initiator" is
		 * arbitrarily considered to be the channel funder (the sender
		 * of `open_channel`).
		 */
		if (remote_initiated)
			peer->stfu_initiator = peer->channel->opener;
	}

	/* BOLT-quiescent #2:
	 * The receiver of `stfu`:
	 *   - if it has sent `stfu` then:
	 *     - MUST now consider the channel to be quiescent
	 *   - otherwise:
	 *     - SHOULD NOT send any more update messages.
	 *     - MUST reply with `stfu` once it can do so.
	 */
	peer->stfu_sent[REMOTE] = true;

	maybe_send_stfu(peer);
}

static bool is_our_turn(const struct eltoo_peer *peer)
{
    return peer->turn == LOCAL;
}

/* Returns true if we queued this for later handling (steals if true) */
static bool handle_master_request_later(struct eltoo_peer *peer, const u8 *msg)
{
	if (peer->stfu) {
		status_debug("queueing master update for later...");
		msg_enqueue(peer->update_queue, take(msg));
		return true;
    } else if (!is_our_turn(peer)) {
        /* We use a noop update to request they yield once,
        then only queue up later messages while waiting. */
        if (msg_queue_length(peer->update_queue) == 0) {
            u8 *noop = towire_update_noop(NULL, &peer->channel_id);
            peer_write(peer->pps, take(noop));
        }
        status_debug("queueing master update for later turn...");
        msg_enqueue(peer->update_queue, take(msg));
        return true;
    }
    return false;
}

#else /* !EXPERIMENTAL_FEATURES */
static bool handle_master_request_later(struct eltoo_peer *peer, const u8 *msg)
{
	return false;
}

static void maybe_send_stfu(struct eltoo_peer *peer)
{
}
#endif

/* Tell gossipd to create channel_update (then it goes into
 * gossip_store, then streams out to peers, or sends it directly if
 * it's a private channel) */
static void send_channel_update(struct eltoo_peer *peer, int disable_flag)
{
	u8 *msg;

	assert(disable_flag == 0 || disable_flag == ROUTING_FLAGS_DISABLED);

	/* Only send an update if we told gossipd */
	if (!peer->channel_local_active)
		return;

	assert(peer->short_channel_ids[LOCAL].u64);

	msg = towire_channeld_local_channel_update(NULL,
						  &peer->short_channel_ids[LOCAL],
						  disable_flag
						  == ROUTING_FLAGS_DISABLED,
						  peer->cltv_delta,
						  peer->htlc_minimum_msat,
						  peer->fee_base,
						  peer->fee_per_satoshi,
						  peer->htlc_maximum_msat);
	wire_sync_write(MASTER_FD, take(msg));
}

/* Tell gossipd and the other side what parameters we expect should
 * they route through us */
static void send_channel_initial_update(struct eltoo_peer *peer)
{
	send_channel_update(peer, 0);
}

/**
 * Add a channel locally and send a channel update to the peer
 *
 * Send a local_add_channel message to gossipd in order to make the channel
 * usable locally, and also tell our peer about our parameters via a
 * channel_update message. The peer may accept the update and use the contained
 * information to route incoming payments through the channel. The
 * channel_update is not preceeded by a channel_announcement and won't make much
 * sense to other nodes, so we don't tell gossipd about it.
 */
static void make_channel_local_active(struct eltoo_peer *peer)
{
	u8 *msg;
	const u8 *annfeatures = get_agreed_channelfeatures(tmpctx,
							   peer->our_features,
							   peer->their_features);

	/* Tell lightningd to tell gossipd about local channel. */
	msg = towire_channeld_local_private_channel(NULL,
						    peer->channel->funding_sats,
						    annfeatures);
 	wire_sync_write(MASTER_FD, take(msg));

	/* Under CI, because blocks come so fast, we often find that the
	 * peer sends its first channel_update before the above message has
	 * reached it. */
	notleak(new_reltimer(&peer->timers, peer,
			     time_from_sec(5),
			     send_channel_initial_update, peer));
}

static void send_announcement_signatures(struct eltoo_peer *peer)
{
    return;
	/* First 2 + 256 byte are the signatures and msg type, skip them */
	size_t offset = 258;
	struct sha256_double hash;
	const u8 *msg, *ca, *req;
	struct pubkey mykey;

	status_debug("Exchanging announcement signatures.");
	ca = create_channel_announcement(tmpctx, peer);
	req = towire_hsmd_cannouncement_sig_req(tmpctx, ca);

	msg = hsm_req(tmpctx, req);
	if (!fromwire_hsmd_cannouncement_sig_reply(msg,
				  &peer->announcement_node_sigs[LOCAL],
				  &peer->announcement_bitcoin_sigs[LOCAL]))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Reading cannouncement_sig_resp: %s",
			      strerror(errno));

	/* Double-check that HSM gave valid signatures. */
	sha256_double(&hash, ca + offset, tal_count(ca) - offset);
	if (!pubkey_from_node_id(&mykey, &peer->node_ids[LOCAL]))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not convert my id '%s' to pubkey",
			      type_to_string(tmpctx, struct node_id,
					     &peer->node_ids[LOCAL]));
	if (!check_signed_hash(&hash, &peer->announcement_node_sigs[LOCAL],
			       &mykey)) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(STATUS_FAIL_HSM_IO,
			      "HSM returned an invalid node signature");
	}

	if (!check_signed_hash(&hash, &peer->announcement_bitcoin_sigs[LOCAL],
			       &peer->channel->funding_pubkey[LOCAL])) {
		/* It's ok to fail here, the channel announcement is
		 * unique, unlike the channel update which may have
		 * been replaced in the meantime. */
		status_failed(STATUS_FAIL_HSM_IO,
			      "HSM returned an invalid bitcoin signature");
	}

	msg = towire_announcement_signatures(
	    NULL, &peer->channel_id, &peer->short_channel_ids[LOCAL],
	    &peer->announcement_node_sigs[LOCAL],
	    &peer->announcement_bitcoin_sigs[LOCAL]);
	peer_write(peer->pps, take(msg));
}

/* Tentatively create a channel_announcement, possibly with invalid
 * signatures. The signatures need to be collected first, by asking
 * the HSM and by exchanging announcement_signature messages. */
static u8 *create_channel_announcement(const tal_t *ctx, struct eltoo_peer *peer)
{
	int first, second;
	u8 *cannounce, *features
		= get_agreed_channelfeatures(tmpctx, peer->our_features,
					     peer->their_features);

	if (peer->channel_direction == 0) {
		first = LOCAL;
		second = REMOTE;
	} else {
		first = REMOTE;
		second = LOCAL;
	}

	cannounce = towire_channel_announcement(
	    ctx, &peer->announcement_node_sigs[first],
	    &peer->announcement_node_sigs[second],
	    &peer->announcement_bitcoin_sigs[first],
	    &peer->announcement_bitcoin_sigs[second],
	    features,
	    &chainparams->genesis_blockhash,
	    &peer->short_channel_ids[LOCAL],
	    &peer->node_ids[first],
	    &peer->node_ids[second],
	    &peer->channel->funding_pubkey[first],
	    &peer->channel->funding_pubkey[second]);
	return cannounce;
}

/* Once we have both, we'd better make sure we agree what they are! */
static void check_short_ids_match(struct eltoo_peer *peer)
{
	assert(peer->have_sigs[LOCAL]);
	assert(peer->have_sigs[REMOTE]);

	if (!short_channel_id_eq(&peer->short_channel_ids[LOCAL],
				 &peer->short_channel_ids[REMOTE]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "We disagree on short_channel_ids:"
				 " I have %s, you say %s",
				 type_to_string(peer, struct short_channel_id,
						&peer->short_channel_ids[LOCAL]),
				 type_to_string(peer, struct short_channel_id,
						&peer->short_channel_ids[REMOTE]));
}

static void announce_channel(struct eltoo_peer *peer)
{
	u8 *cannounce;

	cannounce = create_channel_announcement(tmpctx, peer);

	wire_sync_write(MASTER_FD,
			take(towire_channeld_local_channel_announcement(NULL,
									cannounce)));
	send_channel_update(peer, 0);
}

static void channel_announcement_negotiate(struct eltoo_peer *peer)
{
	/* Don't do any announcement work if we're shutting down */
	if (peer->shutdown_sent[LOCAL])
		return;

	/* Can't do anything until funding is locked. */
	if (!peer->funding_locked[LOCAL] || !peer->funding_locked[REMOTE])
		return;

	if (!peer->channel_local_active) {
		peer->channel_local_active = true;
		make_channel_local_active(peer);
	}

	/* BOLT #7:
	 *
	 * A node:
	 *   - if the `open_channel` message has the `announce_channel` bit set AND a `shutdown` message has not been sent:
	 *     - MUST send the `announcement_signatures` message.
	 *       - MUST NOT send `announcement_signatures` messages until `funding_locked`
	 *       has been sent and received AND the funding transaction has at least six confirmations.
	 *   - otherwise:
	 *     - MUST NOT send the `announcement_signatures` message.
	 */
	if (!(peer->channel_flags & CHANNEL_FLAGS_ANNOUNCE_CHANNEL))
		return;

	/* BOLT #7:
	 *
	 *      - MUST NOT send `announcement_signatures` messages until `funding_locked`
	 *      has been sent and received AND the funding transaction has at least six confirmations.
 	 */
	if (peer->announce_depth_reached && !peer->have_sigs[LOCAL]) {
		/* When we reenable the channel, we will also send the announcement to remote peer, and
		 * receive the remote announcement reply. But we will rebuild the channel with announcement
		 * from the DB directly, other than waiting for the remote announcement reply.
		 */
        /* FIXME no announcements for now */
		send_announcement_signatures(peer);
		peer->have_sigs[LOCAL] = true;
		billboard_update(peer);
	}

	/* If we've completed the signature exchange, we can send a real
	 * announcement, otherwise we send a temporary one */
	if (peer->have_sigs[LOCAL] && peer->have_sigs[REMOTE]) {
		check_short_ids_match(peer);

		/* After making sure short_channel_ids match, we can send remote
		 * announcement to MASTER. */
		wire_sync_write(MASTER_FD,
			        take(towire_channeld_got_announcement(NULL,
			        &peer->announcement_node_sigs[REMOTE],
			        &peer->announcement_bitcoin_sigs[REMOTE])));

		/* Give other nodes time to notice new block. */
		notleak(new_reltimer(&peer->timers, peer,
				     time_from_sec(GOSSIP_ANNOUNCE_DELAY(peer->dev_fast_gossip)),
				     announce_channel, peer));
	}
}

static void handle_peer_funding_locked_eltoo(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *  - upon reconnection:
	 *    - MUST ignore any redundant `funding_locked` it receives.
	 */
	if (peer->funding_locked[REMOTE])
		return;

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	if (!fromwire_funding_locked_eltoo(msg, &chanid))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad funding_locked_eltoo %s", tal_hex(msg, msg));

	if (!channel_id_eq(&chanid, &peer->channel_id))
		peer_failed_err(peer->pps, &chanid,
				"Wrong channel id in %s (expected %s)",
				tal_hex(tmpctx, msg),
				type_to_string(msg, struct channel_id,
					       &peer->channel_id));

	peer->tx_sigs_allowed = false;
	peer->funding_locked[REMOTE] = true;
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_funding_locked_eltoo(NULL)));

	channel_announcement_negotiate(peer);
	billboard_update(peer);
}

static void handle_peer_announcement_signatures(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id chanid;

	if (!fromwire_announcement_signatures(msg,
					      &chanid,
					      &peer->short_channel_ids[REMOTE],
					      &peer->announcement_node_sigs[REMOTE],
					      &peer->announcement_bitcoin_sigs[REMOTE]))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad announcement_signatures %s",
				 tal_hex(msg, msg));

	/* Make sure we agree on the channel ids */
	if (!channel_id_eq(&chanid, &peer->channel_id)) {
		peer_failed_err(peer->pps, &chanid,
				"Wrong channel_id: expected %s, got %s",
				type_to_string(tmpctx, struct channel_id,
					       &peer->channel_id),
				type_to_string(tmpctx, struct channel_id, &chanid));
	}

	peer->have_sigs[REMOTE] = true;
	billboard_update(peer);

	channel_announcement_negotiate(peer);
}

static void handle_peer_add_htlc(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	struct amount_msat amount;
	u32 cltv_expiry;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	enum channel_add_err add_err;
	struct htlc *htlc;
#if EXPERIMENTAL_FEATURES
	struct tlv_update_add_tlvs *tlvs;
#endif
	struct pubkey *blinding = NULL;

	if (!fromwire_update_add_htlc
#if EXPERIMENTAL_FEATURES
	    (msg, msg, &channel_id, &id, &amount,
	     &payment_hash, &cltv_expiry,
	     onion_routing_packet, &tlvs)
#else
	    (msg, &channel_id, &id, &amount,
	     &payment_hash, &cltv_expiry,
	     onion_routing_packet)
#endif
		)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad peer_add_htlc %s", tal_hex(msg, msg));

#if EXPERIMENTAL_FEATURES
	blinding = tlvs->blinding;
#endif
	add_err = eltoo_channel_add_htlc(peer->channel, REMOTE, id, amount,
				   cltv_expiry, &payment_hash,
				   onion_routing_packet, blinding, &htlc,
				   /* err_immediate_failures */ false);
	if (add_err != CHANNEL_ERR_ADD_OK)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad peer_add_htlc: %s",
				 channel_add_err_name(add_err));
}

static struct changed_htlc *changed_htlc_arr(const tal_t *ctx,
					     const struct htlc **changed_htlcs)
{
	struct changed_htlc *changed;
	size_t i;

	changed = tal_arr(ctx, struct changed_htlc, tal_count(changed_htlcs));
	for (i = 0; i < tal_count(changed_htlcs); i++) {
		changed[i].id = changed_htlcs[i]->id;
		changed[i].newstate = changed_htlcs[i]->state;
	}
	return changed;
}

static u8 *sending_updatesig_msg(const tal_t *ctx,
				 u64 update_index,
				 const struct htlc **changed_htlcs,
                 const struct partial_sig *our_update_psig,
                 const struct musig_session *session,
	   		     const struct bitcoin_tx *committed_update_tx,
			     const struct bitcoin_tx *committed_settle_tx)
{
	struct changed_htlc *changed;
	u8 *msg;

	/* We tell master what (of our) HTLCs we will be
	 * committed to, and of unfinished partial signtures. */
	changed = changed_htlc_arr(tmpctx, changed_htlcs);
	msg = towire_channeld_sending_updatesig(ctx, update_index,
						changed, our_update_psig, session, committed_update_tx, committed_settle_tx);
	return msg;
}

static bool shutdown_complete(const struct eltoo_peer *peer)
{
    /* FIXME last line is very wrong */
	return peer->shutdown_sent[LOCAL]
		&& peer->shutdown_sent[REMOTE]
		&& num_channel_htlcs(peer->channel) == 0
		&& peer->updates_received == peer->next_index - 1;
}

/* BOLT #2:
 *
 * A sending node:
 *...
 *  - if there are updates pending on the receiving node's commitment
 *    transaction:
 *     - MUST NOT send a `shutdown`.
 */
/* So we only call this after reestablish or immediately after sending commit */
static void maybe_send_shutdown(struct eltoo_peer *peer)
{
	u8 *msg;
	struct tlv_shutdown_tlvs *tlvs;

	if (!peer->send_shutdown)
		return;

	/* Send a disable channel_update so others don't try to route
	 * over us */
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);

	if (peer->shutdown_wrong_funding) {
		tlvs = tlv_shutdown_tlvs_new(tmpctx);
		tlvs->wrong_funding
			= tal(tlvs, struct tlv_shutdown_tlvs_wrong_funding);
		tlvs->wrong_funding->txid = peer->shutdown_wrong_funding->txid;
		tlvs->wrong_funding->outnum = peer->shutdown_wrong_funding->n;
	} else
		tlvs = NULL;

	msg = towire_shutdown(NULL, &peer->channel_id, peer->final_scriptpubkey,
			      tlvs);
	peer_write(peer->pps, take(msg));
	peer->send_shutdown = false;
	peer->shutdown_sent[LOCAL] = true;
	billboard_update(peer);
}

static void send_shutdown_complete(struct eltoo_peer *peer)
{
	/* Now we can tell master shutdown is complete. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_shutdown_complete(NULL)));
	per_peer_state_fdpass_send(MASTER_FD, peer->pps);
	close(MASTER_FD);
}

/* This queues other traffic from the fd until we get reply. */
static u8 *master_wait_sync_reply(const tal_t *ctx,
				  struct eltoo_peer *peer,
				  const u8 *msg,
				  int replytype)
{
	u8 *reply;

	status_debug("Sending master %u", fromwire_peektype(msg));

	if (!wire_sync_write(MASTER_FD, msg))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not set sync write to master: %s",
			      strerror(errno));

	status_debug("... , awaiting %u", replytype);

	for (;;) {
		int type;

		reply = wire_sync_read(ctx, MASTER_FD);
		if (!reply)
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Could not set sync read from master: %s",
				      strerror(errno));
		type = fromwire_peektype(reply);
		if (type == replytype) {
			status_debug("Got it!");
			break;
		}

		status_debug("Nope, got %u instead", type);
		msg_enqueue(peer->from_master, take(reply));
	}

	return reply;
}

static void change_turn(struct eltoo_peer *peer, enum side turn)
{
    assert(peer->turn == !turn);
    peer->turn = turn;
    peer->can_yield = true;
    status_debug("turn is now %s", side_to_str(turn));
}

static void send_update(struct eltoo_peer *peer)
{
	u8 *msg;
    const u8 *hsmd_msg;
	const struct htlc **changed_htlcs;
	struct bitcoin_tx **update_and_settle_txs;
	const struct htlc **htlc_map;
	struct wally_tx_output *direct_outputs[NUM_SIDES];

#if DEVELOPER
	if (peer->dev_disable_commit && !*peer->dev_disable_commit) {
		peer->commit_timer = NULL;
		return;
	}
#endif

	/* FIXME: Document this requirement in BOLT 2! */
	/* We can't send two commits in a row. */
	if (peer->updates_received != peer->next_index - 1) {
		assert(peer->updates_received
		       == peer->next_index - 2);
		peer->commit_timer_attempts++;
		/* Only report this in extreme cases */
		if (peer->commit_timer_attempts % 100 == 0)
			status_debug("Can't send commit:"
				     " waiting for update_ack with %"
				     PRIu64" attempts",
				     peer->commit_timer_attempts);
		/* Mark this as done and try again. */
		peer->commit_timer = NULL;
		start_update_timer(peer);
		return;
	}

	/* BOLT #2:
	 *
	 *   - if no HTLCs remain in either commitment transaction:
	 *	- MUST NOT send any `update` message after a `shutdown`.
	 */
	if (peer->shutdown_sent[LOCAL] && !num_channel_htlcs(peer->channel)) {
		status_debug("Can't send commit: final shutdown phase");

		peer->commit_timer = NULL;
		return;
	}

	/* BOLT #2:
	 *
	 * A sending node:
	 *   - MUST NOT send a `commitment_signed` message that does not include
	 *     any updates.
	 */
	changed_htlcs = tal_arr(tmpctx, const struct htlc *, 0);
	if (!channel_sending_update(peer->channel, &changed_htlcs)) {
		status_debug("Can't send commit: nothing to send");

		/* Covers the case where we've just been told to shutdown. */
		maybe_send_shutdown(peer);

		peer->commit_timer = NULL;
		return;
	}

	status_debug("Creating pair of transactions for sending update");
	update_and_settle_txs = eltoo_channel_txs(tmpctx, &htlc_map, direct_outputs,
			  peer->channel,
			  peer->next_index, LOCAL);

    msg = towire_hsmd_psign_update_tx(tmpctx,
            &peer->channel_id,
            update_and_settle_txs[0],
            update_and_settle_txs[1],
            &peer->channel->eltoo_keyset.other_funding_key,
            &peer->channel->eltoo_keyset.other_next_nonce,
            &peer->channel->eltoo_keyset.self_next_nonce);

    status_debug("partial signature req %s on update tx %s, settle tx %s, using our key %s, their key %s, inner pubkey %s, OLD our nonce %s, OLD their nonce %s",
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.self_psig),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[0]),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[1]),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.self_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.other_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.inner_pubkey),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.self_next_nonce),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.other_next_nonce));

    hsmd_msg = hsm_req(tmpctx, take(msg));
    if (!fromwire_hsmd_psign_update_tx_reply(hsmd_msg, &peer->channel->eltoo_keyset.last_committed_state.self_psig, &peer->channel->eltoo_keyset.last_committed_state.session, &peer->channel->eltoo_keyset.self_next_nonce, &peer->channel->eltoo_keyset.inner_pubkey))
        status_failed(STATUS_FAIL_HSM_IO,
                  "Reading psign_update_tx reply: %s",
                  tal_hex(tmpctx, msg));

    /* We don't learn their new nonce until we get ACK... */
    status_debug("partial signature %s on update tx %s, settle tx %s, using our key %s, their key %s, inner pubkey %s, NEW our nonce %s, OLD their nonce %s, session %s",
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.self_psig),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[0]),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[1]),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.self_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.other_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.inner_pubkey),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.self_next_nonce),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.other_next_nonce),
             type_to_string(tmpctx, struct musig_session, &peer->channel->eltoo_keyset.last_committed_state.session));

    /* Cache half-signed tx, for finalization when ACK comes back */
    tal_free(peer->channel->eltoo_keyset.committed_update_tx);
    tal_free(peer->channel->eltoo_keyset.committed_settle_tx);
    peer->channel->eltoo_keyset.committed_update_tx = tal_steal(peer->channel, update_and_settle_txs[0]);
    peer->channel->eltoo_keyset.committed_settle_tx = tal_steal(peer->channel, update_and_settle_txs[1]);

#if DEVELOPER
	if (peer->dev_disable_commit) {
		(*peer->dev_disable_commit)--;
		if (*peer->dev_disable_commit == 0)
			status_unusual("dev-disable-commit-after: disabling");
	}
#endif

	status_debug("Telling master we're about to update...");
	/* Tell master to save this next commit to database, then wait. */
	msg = sending_updatesig_msg(NULL, peer->next_index,
				    changed_htlcs,
				    &peer->channel->eltoo_keyset.last_committed_state.self_psig,
				    &peer->channel->eltoo_keyset.last_committed_state.session,
                    peer->channel->eltoo_keyset.committed_update_tx,
                    peer->channel->eltoo_keyset.committed_settle_tx);
	/* Message is empty; receiving it is the point. */
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNELD_SENDING_UPDATESIG_REPLY);

	status_debug("Sending update_sig");

	peer->next_index++;
	/* Cannot yield after sending an update */
	peer->can_yield = false;

	msg = towire_update_signed(NULL, &peer->channel_id,
				       &peer->channel->eltoo_keyset.last_committed_state.self_psig,
				       &peer->channel->eltoo_keyset.self_next_nonce);
	peer_write(peer->pps, take(msg));

	maybe_send_shutdown(peer);

	/*
	 * - MUST give up its turn when:
     * - sending `update_signed`
	 */
	if (is_our_turn(peer)){
		change_turn(peer, REMOTE);
	} else {
		/* We are not doing optimistic updates */
		status_broken("We're proposing updates out of turn?");
	}

	/* Timer now considered expired, you can add a new one. */
	peer->commit_timer = NULL;
	start_update_timer(peer);
}

static void start_update_timer(struct eltoo_peer *peer)
{
	/* Already armed? */
	if (peer->commit_timer)
		return;

	peer->commit_timer_attempts = 0;
	peer->commit_timer = new_reltimer(&peer->timers, peer,
					  time_from_msec(peer->commit_msec),
					  send_update, peer);
}

static u8 *make_update_signed_ack_msg(const struct eltoo_peer *peer,
                                      const struct partial_sig *our_update_psig,
                                      const struct nonce *next_nonce)
{
    return towire_update_signed_ack(peer, &peer->channel_id, our_update_psig, next_nonce);
}

/* Convert changed htlcs into parts which lightningd expects. */
static void marshall_htlc_info(const tal_t *ctx,
			       const struct htlc **changed_htlcs,
			       struct changed_htlc **changed,
			       struct fulfilled_htlc **fulfilled,
			       const struct failed_htlc ***failed,
			       struct added_htlc **added)
{
	*changed = tal_arr(ctx, struct changed_htlc, 0);
	*added = tal_arr(ctx, struct added_htlc, 0);
	*failed = tal_arr(ctx, const struct failed_htlc *, 0);
	*fulfilled = tal_arr(ctx, struct fulfilled_htlc, 0);

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		const struct htlc *htlc = changed_htlcs[i];
		if (htlc->state == RCVD_ADD_UPDATE) {
			struct added_htlc a;

			a.id = htlc->id;
			a.amount = htlc->amount;
			a.payment_hash = htlc->rhash;
			a.cltv_expiry = abs_locktime_to_blocks(&htlc->expiry);
			memcpy(a.onion_routing_packet,
			       htlc->routing,
			       sizeof(a.onion_routing_packet));
			if (htlc->blinding) {
				a.blinding = htlc->blinding;
				ecdh(a.blinding, &a.blinding_ss);
			} else
				a.blinding = NULL;
			a.fail_immediate = htlc->fail_immediate;
			tal_arr_expand(added, a);
		} else if (htlc->state == RCVD_REMOVE_UPDATE) {
			if (htlc->r) {
				struct fulfilled_htlc f;
				assert(!htlc->failed);
				f.id = htlc->id;
				f.payment_preimage = *htlc->r;
				tal_arr_expand(fulfilled, f);
			} else {
				assert(!htlc->r);
				tal_arr_expand(failed, htlc->failed);
			}
		} else {
			struct changed_htlc c;
			assert(htlc->state == RCVD_REMOVE_ACK
			       || htlc->state == RCVD_ADD_ACK
                   || htlc->state == SENT_REMOVE_REVOCATION /* SENT_REMOVE_ACK */);

			c.id = htlc->id;
			c.newstate = htlc->state;
			tal_arr_expand(changed, c);
		}
	}
}

static void send_update_sign_ack(struct eltoo_peer *peer,
                const struct htlc **changed_htlcs,
			    const struct partial_sig *our_update_psig,
			    const struct partial_sig *their_update_psig,
                const struct musig_session *session,
			    const struct bitcoin_tx *update_tx,
			    const struct bitcoin_tx *settle_tx)
{
	struct changed_htlc *changed;
	struct fulfilled_htlc *fulfilled;
	const struct failed_htlc **failed;
	struct added_htlc *added;
	const u8 *msg;
	const u8 *msg_for_master;

	/* Marshall it now before channel_sending_revoke_and_ack changes htlcs */
	/* FIXME: Make infrastructure handle state post-revoke_and_ack! */
	marshall_htlc_info(tmpctx,
			   changed_htlcs,
			   &changed,
			   &fulfilled,
			   &failed,
			   &added);

    msg = make_update_signed_ack_msg(peer, our_update_psig, &peer->channel->eltoo_keyset.self_next_nonce);

	/* From now on we apply changes to the next commitment */
	peer->next_index++;

	/* If this queues more changes on the other end, send commit. */
    /* FIXME I don't think this can happen with eltoo/turn taking?
	if (channel_sending_revoke_and_ack(peer->channel)) {
		status_debug("revoke_and_ack made pending: commit timer");
		start_update_timer(peer);
	} */

	/* Tell master daemon about update_sig (and by implication, that we're
	 * sending update_sig_ack), then wait for it to ack. */
	msg_for_master
		= towire_channeld_got_updatesig(NULL,
					       peer->next_index - 1,
					       our_update_psig,
                           their_update_psig,
                           session,
					       added,
					       fulfilled,
					       failed,
					       changed,
					       update_tx,
                           settle_tx);
	master_wait_sync_reply(tmpctx, peer, take(msg_for_master),
			       WIRE_CHANNELD_GOT_UPDATESIG_REPLY);

	/* Now we can finally send update_signed_ack to peer */
	peer_write(peer->pps, take(msg));

    /* FIXME Update HTLC states to reflect this and tell master? */

}

static void handle_peer_update_sig(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	struct bitcoin_tx **update_and_settle_txs;
    struct bip340sig update_sig;
	const struct htlc **htlc_map, **changed_htlcs;
    struct nonce their_next_nonce;

	changed_htlcs = tal_arr(msg, const struct htlc *, 0);
    /* Does our counterparty offer any changes? */
	if (!channel_rcvd_update(peer->channel, &changed_htlcs)) {
		/* BOLT #2:
		 *
		 * A sending node:
		 *   - MUST NOT send a `commitment_signed` message that does not
		 *     include any updates.
		 */
		status_debug("Oh hi LND! Empty commitment at #%"PRIu64,
			     peer->next_index);
		if (peer->last_empty_commitment == peer->next_index - 1)
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "update_signed with no changes (again!)");
		peer->last_empty_commitment = peer->next_index;
	}

	if (!fromwire_update_signed(msg,
					&channel_id, &peer->channel->eltoo_keyset.last_committed_state.other_psig, &their_next_nonce))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_signed %s", tal_hex(msg, msg));

    peer->updates_received++;

	status_debug("Received update_sig");

	status_debug("Creating pair of transactions for update we received");
	update_and_settle_txs =
	    eltoo_channel_txs(tmpctx, &htlc_map, /* direct_outputs */ NULL,
			peer->channel,
			peer->next_index, LOCAL);

    /* We sign the same update transaction as peer should have signed */
    msg = towire_hsmd_psign_update_tx(NULL,
                           &peer->channel_id,
                           update_and_settle_txs[0],
                           update_and_settle_txs[1],
                           &peer->channel->eltoo_keyset.other_funding_key,
                           &peer->channel->eltoo_keyset.other_next_nonce,
                           &peer->channel->eltoo_keyset.self_next_nonce);

    status_debug("partial signature req %s on update tx %s, settle tx %s, using our key %s, their key %s, inner pubkey %s, OLD our nonce %s, OLD their nonce %s",
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.self_psig),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[0]),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[1]),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.self_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.other_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.inner_pubkey),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.self_next_nonce),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.other_next_nonce));

    /* Slide their newest nonce into place after consuming it above */
    peer->channel->eltoo_keyset.other_next_nonce = their_next_nonce;

    wire_sync_write(HSM_FD, take(msg));
    msg = wire_sync_read(tmpctx, HSM_FD);
    if (!fromwire_hsmd_psign_update_tx_reply(msg, &peer->channel->eltoo_keyset.last_committed_state.self_psig, &peer->channel->eltoo_keyset.last_committed_state.session, &peer->channel->eltoo_keyset.self_next_nonce, &peer->channel->eltoo_keyset.inner_pubkey))
        status_failed(STATUS_FAIL_HSM_IO, "Bad sign_tx_reply %s",
                  tal_hex(tmpctx, msg));

    status_debug("partial signature combine our_psig %s their_psig %s on update tx %s, settle tx %s, using our key %s, their key %s, inner pubkey %s, NEW our nonce %s, NEW their nonce %s, session %s",
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.self_psig),
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.other_psig),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[0]),
             type_to_string(tmpctx, struct bitcoin_tx, update_and_settle_txs[1]),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.self_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.other_funding_key),
             type_to_string(tmpctx, struct pubkey,
                    &peer->channel->eltoo_keyset.inner_pubkey),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.self_next_nonce),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.other_next_nonce),
             type_to_string(tmpctx, struct musig_session, &peer->channel->eltoo_keyset.last_committed_state.session));

    /* Before replying, make sure signature is correct */
    msg = towire_hsmd_combine_psig(NULL,
                            &peer->channel_id,
                            &peer->channel->eltoo_keyset.last_committed_state.self_psig,
                            &peer->channel->eltoo_keyset.last_committed_state.other_psig,
                            &peer->channel->eltoo_keyset.last_committed_state.session,
                            update_and_settle_txs[0],
                            update_and_settle_txs[1],
                            &peer->channel->eltoo_keyset.inner_pubkey);
    wire_sync_write(HSM_FD, take(msg));
    msg = wire_sync_read(tmpctx, HSM_FD);
    if (!fromwire_hsmd_combine_psig_reply(msg, &update_sig)) {
        status_failed(STATUS_FAIL_HSM_IO,
                  "Bad combine_psig reply %s", tal_hex(tmpctx, msg));
    }

    /* Now that we've checked the update, migrate all signing state from last_committed_state to last_complete_state */
    peer->channel->eltoo_keyset.last_complete_state = peer->channel->eltoo_keyset.last_committed_state;
    
    /* FIXME do we just bump on lightningd side? We are about to send an update, increment HTLCs to sent state
        this was aping peer_sending_revocation
    if (!channel_sending_sign_ack(peer->channel, &changed_htlcs)) {
        status_debug("Failed to increment HTLC state after sending ACK...");
    }*/

	/*
  	 * - MUST accept its turn when:
     * - receiving `update_signed`
	 */
	if (!is_our_turn(peer)) {
		change_turn(peer, LOCAL);
	} else {
		status_broken("We are processing remote's update during our turn?");
	}

    /* Tell master about this exchange, then the peer.
       Note: We do not persist nonces, as they will not outlive
       a single connection to peer! */
	send_update_sign_ack(peer,
        changed_htlcs,
        &peer->channel->eltoo_keyset.last_complete_state.self_psig,
        &peer->channel->eltoo_keyset.last_complete_state.other_psig,
        &peer->channel->eltoo_keyset.last_complete_state.session,
        update_and_settle_txs[0],
        update_and_settle_txs[1]);

	/* We may now be quiescent on our side. */
	maybe_send_stfu(peer);

}

static u8 *got_signed_ack_msg(struct eltoo_peer *peer,
              u64 update_num,
			  const struct htlc **changed_htlcs,
              const struct partial_sig *their_psig,
              const struct partial_sig *our_psig,
              const struct musig_session *session)
{
	u8 *msg;
	struct changed_htlc *changed = tal_arr(tmpctx, struct changed_htlc, 0);

	for (size_t i = 0; i < tal_count(changed_htlcs); i++) {
		struct changed_htlc c;
		const struct htlc *htlc = changed_htlcs[i];

		status_debug("got_signed_ack HTLC %"PRIu64"[%s] => %s",
			     htlc->id, side_to_str(htlc_owner(htlc)),
			     htlc_state_name(htlc->state));

		c.id = changed_htlcs[i]->id;
		c.newstate = changed_htlcs[i]->state;
		tal_arr_expand(&changed, c);
	}

	msg = towire_channeld_got_ack(peer, update_num,
					changed, their_psig, our_psig, session);

	return msg;
}

static void handle_peer_update_sig_ack(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	const u8 *comb_msg;
    struct bip340sig update_sig;
	const struct htlc **changed_htlcs = tal_arr(msg, const struct htlc *, 0);

	if (!fromwire_update_signed_ack(msg, &channel_id, &peer->channel->eltoo_keyset.last_committed_state.other_psig,
				     &peer->channel->eltoo_keyset.other_next_nonce)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_signed_ack %s", tal_hex(msg, msg));
	}

    peer->updates_received++;

    status_debug("partial signature combine req on update tx %s, settle tx %s, our_psig: %s,"
                " their_psig: %s, session %s, OLD our nonce %s, OLD their nonce %s",
             type_to_string(tmpctx, struct bitcoin_tx, peer->channel->eltoo_keyset.committed_update_tx),
             type_to_string(tmpctx, struct bitcoin_tx, peer->channel->eltoo_keyset.committed_settle_tx),
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.self_psig),
             type_to_string(tmpctx, struct partial_sig, &peer->channel->eltoo_keyset.last_committed_state.other_psig),
             type_to_string(tmpctx, struct musig_session, &peer->channel->eltoo_keyset.last_committed_state.session),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.self_next_nonce),
             type_to_string(tmpctx, struct nonce,
                    &peer->channel->eltoo_keyset.other_next_nonce));

    /* This ACK should be for the transaction we sent them in update_signed, used cached */
    comb_msg = towire_hsmd_combine_psig(tmpctx,
                            &channel_id,
                            &peer->channel->eltoo_keyset.last_committed_state.self_psig,
                            &peer->channel->eltoo_keyset.last_committed_state.other_psig,
                            &peer->channel->eltoo_keyset.last_committed_state.session,
                            peer->channel->eltoo_keyset.committed_update_tx,
                            peer->channel->eltoo_keyset.committed_settle_tx,
                            &peer->channel->eltoo_keyset.inner_pubkey);
    wire_sync_write(HSM_FD, take(comb_msg));
    comb_msg = wire_sync_read(tmpctx, HSM_FD);

	if (!fromwire_hsmd_combine_psig_reply(comb_msg, &update_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsmd_combine_psig_reply: %s",
			      tal_hex(tmpctx, comb_msg));

    /* Update looks good, move completed state over */
    peer->channel->eltoo_keyset.last_complete_state = peer->channel->eltoo_keyset.last_committed_state;

	/* We start timer even if this returns false: we might have delayed
	 * commit because we were waiting for this! */
	if (channel_rcvd_update_sign_ack(peer->channel, &changed_htlcs)) {
        /* FIXME I don't think this is possible? */
		status_debug("Commits outstanding after recv update_sign_ack");
	} else {
		status_debug("No commits outstanding after recv update_sign_ack");
    }

	/* Tell master about things this locks in(and final signature), wait for response */
	msg = got_signed_ack_msg(peer, peer->next_index,
			     changed_htlcs, &peer->channel->eltoo_keyset.last_complete_state.other_psig, &peer->channel->eltoo_keyset.last_complete_state.self_psig,
                 &peer->channel->eltoo_keyset.last_complete_state.session);
	master_wait_sync_reply(tmpctx, peer, take(msg),
			       WIRE_CHANNELD_GOT_ACK_REPLY);

	status_debug("update_signed_ack %s: update = %lu",
		     side_to_str(peer->channel->opener), peer->next_index - 1);

	/* We may now be quiescent on our side. */
	maybe_send_stfu(peer);

	start_update_timer(peer);
}

static void handle_peer_fulfill_htlc(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	struct preimage preimage;
	enum channel_remove_err e;
	struct htlc *h;

	if (!fromwire_update_fulfill_htlc(msg, &channel_id,
					  &id, &preimage)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fulfill_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fulfill_htlc(peer->channel, LOCAL, id, &preimage, &h);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		/* FIXME: We could send preimages to master immediately. */
		start_update_timer(peer);
		return;
	/* These shouldn't happen, because any offered HTLC (which would give
	 * us the preimage) should have timed out long before.  If we
	 * were to get preimages from other sources, this could happen. */
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fulfill_htlc: failed to fulfill %"
				 PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_fail_htlc(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	u8 *reason;
	struct htlc *htlc;
	struct failed_htlc *f;

	/* reason is not an onionreply because spec doesn't know about that */
	if (!fromwire_update_fail_htlc(msg, msg,
				       &channel_id, &id, &reason)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_htlc %s", tal_hex(msg, msg));
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, &htlc);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK: {
		htlc->failed = f = tal(htlc, struct failed_htlc);
		f->id = id;
		f->sha256_of_onion = NULL;
		f->onion = new_onionreply(f, take(reason));
		start_update_timer(peer);
		return;
	}
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_htlc: failed to remove %"
				 PRIu64 " error %s", id,
				 channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_fail_malformed_htlc(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 id;
	enum channel_remove_err e;
	struct sha256 sha256_of_onion;
	u16 failure_code;
	struct htlc *htlc;
	struct failed_htlc *f;

	if (!fromwire_update_fail_malformed_htlc(msg, &channel_id, &id,
						 &sha256_of_onion,
						 &failure_code)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_malformed_htlc %s",
				 tal_hex(msg, msg));
	}

	/* BOLT #2:
	 *
	 *   - if the `BADONION` bit in `failure_code` is not set for
	 *    `update_fail_malformed_htlc`:
	 *      - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!(failure_code & BADONION)) {
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_malformed_htlc failure code %u",
				 failure_code);
	}

	e = channel_fail_htlc(peer->channel, LOCAL, id, &htlc);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		htlc->failed = f = tal(htlc, struct failed_htlc);
		f->id = id;
		f->onion = NULL;
		f->sha256_of_onion = tal_dup(f, struct sha256, &sha256_of_onion);
		f->badonion = failure_code;
		start_update_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad update_fail_malformed_htlc: failed to remove %"
				 PRIu64 " error %s", id, channel_remove_err_name(e));
	}
	abort();
}

static void handle_peer_shutdown(struct eltoo_peer *peer, const u8 *shutdown)
{
	struct channel_id channel_id;
	u8 *scriptpubkey;

	/* Disable the channel. */
    /* FIXME Re-enable when gossip worked on
	send_channel_update(peer, ROUTING_FLAGS_DISABLED);
    */
    /* No OPT_SHUTDOWN_WRONG_FUNDING support for now */
	if (!fromwire_shutdown_eltoo(tmpctx, shutdown, &channel_id, &scriptpubkey,
			       &peer->channel->eltoo_keyset.other_next_nonce))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad shutdown %s", tal_hex(peer, shutdown));

	/* FIXME: We shouldn't let them initiate a shutdown while the
	 * channel is active (if we leased funds) */

	/* BOLT #2:
	 *
	 * - if both nodes advertised the `option_upfront_shutdown_script`
	 * feature, and the receiving node received a non-zero-length
	 * `shutdown_scriptpubkey` in `open_channel` or `accept_channel`, and
	 * that `shutdown_scriptpubkey` is not equal to `scriptpubkey`:
	 *    - MAY send a `warning`.
	 *    - MUST fail the connection.
	 */
	/* openingd only sets this if feature was negotiated at opening. */
	if (tal_count(peer->remote_upfront_shutdown_script)
	    && !memeq(scriptpubkey, tal_count(scriptpubkey),
		      peer->remote_upfront_shutdown_script,
		      tal_count(peer->remote_upfront_shutdown_script)))
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "scriptpubkey %s is not as agreed upfront (%s)",
				 tal_hex(peer, scriptpubkey),
				 tal_hex(peer, peer->remote_upfront_shutdown_script));


	/* Tell master: we don't have to wait because on reconnect other end
	 * will re-send anyway. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_got_shutdown_eltoo(NULL, scriptpubkey,
							  &peer->channel->eltoo_keyset.other_next_nonce)));

	peer->shutdown_sent[REMOTE] = true;
	/* BOLT #2:
	 *
	 * A receiving node:
	 * ...
	 * - once there are no outstanding updates on the peer, UNLESS
	 *   it has already sent a `shutdown`:
	 *    - MUST reply to a `shutdown` message with a `shutdown`
	 */
	if (!peer->shutdown_sent[LOCAL]) {
		peer->send_shutdown = true;
		start_update_timer(peer);
	}
	billboard_update(peer);
}

static void handle_unexpected_reestablish(struct eltoo_peer *peer, const u8 *msg)
{
	struct channel_id channel_id;
	u64 last_update_number;
    struct partial_sig their_last_psig;
    struct nonce their_next_nonce;

    /* No reestablish tlvs for now */
	if (!fromwire_channel_reestablish_eltoo
	    (msg, &channel_id,
         &last_update_number,
         &their_last_psig,
         &their_next_nonce)
		)
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "Bad channel_reestablish %s", tal_hex(peer, msg));

	/* Is it the same as the peer channel ID?  */
	if (channel_id_eq(&channel_id, &peer->channel_id)) {
		/* Log this event as unusual.  */
		status_unusual("Got repeated WIRE_CHANNEL_REESTABLISH "
			       "for channel %s, ignoring: %s",
			       type_to_string(tmpctx, struct channel_id,
					      &peer->channel_id),
			       tal_hex(tmpctx, msg));
		/* This is a mitigation for a known bug in some peer software
		 * that sometimes double-sends a reestablish message.
		 *
		 * Ideally we would send some kind of `error` message to the
		 * peer here, but if we sent an `error` message with the
		 * same channel ID it would cause the peer to drop the
		 * channel unilaterally.
		 * We also cannot use 0x00...00 because that means "all
		 * channels", so a proper peer (like C-lightning) will
		 * unilaterally close all channels we have with it, if we
		 * sent the 0x00...00 channel ID.
		 *
		 * So just do not send an error.
		 */
		return;
	}

	/* We only support one channel here, so the unexpected channel is the
	 * peer getting its wires crossed somewhere.
	 * Fail the channel they sent, not the channel we are actively
	 * handling.  */
	peer_failed_err(peer->pps, &channel_id,
			"Peer sent unexpected message %u, (%s) "
			"for nonexistent channel %s",
			WIRE_CHANNEL_REESTABLISH, "WIRE_CHANNEL_REESTABLISH",
			type_to_string(tmpctx, struct channel_id,
				       &channel_id));
}

/* Simplified Update machinery starts */

static bool allow_their_turn(struct eltoo_peer *peer)
{
    /* BOLT-option_simplified_update #2:
     *
     * - During this node's turn:
     *     - if it receives an update message:
     *       - if it has sent its own update:
     *         - MUST ignore the message
     *       - otherwise:
     *         - MUST reply with `yield` and process the message.
     */
    if (peer->turn == REMOTE)
        return true;

    if (peer->turn == LOCAL && peer->can_yield) {
        peer_write(peer->pps,
                  take(towire_yield(NULL,
                            &peer->channel_id)));
        /* BOLT-option_simplified_update #2:
         *  - MUST give up its turn when:
         *...
         *    - sending a `yield`
         */
        change_turn(peer, REMOTE);
        return true;
    }

    /* Sorry, we've already sent updates. */
    status_debug("Sorry, ignoring your message");
    return false;
}

static void handle_yield(struct eltoo_peer *peer, const u8 *yield)
{
    struct channel_id channel_id;

    if (!fromwire_yield(yield, &channel_id))
        peer_failed_warn(peer->pps, &peer->channel_id,
                 "Bad yield %s", tal_hex(peer, yield));

    /* is this lightningd's fault? */
    if (!channel_id_eq(&channel_id, &peer->channel_id)) {
        peer_failed_err(peer->pps, &channel_id,
                "Wrong yield channel_id: expected %s, got %s",
                type_to_string(tmpctx, struct channel_id,
                           &peer->channel_id),
                type_to_string(tmpctx, struct channel_id,
                           &channel_id));
    }

    /* Sanity check; change_turn assumes this has been caught */
    if (is_our_turn(peer)) {
        peer_failed_err(peer->pps, &channel_id,
                "yield when it's not your turn!");
    }

    /* BOLT-option_simplified_update #2:
     * - MUST accept its turn when:
     *     - receiving `revoke_and_ack`
     *     - receiving a `yield`
     */
    change_turn(peer, LOCAL);

    /* That will unplug the dequeue from update_queue */
}

static bool modifies_channel_tx_or_nop(enum peer_wire type)
{
    switch (type) {
    case WIRE_UPDATE_ADD_HTLC:
    case WIRE_UPDATE_FULFILL_HTLC:
    case WIRE_UPDATE_FAIL_HTLC:
    case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
    case WIRE_UPDATE_NOOP:
        return true;
    default:
        return false;
    };
}

/* Simplified Update machinery ends */

static void peer_in(struct eltoo_peer *peer, const u8 *msg)
{
	enum peer_wire type = fromwire_peektype(msg);

	if (handle_peer_error(peer->pps, &peer->channel_id, msg))
		return;

	/* Must get funding_locked before almost anything. */
	if (!peer->funding_locked[REMOTE]) {
		if (type != WIRE_FUNDING_LOCKED_ELTOO
		    && type != WIRE_SHUTDOWN
		    /* We expect these for v2 !! */
		    && type != WIRE_TX_SIGNATURES
		    /* lnd sends these early; it's harmless. */
		    && type != WIRE_UPDATE_FEE
		    && type != WIRE_ANNOUNCEMENT_SIGNATURES) {
			peer_failed_warn(peer->pps, &peer->channel_id,
					 "%s (%u) before funding locked eltoo",
					 peer_wire_name(type), type);
		}
	}

    /* Early return from messages we will not service.
        This will send off a yield message as
        appropriate when it's our turn and are willing
        to service it. */
    if (modifies_channel_tx_or_nop(type) && !allow_their_turn(peer)) {
        return;
    }

	switch (type) {
	case WIRE_FUNDING_LOCKED_ELTOO:
		handle_peer_funding_locked_eltoo(peer, msg);
		return;
	case WIRE_ANNOUNCEMENT_SIGNATURES:
        /* untouched */
		handle_peer_announcement_signatures(peer, msg);
		return;
	case WIRE_UPDATE_ADD_HTLC:
		handle_peer_add_htlc(peer, msg);
		return;
   	case WIRE_COMMITMENT_SIGNED:
        /* FIXME How should we handle illegal messages in general? */
		return;
	case WIRE_UPDATE_FEE:
        /* FIXME How should we handle illegal messages in general? */
		return;
    case WIRE_UPDATE_SIGNED:
        handle_peer_update_sig(peer, msg);
        return;
	case WIRE_UPDATE_BLOCKHEIGHT:
        /* FIXME How should we handle illegal messages in general? */
		return;
	case WIRE_REVOKE_AND_ACK:
        /* FIXME How should we handle illegal messages in general? */
		return;
	case WIRE_UPDATE_SIGNED_ACK:
		handle_peer_update_sig_ack(peer, msg);
		return;
	case WIRE_UPDATE_FULFILL_HTLC:
		handle_peer_fulfill_htlc(peer, msg);
		return;
	case WIRE_UPDATE_FAIL_HTLC:
		handle_peer_fail_htlc(peer, msg);
		return;
	case WIRE_UPDATE_FAIL_MALFORMED_HTLC:
		handle_peer_fail_malformed_htlc(peer, msg);
		return;
	case WIRE_SHUTDOWN:
		handle_peer_shutdown(peer, msg);
		return;
    case WIRE_UPDATE_NOOP:
		/* 
		 *- if it received `update_noop`:
		 * - MUST otherwise ignore the message
		 */
		return;
    case WIRE_YIELD:
		handle_yield(peer, msg);
        return;

#if EXPERIMENTAL_FEATURES
	case WIRE_STFU:
		handle_stfu(peer, msg);
		return;
#endif
	case WIRE_INIT:
	case WIRE_OPEN_CHANNEL:
	case WIRE_ACCEPT_CHANNEL:
	case WIRE_FUNDING_CREATED:
	case WIRE_FUNDING_SIGNED:
	case WIRE_CLOSING_SIGNED:
	case WIRE_TX_ADD_INPUT:
	case WIRE_TX_REMOVE_INPUT:
	case WIRE_TX_ADD_OUTPUT:
	case WIRE_TX_REMOVE_OUTPUT:
	case WIRE_TX_COMPLETE:
	case WIRE_OPEN_CHANNEL2:
	case WIRE_ACCEPT_CHANNEL2:
	case WIRE_TX_SIGNATURES:
	case WIRE_INIT_RBF:
	case WIRE_ACK_RBF:
	case WIRE_CHANNEL_REESTABLISH:
		break;
	case WIRE_CHANNEL_REESTABLISH_ELTOO:
		handle_unexpected_reestablish(peer, msg);
		return;

	/* These are all swallowed by connectd */
	case WIRE_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNEL_UPDATE:
	case WIRE_NODE_ANNOUNCEMENT:
	case WIRE_QUERY_SHORT_CHANNEL_IDS:
	case WIRE_QUERY_CHANNEL_RANGE:
	case WIRE_REPLY_CHANNEL_RANGE:
	case WIRE_GOSSIP_TIMESTAMP_FILTER:
	case WIRE_REPLY_SHORT_CHANNEL_IDS_END:
	case WIRE_PING:
	case WIRE_PONG:
	case WIRE_WARNING:
	case WIRE_ERROR:
	case WIRE_OBS2_ONION_MESSAGE:
	case WIRE_ONION_MESSAGE:
    case WIRE_FUNDING_LOCKED:
    /* Eltoo stuff */
    case WIRE_OPEN_CHANNEL_ELTOO:
    case WIRE_ACCEPT_CHANNEL_ELTOO:
    case WIRE_FUNDING_CREATED_ELTOO:
    case WIRE_FUNDING_SIGNED_ELTOO:
    case WIRE_SHUTDOWN_ELTOO:
    case WIRE_CLOSING_SIGNED_ELTOO:
    /* Eltoo stuff ends */

		abort();
	}

	peer_failed_warn(peer->pps, &peer->channel_id,
			 "Peer sent unknown message %u (%s)",
			 type, peer_wire_name(type));
}

static void send_fail_or_fulfill(struct eltoo_peer *peer, const struct htlc *h)
{
	u8 *msg;

	if (h->failed) {
		const struct failed_htlc *f = h->failed;
		if (f->sha256_of_onion) {
			msg = towire_update_fail_malformed_htlc(NULL,
								&peer->channel_id,
								h->id,
								f->sha256_of_onion,
								f->badonion);
		} else {
			msg = towire_update_fail_htlc(peer, &peer->channel_id, h->id,
						      f->onion->contents);
		}
	} else if (h->r) {
		msg = towire_update_fulfill_htlc(NULL, &peer->channel_id, h->id,
						 h->r);
	} else
		peer_failed_warn(peer->pps, &peer->channel_id,
				 "HTLC %"PRIu64" state %s not failed/fulfilled",
				 h->id, htlc_state_name(h->state));
	peer_write(peer->pps, take(msg));
	peer->can_yield = false;
}

/* FIXME Reconnect fun! Let's compile first. :) */
static void peer_reconnect(struct eltoo_peer *peer,
			   bool reestablish_only)
{
	/* Need to determine who's turn it is here */
}

/* ignores the funding_depth unless depth >= minimum_depth
 * (except to update billboard, and set peer->depth_togo). */
static void handle_funding_depth(struct eltoo_peer *peer, const u8 *msg)
{
	u32 depth;
	struct short_channel_id *scid;

	if (!fromwire_channeld_funding_depth(tmpctx,
					    msg,
					    &scid,
					    &depth))
		master_badmsg(WIRE_CHANNELD_FUNDING_DEPTH, msg);

	/* Too late, we're shutting down! */
	if (peer->shutdown_sent[LOCAL])
		return;

	if (depth < peer->channel->minimum_depth) {
		peer->depth_togo = peer->channel->minimum_depth - depth;

	} else {
		peer->depth_togo = 0;

		assert(scid);
		peer->short_channel_ids[LOCAL] = *scid;

		if (!peer->funding_locked[LOCAL]) {
			status_debug("funding_locked_eltoo"
				     " %"PRIu64"",
				     peer->next_index);
			msg = towire_funding_locked_eltoo(NULL,
						    &peer->channel_id);
			peer_write(peer->pps, take(msg));

			peer->funding_locked[LOCAL] = true;
		}

		peer->announce_depth_reached = (depth >= ANNOUNCE_MIN_DEPTH);

		/* Send temporary or final announcements */
		channel_announcement_negotiate(peer);
	}

	billboard_update(peer);
}

static const u8 *get_cupdate(const struct eltoo_peer *peer)
{
	/* Technically we only need to tell it the first time (unless it's
	 * changed).  But it's not that common. */
	wire_sync_write(MASTER_FD,
			take(towire_channeld_used_channel_update(NULL)));
	return peer->channel_update;
}

static void handle_offer_htlc(struct eltoo_peer *peer, const u8 *inmsg)
{
	u8 *msg;
	u32 cltv_expiry;
	struct amount_msat amount;
	struct sha256 payment_hash;
	u8 onion_routing_packet[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)];
	enum channel_add_err e;
	const u8 *failwiremsg;
	const char *failstr;
	struct pubkey *blinding;

	if (!peer->funding_locked[LOCAL] || !peer->funding_locked[REMOTE])
		status_failed(STATUS_FAIL_MASTER_IO,
			      "funding not locked for offer_htlc");

	if (!fromwire_channeld_offer_htlc(tmpctx, inmsg, &amount,
					 &cltv_expiry, &payment_hash,
					 onion_routing_packet, &blinding))
		master_badmsg(WIRE_CHANNELD_OFFER_HTLC, inmsg);

#if EXPERIMENTAL_FEATURES
	struct tlv_update_add_tlvs *tlvs;
	if (blinding) {
		tlvs = tlv_update_add_tlvs_new(tmpctx);
		tlvs->blinding = tal_dup(tlvs, struct pubkey, blinding);
	} else
		tlvs = NULL;
#endif

	e = eltoo_channel_add_htlc(peer->channel, LOCAL, peer->htlc_id,
			     amount, cltv_expiry, &payment_hash,
			     onion_routing_packet, take(blinding), NULL,
			     true);
	status_debug("Adding HTLC %"PRIu64" amount=%s cltv=%u gave %s",
		     peer->htlc_id,
		     type_to_string(tmpctx, struct amount_msat, &amount),
		     cltv_expiry,
		     channel_add_err_name(e));

	switch (e) {
	case CHANNEL_ERR_ADD_OK:
		/* Tell the peer. */
		msg = towire_update_add_htlc(NULL, &peer->channel_id,
					     peer->htlc_id, amount,
					     &payment_hash, cltv_expiry,
					     onion_routing_packet
#if EXPERIMENTAL_FEATURES
					     , tlvs
#endif
			);
		peer_write(peer->pps, take(msg));
		start_update_timer(peer);
		/* Tell the master. */
		msg = towire_channeld_offer_htlc_reply(NULL, peer->htlc_id,
						      0, "");
		wire_sync_write(MASTER_FD, take(msg));
		peer->htlc_id++;
		peer->can_yield = false;
		return;
	case CHANNEL_ERR_INVALID_EXPIRY:
		failwiremsg = towire_incorrect_cltv_expiry(inmsg, cltv_expiry, get_cupdate(peer));
		failstr = tal_fmt(inmsg, "Invalid cltv_expiry %u", cltv_expiry);
		goto failed;
	case CHANNEL_ERR_DUPLICATE:
	case CHANNEL_ERR_DUPLICATE_ID_DIFFERENT:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Duplicate HTLC %"PRIu64, peer->htlc_id);

	case CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED:
		failwiremsg = towire_required_node_feature_missing(inmsg);
		failstr = "Mini mode: maximum value exceeded";
		goto failed;
	/* FIXME: Fuzz the boundaries a bit to avoid probing? */
	case CHANNEL_ERR_CHANNEL_CAPACITY_EXCEEDED:
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = tal_fmt(inmsg, "Capacity exceeded");
		goto failed;
	case CHANNEL_ERR_HTLC_BELOW_MINIMUM:
		failwiremsg = towire_amount_below_minimum(inmsg, amount, get_cupdate(peer));
		failstr = tal_fmt(inmsg, "HTLC too small (%s minimum)",
				  type_to_string(tmpctx,
						 struct amount_msat,
						 &peer->channel->config[REMOTE].htlc_minimum));
		goto failed;
	case CHANNEL_ERR_TOO_MANY_HTLCS:
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = "Too many HTLCs";
		goto failed;
	case CHANNEL_ERR_DUST_FAILURE:
		/* BOLT-919 #2:
		 * - upon an outgoing HTLC:
		 *   - if a HTLC's `amount_msat` is inferior the counterparty's...
		 *   - SHOULD NOT send this HTLC
		 *   - SHOULD fail this HTLC if it's forwarded
		 */
		failwiremsg = towire_temporary_channel_failure(inmsg, get_cupdate(peer));
		failstr = "HTLC too dusty, allowed dust limit reached";
		goto failed;
	}
	/* Shouldn't return anything else! */
	abort();

failed:
	msg = towire_channeld_offer_htlc_reply(NULL, 0, failwiremsg, failstr);
	wire_sync_write(MASTER_FD, take(msg));
}

static void handle_config_channel(struct eltoo_peer *peer, const u8 *inmsg)
{
	u32 *base, *ppm;
	struct amount_msat *htlc_min, *htlc_max;
	bool changed;

	if (!fromwire_channeld_config_channel(inmsg, inmsg,
					      &base, &ppm,
					      &htlc_min,
					      &htlc_max))
		master_badmsg(WIRE_CHANNELD_CONFIG_CHANNEL, inmsg);

	/* only send channel updates if values actually changed */
	changed = false;
	if (base && *base != peer->fee_base) {
		peer->fee_base = *base;
		changed = true;
	}
	if (ppm && *ppm != peer->fee_per_satoshi) {
		peer->fee_per_satoshi = *ppm;
		changed = true;
	}
	if (htlc_min && !amount_msat_eq(*htlc_min, peer->htlc_minimum_msat)) {
		peer->htlc_minimum_msat = *htlc_min;
		changed = true;
	}
	if (htlc_max && !amount_msat_eq(*htlc_max, peer->htlc_maximum_msat)) {
		peer->htlc_maximum_msat = *htlc_max;
		changed = true;
	}

	if (changed)
		send_channel_update(peer, 0);
}


static void handle_preimage(struct eltoo_peer *peer, const u8 *inmsg)
{
	struct fulfilled_htlc fulfilled_htlc;
	struct htlc *h;

	if (!fromwire_channeld_fulfill_htlc(inmsg, &fulfilled_htlc))
		master_badmsg(WIRE_CHANNELD_FULFILL_HTLC, inmsg);

	switch (channel_fulfill_htlc(peer->channel, REMOTE,
				     fulfilled_htlc.id,
				     &fulfilled_htlc.payment_preimage,
				     &h)) {
	case CHANNEL_ERR_REMOVE_OK:
		send_fail_or_fulfill(peer, h);
		start_update_timer(peer);
		return;
	/* These shouldn't happen, because any offered HTLC (which would give
	 * us the preimage) should have timed out long before.  If we
	 * were to get preimages from other sources, this could happen. */
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "HTLC %"PRIu64" preimage failed",
			      fulfilled_htlc.id);
	}
	abort();
}

static void handle_fail(struct eltoo_peer *peer, const u8 *inmsg)
{
	struct failed_htlc *failed_htlc;
	enum channel_remove_err e;
	struct htlc *h;

	if (!fromwire_channeld_fail_htlc(inmsg, inmsg, &failed_htlc))
		master_badmsg(WIRE_CHANNELD_FAIL_HTLC, inmsg);

	e = channel_fail_htlc(peer->channel, REMOTE, failed_htlc->id, &h);
	switch (e) {
	case CHANNEL_ERR_REMOVE_OK:
		h->failed = tal_steal(h, failed_htlc);
		send_fail_or_fulfill(peer, h);
		start_update_timer(peer);
		return;
	case CHANNEL_ERR_NO_SUCH_ID:
	case CHANNEL_ERR_ALREADY_FULFILLED:
	case CHANNEL_ERR_HTLC_UNCOMMITTED:
	case CHANNEL_ERR_HTLC_NOT_IRREVOCABLE:
	case CHANNEL_ERR_BAD_PREIMAGE:
		status_failed(STATUS_FAIL_MASTER_IO,
			      "HTLC %"PRIu64" removal failed: %s",
			      failed_htlc->id,
			      channel_remove_err_name(e));
	}
	abort();
}

static void handle_shutdown_cmd(struct eltoo_peer *peer, const u8 *inmsg)
{
	u32 *final_index;
	struct ext_key *final_ext_key;
	u8 *local_shutdown_script;

	if (!fromwire_channeld_send_shutdown(peer, inmsg,
					     &final_index,
					     &final_ext_key,
					     &local_shutdown_script,
					     &peer->shutdown_wrong_funding))
		master_badmsg(WIRE_CHANNELD_SEND_SHUTDOWN, inmsg);

	tal_free(peer->final_index);
	peer->final_index = final_index;

	tal_free(peer->final_ext_key);
	peer->final_ext_key = final_ext_key;

	tal_free(peer->final_scriptpubkey);
	peer->final_scriptpubkey = local_shutdown_script;

	/* We can't send this until commit (if any) is done, so start timer. */
	peer->send_shutdown = true;
	start_update_timer(peer);
}

/* Lightningd tells us when channel_update has changed. */
static void handle_channel_update(struct eltoo_peer *peer, const u8 *msg)
{
	peer->channel_update = tal_free(peer->channel_update);
	if (!fromwire_channeld_channel_update(peer, msg, &peer->channel_update))
		master_badmsg(WIRE_CHANNELD_CHANNEL_UPDATE, msg);
}

static void handle_send_error(struct eltoo_peer *peer, const u8 *msg)
{
	char *reason;
	if (!fromwire_channeld_send_error(msg, msg, &reason))
		master_badmsg(WIRE_CHANNELD_SEND_ERROR, msg);
	status_debug("Send error reason: %s", reason);
	peer_write(peer->pps,
			  take(towire_errorfmt(NULL, &peer->channel_id,
					       "%s", reason)));

	wire_sync_write(MASTER_FD,
			take(towire_channeld_send_error_reply(NULL)));
}

#if DEVELOPER
static void handle_dev_reenable_commit(struct eltoo_peer *peer)
{
	peer->dev_disable_commit = tal_free(peer->dev_disable_commit);
	start_update_timer(peer);
	status_debug("dev_reenable_commit");
	wire_sync_write(MASTER_FD,
			take(towire_channeld_dev_reenable_commit_reply(NULL)));
}

static void handle_dev_memleak(struct eltoo_peer *peer, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	memtable = memleak_find_allocations(tmpctx, msg, msg);

	/* Now delete peer and things it has pointers to. */
	memleak_remove_region(memtable, peer, tal_bytelen(peer));

	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(MASTER_FD,
			 take(towire_channeld_dev_memleak_reply(NULL,
							       found_leak)));
}

/* Unused for now, just take message off wire */
static void handle_feerates(struct eltoo_peer *peer, const u8 *inmsg)
{
    u32 dummy_feerate;

    if (!fromwire_channeld_feerates(inmsg, &dummy_feerate,
                       &dummy_feerate,
                       &dummy_feerate,
                       &dummy_feerate))
        master_badmsg(WIRE_CHANNELD_FEERATES, inmsg);
}

/* Unused for now, just take message off wire */
static void handle_blockheight(struct eltoo_peer *peer, const u8 *inmsg)
{
    u32 blockheight;

    if (!fromwire_channeld_blockheight(inmsg, &blockheight))
        master_badmsg(WIRE_CHANNELD_BLOCKHEIGHT, inmsg);
}


#if EXPERIMENTAL_FEATURES
static void handle_dev_quiesce(struct eltoo_peer *peer, const u8 *msg)
{
	if (!fromwire_channeld_dev_quiesce(msg))
		master_badmsg(WIRE_CHANNELD_DEV_QUIESCE, msg);

	/* Don't do this twice. */
	if (peer->stfu)
		status_failed(STATUS_FAIL_MASTER_IO, "dev_quiesce already");

	peer->stfu = true;
	peer->stfu_initiator = LOCAL;
	maybe_send_stfu(peer);
}
#endif /* EXPERIMENTAL_FEATURES */
#endif /* DEVELOPER */

static void req_in(struct eltoo_peer *peer, const u8 *msg)
{
	enum channeld_wire t = fromwire_peektype(msg);

	switch (t) {
	case WIRE_CHANNELD_FUNDING_DEPTH:
		handle_funding_depth(peer, msg);
		return;
	case WIRE_CHANNELD_OFFER_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_offer_htlc(peer, msg);
		return;
	case WIRE_CHANNELD_FEERATES:
        handle_feerates(peer, msg);
		return;
	case WIRE_CHANNELD_BLOCKHEIGHT:
        handle_blockheight(peer, msg);
		return;
	case WIRE_CHANNELD_FULFILL_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_preimage(peer, msg);
		return;
	case WIRE_CHANNELD_FAIL_HTLC:
		if (handle_master_request_later(peer, msg))
			return;
		handle_fail(peer, msg);
		return;
	case WIRE_CHANNELD_CONFIG_CHANNEL:
		if (handle_master_request_later(peer, msg))
			return;
		handle_config_channel(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_SHUTDOWN:
		handle_shutdown_cmd(peer, msg);
		return;
	case WIRE_CHANNELD_SEND_ERROR:
		handle_send_error(peer, msg);
		return;
	case WIRE_CHANNELD_CHANNEL_UPDATE:
		handle_channel_update(peer, msg);
		return;
#if DEVELOPER
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
		handle_dev_reenable_commit(peer);
		return;
	case WIRE_CHANNELD_DEV_MEMLEAK:
		handle_dev_memleak(peer, msg);
		return;
	case WIRE_CHANNELD_DEV_QUIESCE:
#if EXPERIMENTAL_FEATURES
		handle_dev_quiesce(peer, msg);
		return;
#endif /* EXPERIMENTAL_FEATURES */
#else
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT:
	case WIRE_CHANNELD_DEV_MEMLEAK:
	case WIRE_CHANNELD_DEV_QUIESCE:
#endif /* DEVELOPER */
	case WIRE_CHANNELD_INIT:
	case WIRE_CHANNELD_OFFER_HTLC_REPLY:
	case WIRE_CHANNELD_SENDING_COMMITSIG:
	case WIRE_CHANNELD_GOT_COMMITSIG:
	case WIRE_CHANNELD_GOT_REVOKE:
	case WIRE_CHANNELD_SENDING_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_COMMITSIG_REPLY:
	case WIRE_CHANNELD_GOT_REVOKE_REPLY:
	case WIRE_CHANNELD_GOT_FUNDING_LOCKED:
	case WIRE_CHANNELD_GOT_ANNOUNCEMENT:
	case WIRE_CHANNELD_GOT_SHUTDOWN:
	case WIRE_CHANNELD_SHUTDOWN_COMPLETE:
	case WIRE_CHANNELD_DEV_REENABLE_COMMIT_REPLY:
	case WIRE_CHANNELD_FAIL_FALLEN_BEHIND:
	case WIRE_CHANNELD_DEV_MEMLEAK_REPLY:
	case WIRE_CHANNELD_SEND_ERROR_REPLY:
	case WIRE_CHANNELD_DEV_QUIESCE_REPLY:
	case WIRE_CHANNELD_UPGRADED:
	case WIRE_CHANNELD_USED_CHANNEL_UPDATE:
	case WIRE_CHANNELD_LOCAL_CHANNEL_UPDATE:
	case WIRE_CHANNELD_LOCAL_CHANNEL_ANNOUNCEMENT:
	case WIRE_CHANNELD_LOCAL_PRIVATE_CHANNEL:
    /* FIXME deal with these? */
    case WIRE_CHANNELD_GOT_FUNDING_LOCKED_ELTOO:
    case WIRE_CHANNELD_GOT_UPDATESIG:
    case WIRE_CHANNELD_GOT_UPDATESIG_REPLY:
    case WIRE_CHANNELD_GOT_ACK:
    case WIRE_CHANNELD_GOT_ACK_REPLY:
    case WIRE_CHANNELD_GOT_SHUTDOWN_ELTOO:
    case WIRE_CHANNELD_SENDING_UPDATESIG:
    case WIRE_CHANNELD_SENDING_UPDATESIG_REPLY:
    case WIRE_CHANNELD_INIT_ELTOO:
		break;
	}
	master_badmsg(-1, msg);
}

/* We do this synchronously. */
static void init_channel(struct eltoo_peer *peer)
{
	struct amount_sat funding_sats;
	struct amount_msat local_msat;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct pubkey settle_pubkey[NUM_SIDES];
    struct eltoo_sign complete_state;
    struct eltoo_sign committed_state;
    struct nonce nonces[NUM_SIDES];
	struct channel_config conf[NUM_SIDES];
	struct bitcoin_outpoint funding;
	enum side opener;
	struct existing_htlc **htlcs;
	bool reconnected;
	u32 final_index;
	struct ext_key final_ext_key;
	u8 *fwd_msg;
	const u8 *msg;
	u32 minimum_depth;
	secp256k1_ecdsa_signature *remote_ann_node_sig;
	secp256k1_ecdsa_signature *remote_ann_bitcoin_sig;
	bool reestablish_only;
	struct channel_type *channel_type;
	u32 *dev_disable_commit; /* Always NULL */
	bool dev_fast_gossip;
#if !DEVELOPER
	bool dev_fail_process_onionpacket; /* Ignored */
#endif

	assert(!(fcntl(MASTER_FD, F_GETFL) & O_NONBLOCK));

	msg = wire_sync_read(tmpctx, MASTER_FD);
	if (!fromwire_channeld_init_eltoo(peer, msg,
				    &chainparams,
				    &peer->our_features,
				    &peer->channel_id,
				    &funding,
				    &funding_sats,
				    &minimum_depth,
				    &conf[LOCAL], &conf[REMOTE],
				    &complete_state.other_psig,
				    &complete_state.self_psig,
				    &complete_state.session,
				    &committed_state.other_psig,
				    &committed_state.self_psig,
				    &committed_state.session,
                    &nonces[REMOTE],
                    &nonces[LOCAL],
				    &funding_pubkey[REMOTE],
                    &settle_pubkey[REMOTE],
				    &opener,
				    &peer->fee_base,
				    &peer->fee_per_satoshi,
				    &peer->htlc_minimum_msat,
				    &peer->htlc_maximum_msat,
				    &local_msat,
				    &funding_pubkey[LOCAL],
                    &settle_pubkey[LOCAL],
				    &peer->node_ids[LOCAL],
				    &peer->node_ids[REMOTE],
				    &peer->commit_msec,
				    &peer->cltv_delta,
				    &peer->next_index,
				    &peer->updates_received,
				    &peer->htlc_id,
				    &htlcs,
				    &peer->funding_locked[LOCAL],
				    &peer->funding_locked[REMOTE],
				    &peer->short_channel_ids[LOCAL],
				    &reconnected,
				    &peer->send_shutdown,
				    &peer->shutdown_sent[REMOTE],
				    &final_index,
				    &final_ext_key,
				    &peer->final_scriptpubkey,
				    &peer->channel_flags,
				    &fwd_msg,
				    &peer->announce_depth_reached,
				    &peer->their_features,
				    &peer->remote_upfront_shutdown_script,
				    &remote_ann_node_sig,
				    &remote_ann_bitcoin_sig,
				    &channel_type,
				    &dev_fast_gossip,
				    &dev_fail_process_onionpacket,
				    &dev_disable_commit,
				    &reestablish_only,
				    &peer->channel_update)) {
		master_badmsg(WIRE_CHANNELD_INIT, msg);
	}

	peer->final_index = tal_dup(peer, u32, &final_index);
	peer->final_ext_key = tal_dup(peer, struct ext_key, &final_ext_key);

#if DEVELOPER
	peer->dev_disable_commit = dev_disable_commit;
	peer->dev_fast_gossip = dev_fast_gossip;
#endif

	/* stdin == requests, 3 == peer */
	peer->pps = new_per_peer_state(peer);
	per_peer_state_set_fd(peer->pps, 3);

	status_debug("init %s: "
		     " next_idx = %"PRIu64
		     " updates_received = %"PRIu64,
		     side_to_str(opener),
		     peer->next_index,
		     peer->updates_received);

	if (remote_ann_node_sig && remote_ann_bitcoin_sig) {
		peer->announcement_node_sigs[REMOTE] = *remote_ann_node_sig;
		peer->announcement_bitcoin_sigs[REMOTE] = *remote_ann_bitcoin_sig;
		peer->have_sigs[REMOTE] = true;

		/* Before we store announcement into DB, we have made sure
		 * remote short_channel_id matched the local. Now we initial
		 * it directly!
		 */
		peer->short_channel_ids[REMOTE] = peer->short_channel_ids[LOCAL];
		tal_free(remote_ann_node_sig);
		tal_free(remote_ann_bitcoin_sig);
	}

	/* First commit is used for opening: if we've sent 0, we're on
	 * index 1. */
	assert(peer->next_index > 0);

	peer->channel = new_full_eltoo_channel(peer, &peer->channel_id,
					 &funding,
					 minimum_depth,
					 funding_sats,
					 local_msat,
					 &conf[LOCAL], &conf[REMOTE],
					 &funding_pubkey[LOCAL],
					 &funding_pubkey[REMOTE],
                     &settle_pubkey[LOCAL],
                     &settle_pubkey[REMOTE],
                     &complete_state,
                     &committed_state,
					 take(channel_type),
					 feature_offered(peer->their_features,
							 OPT_LARGE_CHANNELS),
					 opener);

    /* FIXME new_full_eltoo_channel should take the nonces... */
    peer->channel->eltoo_keyset.other_next_nonce = nonces[REMOTE];
    peer->channel->eltoo_keyset.self_next_nonce = nonces[LOCAL];

	if (!channel_force_htlcs(peer->channel,
			 cast_const2(const struct existing_htlc **, htlcs)))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Could not restore HTLCs");

	/* We don't need these any more, so free them. */
	tal_free(htlcs);

	peer->channel_direction = node_id_idx(&peer->node_ids[LOCAL],
					      &peer->node_ids[REMOTE]);

	/* from now we need keep watch over WIRE_CHANNELD_FUNDING_DEPTH */
	peer->depth_togo = minimum_depth;

	/* We don't send updates out of turn so this is always true */
	peer->can_yield = true;

	/* OK, now we can process peer messages. */
	if (reconnected)
		peer_reconnect(peer, reestablish_only);
	else {
		assert(!reestablish_only);
		peer->turn = 
			node_id_cmp(&(peer->node_ids[LOCAL]), &(peer->node_ids[REMOTE])) < 0 ? LOCAL : REMOTE;
	}

	/* If we have a messages to send, send them immediately */
	if (fwd_msg)
		peer_write(peer->pps, take(fwd_msg));

	/* Reenable channel */
	channel_announcement_negotiate(peer);

	billboard_update(peer);
}

int main(int argc, char *argv[])
{
	setup_locale();

	int i, nfds;
	fd_set fds_in, fds_out;
	struct eltoo_peer *peer;

	subdaemon_setup(argc, argv);

	status_setup_sync(MASTER_FD);

	peer = tal(NULL, struct eltoo_peer);
	timers_init(&peer->timers, time_mono());
	peer->commit_timer = NULL;
	peer->have_sigs[LOCAL] = peer->have_sigs[REMOTE] = false;
	peer->announce_depth_reached = false;
	peer->channel_local_active = false;
	peer->from_master = msg_queue_new(peer, true);
	peer->shutdown_sent[LOCAL] = false;
	peer->shutdown_wrong_funding = NULL;
	peer->last_update_timestamp = 0;
	peer->last_empty_commitment = 0;
#if EXPERIMENTAL_FEATURES
	peer->stfu = false;
	peer->stfu_sent[LOCAL] = peer->stfu_sent[REMOTE] = false;
	peer->update_queue = msg_queue_new(peer, false);
	/* peer->our_turn is decided in init_channel */
#endif

	/* We send these to HSM to get real signatures; don't have valgrind
	 * complain. */
	for (i = 0; i < NUM_SIDES; i++) {
		memset(&peer->announcement_node_sigs[i], 0,
		       sizeof(peer->announcement_node_sigs[i]));
		memset(&peer->announcement_bitcoin_sigs[i], 0,
		       sizeof(peer->announcement_bitcoin_sigs[i]));
	}

	/* Prepare the ecdh() function for use */
	ecdh_hsmd_setup(HSM_FD, status_failed);

	/* Read init_channel message sync. */
	init_channel(peer);

	FD_ZERO(&fds_in);
	FD_SET(MASTER_FD, &fds_in);
	FD_SET(peer->pps->peer_fd, &fds_in);

	FD_ZERO(&fds_out);
	FD_SET(peer->pps->peer_fd, &fds_out);
	nfds = peer->pps->peer_fd+1;

	while (!shutdown_complete(peer)) {
		struct timemono first;
		fd_set rfds = fds_in;
		struct timeval timeout, *tptr;
		struct timer *expired;
		const u8 *msg;
		struct timemono now = time_mono();

		/* Free any temporary allocations */
		clean_tmpctx();

		/* For simplicity, we process one event from master at a time. */
		msg = msg_dequeue(peer->from_master);
		if (msg) {
			status_debug("Now dealing with deferred %s",
				     channeld_wire_name(
					     fromwire_peektype(msg)));
			req_in(peer, msg);
			tal_free(msg);
			continue;
		}

        /* And one at a time from peers */
        if (!peer->stfu && is_our_turn(peer)
            && (msg = msg_dequeue(peer->update_queue))) {
            status_debug("Now dealing with deferred update %s",
                     channeld_wire_name(
                         fromwire_peektype(msg)));
            req_in(peer, msg);
            tal_free(msg);
            continue;
        } else if (msg_queue_length(peer->update_queue)) {
            status_debug("Ignoring deferred updates...");
        }

		expired = timers_expire(&peer->timers, now);
		if (expired) {
			timer_expired(expired);
			continue;
		}

		/* Might not be waiting for anything. */
		tptr = NULL;

		if (timer_earliest(&peer->timers, &first)) {
			timeout = timespec_to_timeval(
				timemono_between(first, now).ts);
			tptr = &timeout;
		}


        status_debug("***SELECT***");
		if (select(nfds, &rfds, NULL, NULL, tptr) < 0) {
			/* Signals OK, eg. SIGUSR1 */
			if (errno == EINTR)
				continue;
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "select failed: %s", strerror(errno));
		}
        status_debug("***UNSELECT***");

		if (FD_ISSET(MASTER_FD, &rfds)) {
			msg = wire_sync_read(tmpctx, MASTER_FD);

			if (!msg)
				status_failed(STATUS_FAIL_MASTER_IO,
					      "Can't read command: %s",
					      strerror(errno));
			status_debug("Dealing with %s",
				     channeld_wire_name(
					     fromwire_peektype(msg)));
			req_in(peer, msg);
		} else if (FD_ISSET(peer->pps->peer_fd, &rfds)) {
			/* This could take forever, but who cares? */
			msg = peer_read(tmpctx, peer->pps);
			peer_in(peer, msg);
		}
	}

	/* We only exit when shutdown is complete. */
	assert(shutdown_complete(peer));
	send_shutdown_complete(peer);
	daemon_shutdown();
	return 0;
}
