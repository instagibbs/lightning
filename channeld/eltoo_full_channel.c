#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/array_size/array_size.h>
#include <channeld/commit_tx.h>
#include <channeld/eltoo_full_channel.h>
#include <channeld/full_channel_error.h>
#include <channeld/settle_tx.h>
#include <common/blockheight_states.h>
#include <common/channel_config.h>
#include <common/features.h>
#include <common/fee_states.h>
#include <common/htlc_trim.h>
#include <common/htlc_tx.h>
#include <common/htlc_wire.h>
#include <common/keyset.h>
#include <common/memleak.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <common/update_tx.h>
#include <stdio.h>
  /* Needs to be at end, since it doesn't include its own hdrs */
  #include "full_channel_error_names_gen.h"

#if DEVELOPER
static void memleak_help_htlcmap(struct htable *memtable,
				 struct htlc_map *htlcs)
{
	memleak_remove_htable(memtable, &htlcs->raw);
}
#endif /* DEVELOPER */

/* This is a dangerous thing!  Because we apply HTLCs in many places
 * in bulk, we can temporarily go negative.  You must check balance_ok()
 * at the end! */
struct balance {
	s64 msat;
};

static void to_balance(struct balance *balance,
		       const struct amount_msat msat)
{
	balance->msat = msat.millisatoshis; /* Raw: balance */
	assert(balance->msat >= 0);
}

/* What does adding the HTLC do to the balance for this side (subtracts) */
static void balance_add_htlc(struct balance *balance,
			     const struct htlc *htlc,
			     enum side side)
{
	if (htlc_owner(htlc) == side)
		balance->msat -= htlc->amount.millisatoshis; /* Raw: balance */
}

/* What does removing the HTLC do to the balance for this side (adds) */
static void balance_remove_htlc(struct balance *balance,
				const struct htlc *htlc,
				enum side side)
{
	enum side paid_to;

	/* Fulfilled HTLCs are paid to recipient, otherwise returns to owner */
	if (htlc->r)
		paid_to = !htlc_owner(htlc);
	else
		paid_to = htlc_owner(htlc);

	if (side == paid_to)
		balance->msat += htlc->amount.millisatoshis; /* Raw: balance */
}

static bool balance_ok(const struct balance *balance,
		       struct amount_msat *msat)
	WARN_UNUSED_RESULT;

static bool balance_ok(const struct balance *balance,
		       struct amount_msat *msat)
{
	if (balance->msat < 0)
		return false;
	*msat = amount_msat(balance->msat);
	return true;
}

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
                 const struct partial_sig *self_psig,
                 const struct partial_sig *other_psig,
                 const struct musig_session *session,
				 const struct channel_type *type TAKES,
				 bool option_wumbo,
				 enum side opener)
{
	struct channel *channel = new_initial_eltoo_channel(ctx,
						      cid,
						      funding,
						      minimum_depth,
						      funding_sats,
						      local_msat,
						      local, remote,
						      local_funding_pubkey,
						      remote_funding_pubkey,
						      local_settle_pubkey,
						      remote_settle_pubkey,
                              self_psig,
                              other_psig,
                              session,
						      type,
						      option_wumbo,
						      opener);

	if (channel) {
		channel->htlcs = tal(channel, struct htlc_map);
		htlc_map_init(channel->htlcs);
		memleak_add_helper(channel->htlcs, memleak_help_htlcmap);
		tal_add_destructor(channel->htlcs, htlc_map_clear);
	}
	return channel;
}

static void htlc_arr_append(const struct htlc ***arr, const struct htlc *htlc)
{
	if (!arr)
		return;
	tal_arr_expand(arr, htlc);
}

static void dump_htlc(const struct htlc *htlc, const char *prefix)
{
	enum htlc_state remote_state;
    enum htlc_state state = htlc->state;

	if (htlc->state <= SENT_REMOVE_ACK)
		remote_state = state + 10;
	else
		remote_state = state - 10;

	status_debug("%s: HTLC %s %"PRIu64" = %s/%s %s",
		     prefix,
		     htlc_state_owner(state) == LOCAL ? "LOCAL" : "REMOTE",
		     htlc->id,
		     htlc_state_name(state),
		     htlc_state_name(remote_state),
		     htlc->r ? "FULFILLED" : htlc->failed ? "FAILED"
		     : "");
}

void dump_htlcs(const struct channel *channel, const char *prefix)
{
#ifdef SUPERVERBOSE
	struct htlc_map_iter it;
	const struct htlc *htlc;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		dump_htlc(htlc, prefix);
	}
#endif
}

/* Returns up to three arrays:
 * committed: HTLCs currently committed.
 * pending_removal: HTLCs pending removal (subset of committed)
 * pending_addition: HTLCs pending addition (no overlap with committed)
 *
 * Also returns number of HTLCs for other side.
 */
static size_t gather_htlcs(const tal_t *ctx,
			   const struct channel *channel,
			   enum side side,
			   const struct htlc ***committed,
			   const struct htlc ***pending_removal,
			   const struct htlc ***pending_addition)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;
	const int committed_flag = HTLC_FLAG(side, HTLC_F_COMMITTED);
	const int pending_flag = HTLC_FLAG(side, HTLC_F_PENDING);
	size_t num_other_side = 0;

	*committed = tal_arr(ctx, const struct htlc *, 0);
	if (pending_removal)
		*pending_removal = tal_arr(ctx, const struct htlc *, 0);
	if (pending_addition)
		*pending_addition = tal_arr(ctx, const struct htlc *, 0);

	if (!channel->htlcs)
		return num_other_side;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		if (eltoo_htlc_has(htlc, committed_flag)) {
#ifdef SUPERVERBOSE
			dump_htlc(htlc, "COMMITTED");
#endif
			htlc_arr_append(committed, htlc);
			if (eltoo_htlc_has(htlc, pending_flag)) {
#ifdef SUPERVERBOSE
				dump_htlc(htlc, "REMOVING");
#endif
				htlc_arr_append(pending_removal, htlc);
			} else if (htlc_owner(htlc) != side)
				num_other_side++;
		} else if (eltoo_htlc_has(htlc, pending_flag)) {
			htlc_arr_append(pending_addition, htlc);
#ifdef SUPERVERBOSE
			dump_htlc(htlc, "ADDING");
#endif
			if (htlc_owner(htlc) != side)
				num_other_side++;
		}
	}
	return num_other_side;
}

static bool sum_offered_msatoshis(struct amount_msat *total,
				  const struct htlc **htlcs,
				  enum side side)
{
	size_t i;

	*total = AMOUNT_MSAT(0);
	for (i = 0; i < tal_count(htlcs); i++) {
		if (htlc_owner(htlcs[i]) == side) {
			if (!amount_msat_add(total, *total, htlcs[i]->amount))
				return false;
		}
	}
	return true;
}

struct bitcoin_tx **eltoo_channel_txs(const tal_t *ctx,
                const struct htlc ***htlcmap,
                struct wally_tx_output *direct_outputs[NUM_SIDES],
                const struct channel *channel,
                u64 update_number,
                enum side side) /* FIXME remove */
{
    assert(side == LOCAL);
    struct bitcoin_tx **txs;
    const struct htlc **committed;

    /* Figure out what @side will already be committed to. */
    /* FIXME how does "side" work here? We're doing both sides. */
    gather_htlcs(ctx, channel, LOCAL, &committed, NULL, NULL);

    txs = tal_arr(ctx, struct bitcoin_tx *, 2);
    /* settle txn has finalized witness data, just needs prevout rebinding */
    txs[1] = settle_tx(
        ctx, &channel->funding,
        channel->funding_sats,
        channel->config[LOCAL].shared_delay,
        &channel->eltoo_keyset,
        channel->config[LOCAL].dust_limit, channel->view[LOCAL].owed[LOCAL],
        channel->view[LOCAL].owed[REMOTE], committed, htlcmap, direct_outputs,
        update_number);

    /* We only fill out witness data for update transactions for onchain events */
    txs[0] = unbound_update_tx(ctx,
        txs[1],
        channel->funding_sats,
        &channel->eltoo_keyset.inner_pubkey);

    /* FIXME We don't handle failure to construct transactions yet */
    assert(txs[0]);
    assert(txs[1]);

    /* Set the remote/local pubkeys on the update tx psbt FIXME add
      inner pubkey when possible */
    psbt_input_add_pubkey(txs[0]->psbt, 0,
                  &channel->eltoo_keyset.self_funding_key);
    psbt_input_add_pubkey(txs[0]->psbt, 0,
                  &channel->eltoo_keyset.other_funding_key);

    tal_free(committed);
    return txs;
}

static enum channel_add_err add_htlc(struct channel *channel,
				     enum htlc_state state,
				     u64 id,
				     struct amount_msat amount,
				     u32 cltv_expiry,
				     const struct sha256 *payment_hash,
				     const u8 routing[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
				     const struct pubkey *blinding TAKES,
				     struct htlc **htlcp,
				     bool enforce_aggregate_limits,
				     bool err_immediate_failures)
{
	struct htlc *htlc, *old;
	struct amount_msat msat_in_htlcs, committed_msat,
			   adding_msat, removing_msat, htlc_dust_amt;
	enum side sender = htlc_state_owner(state), recipient = !sender;
	const struct htlc **committed, **adding, **removing;
    size_t htlc_count;
    bool ok;

	htlc = tal(tmpctx, struct htlc);

	htlc->id = id;
	htlc->amount = amount;
	htlc->state = state;
	htlc->fail_immediate = false;

	htlc->rhash = *payment_hash;
	htlc->blinding = tal_dup_or_null(htlc, struct pubkey, blinding);
	htlc->failed = NULL;
	htlc->r = NULL;
	htlc->routing = tal_dup_arr(htlc, u8, routing, TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE), 0);

	/* FIXME: Change expiry to simple u32 */

	/* BOLT #2:
	 *
	 * A receiving node:
	 *...
	 *  - if sending node sets `cltv_expiry` to greater or equal to
	 *    500000000:
	 *    - SHOULD send a `warning` and close the connection, or send an
	 *      `error` and fail the channel.
	 */
	if (!blocks_to_abs_locktime(cltv_expiry, &htlc->expiry)) {
		return CHANNEL_ERR_INVALID_EXPIRY;
	}

	old = htlc_get(channel->htlcs, htlc->id, htlc_owner(htlc));
	if (old) {
		if (old->state != htlc->state
		    || !amount_msat_eq(old->amount, htlc->amount)
		    || old->expiry.locktime != htlc->expiry.locktime
		    || !sha256_eq(&old->rhash, &htlc->rhash))
			return CHANNEL_ERR_DUPLICATE_ID_DIFFERENT;
		else
			return CHANNEL_ERR_DUPLICATE;
	}

	/* BOLT #2:
	 *
	 * A receiving node:
	 *  - receiving an `amount_msat` equal to 0, OR less than its own
	 *    `htlc_minimum_msat`:
	 *        - SHOULD send a `warning` and close the connection, or send an
	 *        `error` and fail the channel.
	 */
	if (amount_msat_eq(htlc->amount, AMOUNT_MSAT(0))) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}
	if (amount_msat_less(htlc->amount, channel->config[recipient].htlc_minimum)) {
		return CHANNEL_ERR_HTLC_BELOW_MINIMUM;
	}

	/* FIXME: There used to be a requirement that we not send more than
	 * 2^32 msat, *but* only electrum enforced it.  Remove in next version:
	 *
	 * A sending node:
	 *...
	 * - for channels with `chain_hash` identifying the Bitcoin blockchain:
	 *    - MUST set the four most significant bytes of `amount_msat` to 0.
	 */
	if (sender == LOCAL
	    && amount_msat_greater(htlc->amount, chainparams->max_payment)
	    && !channel->option_wumbo) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* Figure out what receiver will already be committed to. */
	htlc_count = gather_htlcs(tmpctx, channel, recipient, &committed, &removing, &adding);
	htlc_arr_append(&adding, htlc);

	/* BOLT #2:
	 *
	 *   - if a sending node adds more than receiver `max_accepted_htlcs`
	 *     HTLCs to its local commitment transaction...
	 *         - SHOULD send a `warning` and close the connection, or send an
	 *         `error` and fail the channel.
	 */
	if (htlc_count + 1 > channel->config[recipient].max_accepted_htlcs) {
		return CHANNEL_ERR_TOO_MANY_HTLCS;
	}

	/* Also *we* should not add more htlc's we configured.  This
	 * mitigates attacks in which a peer can force the opener of
	 * the channel to pay unnecessary onchain fees during a fee
	 * spike with large commitment transactions.
	 */
	if (sender == LOCAL
	    && htlc_count + 1 > channel->config[LOCAL].max_accepted_htlcs) {
		return CHANNEL_ERR_TOO_MANY_HTLCS;
	}

	/* These cannot overflow with HTLC amount limitations, but
	 * maybe adding could later if they try to add a maximal HTLC. */
	if (!sum_offered_msatoshis(&committed_msat,
				   committed, htlc_owner(htlc))
	    || !sum_offered_msatoshis(&removing_msat,
				      removing, htlc_owner(htlc))
	    || !sum_offered_msatoshis(&adding_msat,
				      adding, htlc_owner(htlc))) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	if (!amount_msat_add(&msat_in_htlcs, committed_msat, adding_msat)
	    || !amount_msat_sub(&msat_in_htlcs, msat_in_htlcs, removing_msat)) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

	/* BOLT #2:
	 *
	 *   - if a sending node... adds more than receiver
	 *     `max_htlc_value_in_flight_msat` worth of offered HTLCs to its
	 *     local commitment transaction:
	 *     - SHOULD send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */

	/* We don't enforce this for channel_force_htlcs: some might already
	 * be fulfilled/failed */
	if (enforce_aggregate_limits
	    && amount_msat_greater(msat_in_htlcs,
				   channel->config[recipient].max_htlc_value_in_flight)) {
		return CHANNEL_ERR_MAX_HTLC_VALUE_EXCEEDED;
	}

    /* No fee "fun", just don't make relay dust */

	ok = amount_sat_to_msat(&htlc_dust_amt, channel->config[sender].dust_limit);
    /* Shouldn't happen? */
    assert(ok);

    assert(channel->config[sender].dust_limit.satoshis ==
        channel->config[!sender].dust_limit.satoshis);

    /* This really shouldn't happen unless you never want an HTLC... */
	if (amount_msat_greater(htlc_dust_amt,
				channel->config[LOCAL].max_dust_htlc_exposure_msat)) {
		htlc->fail_immediate = true;
		if (err_immediate_failures)
			return CHANNEL_ERR_DUST_FAILURE;
	}

	/* Also check the sender, as they'll eventually have the same
	 * constraint */
	dump_htlc(htlc, "NEW:");
	htlc_map_add(channel->htlcs, tal_steal(channel, htlc));
	if (htlcp)
		*htlcp = htlc;

	return CHANNEL_ERR_ADD_OK;
}

enum channel_add_err eltoo_channel_add_htlc(struct channel *channel,
				      enum side sender,
				      u64 id,
				      struct amount_msat amount,
				      u32 cltv_expiry,
				      const struct sha256 *payment_hash,
				      const u8 routing[TOTAL_PACKET_SIZE(ROUTING_INFO_SIZE)],
				      const struct pubkey *blinding TAKES,
				      struct htlc **htlcp,
				      bool err_immediate_failures)
{
    /* FIXME figure out HTLC state machine for eltoo */
	enum htlc_state state;

	if (sender == LOCAL)
		state = SENT_ADD_HTLC;
	else
		state = RCVD_ADD_HTLC;

	/* BOLT #2:
	 * - MUST increase the value of `id` by 1 for each successive offer.
	 */
	/* This is a weak (bit cheap) check: */
	if (htlc_get(channel->htlcs, id+1, sender))
		status_broken("Peer sent out-of-order HTLC ids (is that you, old c-lightning node?)");

	return add_htlc(channel, state, id, amount, cltv_expiry,
			payment_hash, routing, blinding,
			htlcp, true, err_immediate_failures);
}

struct htlc *eltoo_channel_get_htlc(struct channel *channel, enum side sender, u64 id)
{
	return eltoo_htlc_get(channel->htlcs, id, sender);
}

enum channel_remove_err channel_fulfill_htlc(struct channel *channel,
					     enum side owner,
					     u64 id,
					     const struct preimage *preimage,
					     struct htlc **htlcp)
{
	struct sha256 hash;
	struct htlc *htlc;

	htlc = eltoo_channel_get_htlc(channel, owner, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	if (htlc->r)
		return CHANNEL_ERR_ALREADY_FULFILLED;

	sha256(&hash, preimage, sizeof(*preimage));
	/* BOLT #2:
	 *
	 *  - if the `payment_preimage` value in `update_fulfill_htlc`
	 *  doesn't SHA256 hash to the corresponding HTLC `payment_hash`:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!sha256_eq(&hash, &htlc->rhash))
		return CHANNEL_ERR_BAD_PREIMAGE;

	htlc->r = tal_dup(htlc, struct preimage, preimage);

	/* BOLT #2:
	 *
	 *  - if the `id` does not correspond to an HTLC in its current
	 *    commitment transaction:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!eltoo_htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_unusual("channel_fulfill_htlc: %"PRIu64" in state %s, uncommitted",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_UNCOMMITTED;
	}

	/* We enforce a stricter check, forcing state machine to be linear,
	 * based on: */
	/* BOLT #2:
	 *
	 * A node:
	 *...
	 *  - until the corresponding HTLC is irrevocably committed in both
	 *    sides' commitment transactions:
	 *    - MUST NOT send an `update_fulfill_htlc`, `update_fail_htlc`, or
	 *      `update_fail_malformed_htlc`.
	 */
    /* RCVD_ADD_COMMIT == RCVD_ADD_UPDATE is irrevocable */
    /* FIXME really gotta think about these transitions.... */
	if (htlc->state == RCVD_ADD_ACK /* RCVD_ADD_REVOCATION */)
		htlc->state = RCVD_REMOVE_HTLC;
//	else if (htlc->state == SENT_ADD_ACK)
//		htlc->state = SENT_REMOVE_HTLC;
    else if (htlc->state == RCVD_ADD_UPDATE)
        htlc->state = SENT_REMOVE_HTLC;
    else if (htlc->state == SENT_ADD_UPDATE)
        htlc->state = RCVD_REMOVE_HTLC;
	else {
		status_unusual("channel_fulfill_htlc: %"PRIu64" in state %s, not irrevocable",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}

	dump_htlc(htlc, "FULFILL:");

	if (htlcp)
		*htlcp = htlc;

	return CHANNEL_ERR_REMOVE_OK;
}

enum channel_remove_err channel_fail_htlc(struct channel *channel,
					  enum side owner, u64 id,
					  struct htlc **htlcp)
{
	struct htlc *htlc;

	htlc = eltoo_channel_get_htlc(channel, owner, id);
	if (!htlc)
		return CHANNEL_ERR_NO_SUCH_ID;

	/* BOLT #2:
	 *
	 * A receiving node:
	 *   - if the `id` does not correspond to an HTLC in its current
	 *     commitment transaction:
	 *     - MUST send a `warning` and close the connection, or send an
	 *       `error` and fail the channel.
	 */
	if (!eltoo_htlc_has(htlc, HTLC_FLAG(!htlc_owner(htlc), HTLC_F_COMMITTED))) {
		status_unusual("channel_fail_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_UNCOMMITTED;
	}

	/* FIXME: Technically, they can fail this before we're committed to
	 * it.  This implies a non-linear state machine. */
	if (htlc->state == SENT_ADD_ACK)
		htlc->state = SENT_REMOVE_HTLC;
	else if (htlc->state == RCVD_ADD_ACK)
		htlc->state = RCVD_REMOVE_HTLC;
	else {
		status_unusual("channel_fail_htlc: %"PRIu64" in state %s",
			     htlc->id, htlc_state_name(htlc->state));
		return CHANNEL_ERR_HTLC_NOT_IRREVOCABLE;
	}

	dump_htlc(htlc, "FAIL:");
	if (htlcp)
		*htlcp = htlc;
	return CHANNEL_ERR_REMOVE_OK;
}

static void htlc_incstate(struct channel *channel,
			  struct htlc *htlc,
			  struct balance owed[NUM_SIDES])
{
	int preflags, postflags;
    enum side sidechanged = LOCAL;
	const int committed_f = HTLC_FLAG(sidechanged, HTLC_F_COMMITTED);
    /* We need to jump to real terminal state for eltoo, step 1(index 0) goes to 4 */
    int state_gap = (channel->config[LOCAL].is_eltoo && (htlc->state % 5 == 1)) ? 3 : 1;

	status_debug("htlc %"PRIu64": %s->%s", htlc->id,
		     htlc_state_name(htlc->state),
		     htlc_state_name(htlc->state+state_gap));

	preflags = eltoo_htlc_state_flags(htlc->state);
	postflags = eltoo_htlc_state_flags(htlc->state + state_gap);
	/* You can't change sides. */
	assert((preflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER))
	       == (postflags & (HTLC_LOCAL_F_OWNER|HTLC_REMOTE_F_OWNER)));

	htlc->state += state_gap;

	/* If we've added or removed, adjust balances. */
	if (!(preflags & committed_f) && (postflags & committed_f)) {
		status_debug("htlc added %s: local %"PRId64" remote %"PRId64,
			     side_to_str(sidechanged),
			     owed[LOCAL].msat, owed[REMOTE].msat);
		balance_add_htlc(&owed[LOCAL], htlc, LOCAL);
		balance_add_htlc(&owed[REMOTE], htlc, REMOTE);
		status_debug("-> local %"PRId64" remote %"PRId64,
			     owed[LOCAL].msat, owed[REMOTE].msat);
	} else if ((preflags & committed_f) && !(postflags & committed_f)) {
		status_debug("htlc added %s: local %"PRId64" remote %"PRId64,
			     side_to_str(sidechanged),
			     owed[LOCAL].msat, owed[REMOTE].msat);
		balance_remove_htlc(&owed[LOCAL], htlc, LOCAL);
		balance_remove_htlc(&owed[REMOTE], htlc, REMOTE);
		status_debug("-> local %"PRId64" remote %"PRId64,
			     owed[LOCAL].msat, owed[REMOTE].msat);
	}
}

/* Returns flags which were changed. */
static int change_htlcs(struct channel *channel,
			// FIXME not needed? enum side sidechanged,
			const enum htlc_state *htlc_states,
			size_t n_hstates,
			const struct htlc ***htlcs,
			const char *prefix)
{
	struct htlc_map_iter it;
	struct htlc *h;
	int cflags = 0;
	int i;
	struct balance owed[NUM_SIDES];

	for (i = 0; i < NUM_SIDES; i++)
		to_balance(&owed[i], channel->view[LOCAL].owed[i]);

	for (h = htlc_map_first(channel->htlcs, &it);
	     h;
	     h = htlc_map_next(channel->htlcs, &it)) {
		for (i = 0; i < n_hstates; i++) {
			if (h->state == htlc_states[i]) {
				htlc_incstate(channel, h, owed);
				dump_htlc(h, prefix);
                /* Adds to changed htlcs */
				htlc_arr_append(htlcs, h);
				cflags |= (eltoo_htlc_state_flags(htlc_states[i])
					   ^ eltoo_htlc_state_flags(h->state));
			}
		}
	}

	for (i = 0; i < NUM_SIDES; i++) {
		if (!balance_ok(&owed[i], &channel->view[LOCAL].owed[i])) {
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s: %s balance underflow: %s -> %"PRId64,
				      side_to_str(LOCAL),
				      side_to_str(i),
				      type_to_string(tmpctx, struct amount_msat,
						     &channel->view[LOCAL].owed[i]),
				      owed[i].msat);
		}
	}

	return cflags;
}

bool channel_sending_update(struct channel *channel,
			    const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states_to_inc[] = { SENT_ADD_HTLC,
					   SENT_REMOVE_HTLC };
	status_debug("Trying update");

	change = change_htlcs(channel, states_to_inc, ARRAY_SIZE(states_to_inc),
			      htlcs, "sending_update");
	if (!change)
		return false;

	return true;
}

bool channel_rcvd_update(struct channel *channel, const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = {RCVD_REMOVE_HTLC,
					   RCVD_ADD_HTLC};

	status_debug("Received Update");
	change = change_htlcs(channel, states, ARRAY_SIZE(states),
			      htlcs, "rcvd_update");
	if (!change)
		return false;
	return true;
}

/*
bool channel_sending_sign_ack(struct channel *channel, const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = {RCVD_REMOVE_UPDATE,
					   RCVD_ADD_UPDATE};

	status_debug("Sending Signed ACK");
	change = change_htlcs(channel, states, ARRAY_SIZE(states),
			      htlcs, "sending_sign_ack");
	if (!change)
		return false;
}
*/	

bool channel_rcvd_update_sign_ack(struct channel *channel,
				 const struct htlc ***htlcs)
{
	int change;
	const enum htlc_state states[] = { SENT_ADD_UPDATE,
					   SENT_REMOVE_UPDATE };

	status_debug("Received update_sign_ack");
	change = change_htlcs(channel, states, ARRAY_SIZE(states),
			      htlcs, "rcvd_update_sign_ack");

	/* FIXME what should this be? ... Their ack can queue changes on our side. */
	return (change & HTLC_LOCAL_F_PENDING);
}

size_t num_channel_htlcs(const struct channel *channel)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;
	size_t n = 0;

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		/* FIXME: Clean these out! */
		if (!htlc_is_dead(htlc))
			n++;
	}
	return n;
}

static bool adjust_balance(struct balance view_owed[NUM_SIDES][NUM_SIDES],
			   struct htlc *htlc)
{
	enum side side;

	for (side = 0; side < NUM_SIDES; side++) {
		/* Did it ever add it? */
		if (!eltoo_htlc_has(htlc, HTLC_FLAG(side, HTLC_F_WAS_COMMITTED)))
			continue;

		/* Add it. */
		balance_add_htlc(&view_owed[side][LOCAL], htlc, LOCAL);
		balance_add_htlc(&view_owed[side][REMOTE], htlc, REMOTE);

		/* If it is no longer committed, remove it (depending
		 * on fail || fulfill). */
		if (eltoo_htlc_has(htlc, HTLC_FLAG(side, HTLC_F_COMMITTED)))
			continue;

		if (!htlc->failed && !htlc->r) {
			status_broken("%s HTLC %"PRIu64
				      " %s neither fail nor fulfill?",
				      htlc_state_owner(htlc->state) == LOCAL
				      ? "out" : "in",
				      htlc->id,
				      htlc_state_name(htlc->state));
			return false;
		}
		balance_remove_htlc(&view_owed[side][LOCAL], htlc, LOCAL);
		balance_remove_htlc(&view_owed[side][REMOTE], htlc, REMOTE);
	}
	return true;
}

bool pending_updates(const struct channel *channel,
		     enum side side,
		     bool uncommitted_ok)
{
	struct htlc_map_iter it;
	const struct htlc *htlc;

    /* No blockheight updates for eltoo for now, continue */

	for (htlc = htlc_map_first(channel->htlcs, &it);
	     htlc;
	     htlc = htlc_map_next(channel->htlcs, &it)) {
		int flags = eltoo_htlc_state_flags(htlc->state);

		/* If it's still being added, its owner added it. */
		if (flags & HTLC_ADDING) {
			/* It might be OK if it's added, but not committed */
			if (uncommitted_ok
			    && (flags & HTLC_FLAG(!side, HTLC_F_PENDING)))
				continue;
			if (htlc_owner(htlc) == side)
				return true;
		/* If it's being removed, non-owner removed it */
		} else if (eltoo_htlc_state_flags(htlc->state) & HTLC_REMOVING) {
			/* It might be OK if it's removed, but not committed */
			if (uncommitted_ok
			    && (flags & HTLC_FLAG(!side, HTLC_F_PENDING)))
				continue;
			if (htlc_owner(htlc) != side)
				return true;
		}
	}

	return false;
}

bool channel_force_htlcs(struct channel *channel,
			 const struct existing_htlc **htlcs)
{
	struct balance view_owed[NUM_SIDES][NUM_SIDES];

	/* You'd think, since we traverse HTLCs in ID order, this would never
	 * go negative.  But this ignores the fact that HTLCs ids from each
	 * side have no correlation with each other.  Copy into struct balance,
	 * to allow transient underflow. */
	for (int view = 0; view < NUM_SIDES; view++) {
		for (int side = 0; side < NUM_SIDES; side++) {
			to_balance(&view_owed[view][side],
				   channel->view[view].owed[side]);
		}
	}

	for (size_t i = 0; i < tal_count(htlcs); i++) {
		enum channel_add_err e;
		struct htlc *htlc;

		status_debug("Restoring HTLC %zu/%zu:"
			     " id=%"PRIu64" amount=%s cltv=%u"
			     " payment_hash=%s %s",
			     i, tal_count(htlcs),
			     htlcs[i]->id,
			     type_to_string(tmpctx, struct amount_msat,
					    &htlcs[i]->amount),
			     htlcs[i]->cltv_expiry,
			     type_to_string(tmpctx, struct sha256,
					    &htlcs[i]->payment_hash),
			     htlcs[i]->payment_preimage ? "(have preimage)"
			     : htlcs[i]->failed ? "(failed)" : "");

		e = add_htlc(channel, htlcs[i]->state,
			     htlcs[i]->id, htlcs[i]->amount,
			     htlcs[i]->cltv_expiry,
			     &htlcs[i]->payment_hash,
			     htlcs[i]->onion_routing_packet,
			     htlcs[i]->blinding,
			     &htlc, false, false);
		if (e != CHANNEL_ERR_ADD_OK) {
			status_broken("%s HTLC %"PRIu64" failed error %u",
				     htlc_state_owner(htlcs[i]->state) == LOCAL
				     ? "out" : "in", htlcs[i]->id, e);
			return false;
		}
		if (htlcs[i]->payment_preimage)
			htlc->r = tal_dup(htlc, struct preimage,
					  htlcs[i]->payment_preimage);
		if (htlcs[i]->failed)
			htlc->failed = tal_steal(htlc, htlcs[i]->failed);

		if (!adjust_balance(view_owed, htlc))
			return false;
	}

	/* Convert back and check */
	for (int view = 0; view < NUM_SIDES; view++) {
		for (int side = 0; side < NUM_SIDES; side++) {
			if (!balance_ok(&view_owed[view][side],
					&channel->view[view].owed[side])) {
				status_broken("view %s[%s] balance underflow:"
					      " %"PRId64,
					      side_to_str(view),
					      side_to_str(side),
					      view_owed[view][side].msat);
				return false;
			}
		}
	}

	return true;
}

const char *channel_add_err_name(enum channel_add_err e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	for (size_t i = 0; enum_channel_add_err_names[i].name; i++) {
		if (enum_channel_add_err_names[i].v == e)
			return enum_channel_add_err_names[i].name;
	}
	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}

const char *channel_remove_err_name(enum channel_remove_err e)
{
	static char invalidbuf[sizeof("INVALID ") + STR_MAX_CHARS(e)];

	for (size_t i = 0; enum_channel_remove_err_names[i].name; i++) {
		if (enum_channel_remove_err_names[i].v == e)
			return enum_channel_remove_err_names[i].name;
	}
	snprintf(invalidbuf, sizeof(invalidbuf), "INVALID %i", e);
	return invalidbuf;
}
