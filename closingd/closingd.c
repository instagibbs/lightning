#include "config.h"
#include <bitcoin/script.h>
#include <ccan/cast/cast.h>
#include <ccan/tal/str/str.h>
#include <closingd/closingd_wiregen.h>
#include <common/close_tx.h>
#include <common/closing_fee.h>
#include <common/memleak.h>
#include <common/peer_billboard.h>
#include <common/peer_failed.h>
#include <common/peer_io.h>
#include <common/per_peer_state.h>
#include <common/read_peer_msg.h>
#include <common/shutdown_scriptpubkey.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/utils.h>
#include <errno.h>
#include <hsmd/hsmd_wiregen.h>
#include <inttypes.h>
#include <stdio.h>
#include <unistd.h>
#include <wire/peer_wire.h>
#include <wire/wire_sync.h>

/* Sequence number for simple close: allows locktime, signals RBF */
#define SIMPLE_CLOSE_SEQUENCE 0xFFFFFFFD

/* stdin == requests, 3 == peer, 4 = hsmd */
#define REQ_FD STDIN_FILENO
#define HSM_FD 4

static void notify(enum log_level level, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	wire_sync_write(REQ_FD,
			take(towire_closingd_notification(NULL,
							  level,
							  tal_vfmt(tmpctx, fmt,
								   ap))));

	va_end(ap);
}

static struct bitcoin_tx *close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   struct per_peer_state *pps,
				   const struct channel_id *channel_id,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   u8 *scriptpubkey[NUM_SIDES],
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   const u8 *funding_wscript,
				   const struct amount_sat out[NUM_SIDES],
				   enum side opener,
				   struct amount_sat fee,
				   struct amount_sat dust_limit,
				   const struct bitcoin_outpoint *wrong_funding)
{
	struct bitcoin_tx *tx;
	struct amount_sat out_minus_fee[NUM_SIDES];

	out_minus_fee[LOCAL] = out[LOCAL];
	out_minus_fee[REMOTE] = out[REMOTE];
	if (!amount_sat_sub(&out_minus_fee[opener], out[opener], fee))
		peer_failed_warn(pps, channel_id,
				 "Funder cannot afford fee %s (%s and %s)",
				 fmt_amount_sat(tmpctx, fee),
				 fmt_amount_sat(tmpctx, out[LOCAL]),
				 fmt_amount_sat(tmpctx, out[REMOTE]));

	status_debug("Making close tx at = %s/%s fee %s",
		     fmt_amount_sat(tmpctx, out[LOCAL]),
		     fmt_amount_sat(tmpctx, out[REMOTE]),
		     fmt_amount_sat(tmpctx, fee));

	/* FIXME: We need to allow this! */
	tx = create_close_tx(ctx,
			     chainparams,
			     local_wallet_index, local_wallet_ext_key,
			     scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_wscript,
			     funding,
			     funding_sats,
			     out_minus_fee[LOCAL],
			     out_minus_fee[REMOTE],
			     dust_limit);
	if (!tx)
		peer_failed_err(pps, channel_id,
				"Both outputs below dust limit:"
				" funding = %s"
				" fee = %s"
				" dust_limit = %s"
				" LOCAL = %s"
				" REMOTE = %s",
				fmt_amount_sat(tmpctx, funding_sats),
				fmt_amount_sat(tmpctx, fee),
				fmt_amount_sat(tmpctx, dust_limit),
				fmt_amount_sat(tmpctx, out[LOCAL]),
				fmt_amount_sat(tmpctx, out[REMOTE]));

	if (wrong_funding)
		bitcoin_tx_input_set_outpoint(tx, 0, wrong_funding);

	return tx;
}

/* Handle random messages we might get, returning the first non-handled one. */
static u8 *closing_read_peer_msg(const tal_t *ctx,
				 struct per_peer_state *pps)
{
	for (;;) {
		u8 *msg;

		clean_tmpctx();
		msg = peer_read(ctx, pps);
		if (!handle_peer_error_or_warning(pps, msg))
			return msg;
	}
}

static void send_offer(struct per_peer_state *pps,
		       const struct chainparams *chainparams,
		       const struct channel_id *channel_id,
		       const struct pubkey *funding_pubkey,
		       const u8 *funding_wscript,
		       u32 *local_wallet_index,
		       const struct ext_key *local_wallet_ext_key,
		       u8 *scriptpubkey[NUM_SIDES],
		       const struct bitcoin_outpoint *funding,
		       struct amount_sat funding_sats,
		       const struct amount_sat out[NUM_SIDES],
		       enum side opener,
		       struct amount_sat our_dust_limit,
		       struct amount_sat fee_to_offer,
		       const struct bitcoin_outpoint *wrong_funding,
		       const struct tlv_closing_signed_tlvs_fee_range *tlv_fees)
{
	struct bitcoin_tx *tx;
	struct bitcoin_signature our_sig;
	struct tlv_closing_signed_tlvs *close_tlvs;
	u8 *msg;

	/* BOLT #2:
	 *
	 *   - MUST set `signature` to the Bitcoin signature of the close
	 *     transaction, as specified in [BOLT
	 *     #3](03-transactions.md#closing-transaction).
	 */
	tx = close_tx(tmpctx, chainparams, pps, channel_id,
		      local_wallet_index,
		      local_wallet_ext_key,
		      scriptpubkey,
		      funding,
		      funding_sats,
		      funding_wscript,
		      out,
		      opener, fee_to_offer, our_dust_limit,
		      wrong_funding);

	/* BOLT #3:
	 *
	 * ## Legacy Closing Transaction
	 *...
	 * Each node offering a signature... MAY eliminate its
	 * own output.
	 */
	/* (We don't do this). */
	wire_sync_write(HSM_FD,
			take(towire_hsmd_sign_mutual_close_tx(NULL,
							     tx,
							     &funding_pubkey[REMOTE])));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &our_sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsm_sign_mutual_close_tx reply %s",
			      tal_hex(tmpctx, msg));

	status_debug("sending fee offer %s",
		     fmt_amount_sat(tmpctx, fee_to_offer));

	/* Add the new close_tlvs with our fee range */
	if (tlv_fees) {
		close_tlvs = tlv_closing_signed_tlvs_new(msg);
		close_tlvs->fee_range
			= cast_const(struct tlv_closing_signed_tlvs_fee_range *,
				     tlv_fees);
		notify(LOG_INFORM, "Sending closing fee offer %s, with range %s-%s",
		       fmt_amount_sat(tmpctx, fee_to_offer),
		       fmt_amount_sat(tmpctx, tlv_fees->min_fee_satoshis),
		       fmt_amount_sat(tmpctx, tlv_fees->max_fee_satoshis));
	} else
		close_tlvs = NULL;

	assert(our_sig.sighash_type == SIGHASH_ALL);
	msg = towire_closing_signed(NULL, channel_id, fee_to_offer, &our_sig.s,
				    close_tlvs);

	peer_write(pps, take(msg));
}

static void tell_master_their_offer(const struct bitcoin_signature *their_sig,
				    const struct bitcoin_tx *tx,
				    struct bitcoin_txid *tx_id)
{
	u8 *msg = towire_closingd_received_signature(NULL, their_sig, tx);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Writing received to master: %s",
			      strerror(errno));

	/* Wait for master to ack, to make sure it's in db. */
	msg = wire_sync_read(NULL, REQ_FD);
	if (!fromwire_closingd_received_signature_reply(msg, tx_id))
		master_badmsg(WIRE_CLOSINGD_RECEIVED_SIGNATURE_REPLY, msg);
	tal_free(msg);
}

/* Returns fee they offered. */
static struct amount_sat
receive_offer(struct per_peer_state *pps,
	      const struct chainparams *chainparams,
	      const struct channel_id *channel_id,
	      const struct pubkey *funding_pubkey,
	      const u8 *funding_wscript,
	      u32 *local_wallet_index,
	      const struct ext_key *local_wallet_ext_key,
	      u8 *scriptpubkey[NUM_SIDES],
	      const struct bitcoin_outpoint *funding,
	      struct amount_sat funding_sats,
	      const struct amount_sat out[NUM_SIDES],
	      enum side opener,
	      struct amount_sat our_dust_limit,
	      struct amount_sat min_fee_to_accept,
	      const struct bitcoin_outpoint *wrong_funding,
	      struct bitcoin_txid *closing_txid,
	      struct tlv_closing_signed_tlvs_fee_range **tlv_fees)
{
	u8 *msg;
	struct channel_id their_channel_id;
	struct amount_sat received_fee;
	struct bitcoin_signature their_sig;
	struct bitcoin_tx *tx;
	struct tlv_closing_signed_tlvs *close_tlvs;

	/* Wait for them to say something interesting */
	do {
		msg = closing_read_peer_msg(tmpctx, pps);

		/* BOLT #2:
		 *
		 *  - upon reconnection:
		 *     - MUST ignore any redundant `channel_ready` it receives.
		 */
		/* This should only happen if we've made no commitments, but
		 * we don't have to check that: it's their problem. */
		if (fromwire_peektype(msg) == WIRE_CHANNEL_READY)
			msg = tal_free(msg);
		/* BOLT #2:
		 *     - if it has sent a previous `shutdown`:
		 *       - MUST retransmit `shutdown`.
		 */
		else if (fromwire_peektype(msg) == WIRE_SHUTDOWN)
			msg = tal_free(msg);
		/* We can get announcement signatures: too late! */
		else if (fromwire_peektype(msg) == WIRE_ANNOUNCEMENT_SIGNATURES)
			msg = tal_free(msg);
	} while (!msg);

	their_sig.sighash_type = SIGHASH_ALL;
	if (!fromwire_closing_signed(msg, msg, &their_channel_id,
				     &received_fee, &their_sig.s,
				     &close_tlvs))
		peer_failed_warn(pps, channel_id,
				 "Expected closing_signed: %s",
				 tal_hex(tmpctx, msg));

	/* BOLT #2:
	 *
	 * The receiving node:
	 *   - if the `signature` is not valid for either variant of closing transaction
	 *   specified in [BOLT #3](03-transactions.md#closing-transaction)
	 *   OR non-compliant with LOW-S-standard rule...:
	 *     - MUST send a `warning` and close the connection, or send an
	 *	 `error` and fail the channel.
	 */
	tx = close_tx(tmpctx, chainparams, pps, channel_id,
		      local_wallet_index,
		      local_wallet_ext_key,
		      scriptpubkey,
		      funding,
		      funding_sats,
		      funding_wscript,
		      out, opener, received_fee, our_dust_limit,
		      wrong_funding);

	if (!check_tx_sig(tx, 0, NULL, funding_wscript,
			  &funding_pubkey[REMOTE], &their_sig)) {
		/* Trim it by reducing their output to minimum */
		struct bitcoin_tx *trimmed;
		struct amount_sat trimming_out[NUM_SIDES];

		if (opener == REMOTE)
			trimming_out[REMOTE] = received_fee;
		else
			trimming_out[REMOTE] = AMOUNT_SAT(0);
		trimming_out[LOCAL] = out[LOCAL];

		/* BOLT #3:
		 *
		 * Each node offering a signature:
		 *   - MUST round each output down to whole satoshis.
		 *   - MUST subtract the fee given by `fee_satoshis` from the
		 *     output to the funder.
		 *   - MUST remove any output below its own
		 *    `dust_limit_satoshis`.
		 *   - MAY eliminate its own output.
		 */
		trimmed = close_tx(tmpctx, chainparams, pps, channel_id,
				   local_wallet_index,
				   local_wallet_ext_key,
				   scriptpubkey,
				   funding,
				   funding_sats,
				   funding_wscript,
				   trimming_out,
				   opener, received_fee, our_dust_limit,
				   wrong_funding);
		if (!trimmed
		    || !check_tx_sig(trimmed, 0, NULL, funding_wscript,
				     &funding_pubkey[REMOTE], &their_sig)) {
			peer_failed_warn(pps, channel_id,
					 "Bad closing_signed signature for"
					 " %s (and trimmed version %s)",
					 fmt_bitcoin_tx(tmpctx,
							tx),
					 trimmed ?
					 fmt_bitcoin_tx(tmpctx,
							trimmed)
					 : "NONE");
		}
		tx = trimmed;
	}

	status_debug("Received fee offer %s",
		     fmt_amount_sat(tmpctx, received_fee));

	if (tlv_fees) {
		if (close_tlvs) {
			*tlv_fees = tal_steal(tlv_fees, close_tlvs->fee_range);
		} else {
			*tlv_fees = NULL;
		}
	}

	if (close_tlvs && close_tlvs->fee_range) {
		notify(LOG_INFORM, "Received closing fee offer %s, with range %s-%s",
		       fmt_amount_sat(tmpctx, received_fee),
		       fmt_amount_sat(tmpctx,
				      close_tlvs->fee_range->min_fee_satoshis),
		       fmt_amount_sat(tmpctx,
				      close_tlvs->fee_range->max_fee_satoshis));
	} else {
		notify(LOG_INFORM, "Received closing fee offer %s, without range",
		       fmt_amount_sat(tmpctx, received_fee));
	}

	/* Master sorts out what is best offer, we just tell it any above min */
	if (amount_sat_greater_eq(received_fee, min_fee_to_accept)) {
		status_debug("...offer is reasonable");
		tell_master_their_offer(&their_sig, tx, closing_txid);
	}

	return received_fee;
}

struct feerange {
	enum side higher_side;
	struct amount_sat min, max;
};

static void init_feerange(struct feerange *feerange,
			  struct amount_sat commitment_fee,
			  const struct amount_sat offer[NUM_SIDES])
{
	feerange->min = AMOUNT_SAT(0);

	/* FIXME: BOLT 2 previously said that we have to set it to less than
	 * the final commit fee: we do this for now, still:
	 *
	 *  - MUST set `fee_satoshis` less than or equal to the base
         *    fee of the final commitment transaction, as calculated
         *    in [BOLT #3](03-transactions.md#fee-calculation).
	 */
	feerange->max = commitment_fee;

	if (amount_sat_greater(offer[LOCAL], offer[REMOTE]))
		feerange->higher_side = LOCAL;
	else
		feerange->higher_side = REMOTE;

	status_debug("Feerange init %s-%s, %s higher",
		     fmt_amount_sat(tmpctx, feerange->min),
		     fmt_amount_sat(tmpctx, feerange->max),
		     feerange->higher_side == LOCAL ? "local" : "remote");
}

static void adjust_feerange(struct feerange *feerange,
			    struct amount_sat offer, enum side side)
{
	bool ok;

	/* FIXME: BOLT 2 previously said that we have to set it to less than
	 * the final commit fee: we do this for now, still:
	 *
	 *     - MUST propose a value "strictly between" the received
	 *      `fee_satoshis` and its previously-sent `fee_satoshis`.
	 */
	if (side == feerange->higher_side)
		ok = amount_sat_sub(&feerange->max, offer, AMOUNT_SAT(1));
	else
		ok = amount_sat_add(&feerange->min, offer, AMOUNT_SAT(1));

	status_debug("Feerange %s update %s: now %s-%s",
		     side == LOCAL ? "local" : "remote",
		     fmt_amount_sat(tmpctx, offer),
		     fmt_amount_sat(tmpctx, feerange->min),
		     fmt_amount_sat(tmpctx, feerange->max));

	if (!ok)
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Overflow in updating fee range");
}

/* Do these two ranges overlap?  If so, return that range. */
static bool get_overlap(const struct tlv_closing_signed_tlvs_fee_range *r1,
			const struct tlv_closing_signed_tlvs_fee_range *r2,
			struct tlv_closing_signed_tlvs_fee_range *overlap)
{
 	if (amount_sat_greater(r1->min_fee_satoshis, r2->min_fee_satoshis))
		overlap->min_fee_satoshis = r1->min_fee_satoshis;
	else
		overlap->min_fee_satoshis = r2->min_fee_satoshis;
 	if (amount_sat_less(r1->max_fee_satoshis, r2->max_fee_satoshis))
		overlap->max_fee_satoshis = r1->max_fee_satoshis;
	else
		overlap->max_fee_satoshis = r2->max_fee_satoshis;

	return amount_sat_less_eq(overlap->min_fee_satoshis,
				  overlap->max_fee_satoshis);
}

/* Is this amount in this range? */
static bool amount_in_range(struct amount_sat amount,
			    const struct tlv_closing_signed_tlvs_fee_range *r)
{
	return amount_sat_greater_eq(amount, r->min_fee_satoshis)
		&& amount_sat_less_eq(amount, r->max_fee_satoshis);
}

/* Figure out what we should offer now. */
static struct amount_sat
adjust_offer(struct per_peer_state *pps, const struct channel_id *channel_id,
	     const struct feerange *feerange, struct amount_sat remote_offer,
	     struct amount_sat min_fee_to_accept, u64 fee_negotiation_step,
	     u8 fee_negotiation_step_unit)
{
	struct amount_sat min_plus_one, range_len, step_sat, result;
	struct amount_msat step_msat;

	/* Within 1 satoshi?  Agree. */
	if (!amount_sat_add(&min_plus_one, feerange->min, AMOUNT_SAT(1)))
		peer_failed_warn(pps, channel_id,
				 "Fee offer %s min too large",
				 fmt_amount_sat(tmpctx, feerange->min));

	if (amount_sat_greater_eq(min_plus_one, feerange->max))
		return remote_offer;

	/* feerange has already been adjusted so that our new offer is ok to be
	 * any number in [feerange->min, feerange->max] and after the following
	 * min_fee_to_accept is in that range. Thus, pick a fee in
	 * [min_fee_to_accept, feerange->max]. */
	if (amount_sat_greater(feerange->min, min_fee_to_accept))
		min_fee_to_accept = feerange->min;

	/* Max is below our minimum acceptable? */
	if (!amount_sat_sub(&range_len, feerange->max, min_fee_to_accept))
		peer_failed_warn(pps, channel_id,
				 "Feerange %s-%s"
				 " below minimum acceptable %s",
				 fmt_amount_sat(tmpctx, feerange->min),
				 fmt_amount_sat(tmpctx, feerange->max),
				 fmt_amount_sat(tmpctx, min_fee_to_accept));

	if (fee_negotiation_step_unit ==
	    CLOSING_FEE_NEGOTIATION_STEP_UNIT_SATOSHI) {
		/* -1 because the range boundary has already been adjusted with
		 * one from our previous proposal. So, if the user requested a
		 * step of 1 satoshi at a time we should just return our end of
		 * the range from this function. */
		step_msat = amount_msat((fee_negotiation_step - 1)
					* MSAT_PER_SAT);
	} else {
		/* fee_negotiation_step is e.g. 20 to designate 20% from
		 * range_len (which is in satoshi), so:
		 * range_len * fee_negotiation_step / 100 [sat]
		 * is equivalent to:
		 * range_len * fee_negotiation_step * 10 [msat] */
		step_msat = amount_msat(range_len.satoshis /* Raw: % calc */ *
					fee_negotiation_step * 10);
	}

	step_sat = amount_msat_to_sat_round_down(step_msat);

	if (feerange->higher_side == LOCAL) {
		if (!amount_sat_sub(&result, feerange->max, step_sat))
			/* step_sat > feerange->max, unlikely */
			return min_fee_to_accept;

		if (amount_sat_less_eq(result, min_fee_to_accept))
			return min_fee_to_accept;
	} else {
		if (!amount_sat_add(&result, min_fee_to_accept, step_sat))
			/* overflow, unlikely */
			return feerange->max;

		if (amount_sat_greater_eq(result, feerange->max))
			return feerange->max;
	}

	return result;
}

/* FIXME: We should talk to lightningd anyway, rather than doing this */
static void closing_dev_memleak(const tal_t *ctx,
				u8 *scriptpubkey[NUM_SIDES],
				const u8 *funding_wscript)
{
	struct htable *memtable = memleak_start(tmpctx);

	memleak_ptr(memtable, ctx);
	memleak_ptr(memtable, scriptpubkey[LOCAL]);
	memleak_ptr(memtable, scriptpubkey[REMOTE]);
	memleak_ptr(memtable, funding_wscript);

	dump_memleak(memtable, memleak_status_broken, NULL);
}

/* Figure out what weight we actually expect for this closing tx (using zero fees
 * gives the largest possible tx: larger values might omit outputs). */
static size_t closing_tx_weight_estimate(u8 *scriptpubkey[NUM_SIDES],
					 const u8 *funding_wscript,
					 const struct amount_sat *out,
					 struct amount_sat funding_sats,
					 struct amount_sat dust_limit,
					 u32 *local_wallet_index,
					 const struct ext_key *local_wallet_ext_key)
{
	/* We create a dummy close */
	struct bitcoin_tx *tx;
	struct bitcoin_outpoint dummy_funding;

	memset(&dummy_funding, 0, sizeof(dummy_funding));
	tx = create_close_tx(tmpctx, chainparams,
			     local_wallet_index, local_wallet_ext_key,
			     scriptpubkey[LOCAL], scriptpubkey[REMOTE],
			     funding_wscript,
			     &dummy_funding,
			     funding_sats,
			     out[LOCAL],
			     out[REMOTE],
			     dust_limit);

	/* We will have to append the witness */
	return bitcoin_tx_weight(tx) + bitcoin_tx_2of2_input_witness_weight();
}

/* Get the minimum and desired fees */
static void calc_fee_bounds(size_t expected_weight,
			    u32 min_feerate,
			    u32 desired_feerate,
			    u32 max_feerate,
			    struct amount_sat funding,
			    enum side opener,
			    struct amount_sat *minfee,
			    struct amount_sat *desiredfee,
			    struct amount_sat *maxfee)
{
	*minfee = amount_tx_fee(min_feerate, expected_weight);
	*desiredfee = amount_tx_fee(desired_feerate, expected_weight);

	/* BOLT #2:
	 * - if it is not the funder:
	 *  - SHOULD set `max_fee_satoshis` to at least the `max_fee_satoshis`
	 *   received
	 *...
	 * Note that the non-funder is not paying the fee, so there is
	 * no reason for it to have a maximum feerate.
	 */
	if (opener == REMOTE) {
		*maxfee = funding;

	} else {
		/* BOLT #2:
		 * The sending node:
		 *
		 *   - SHOULD set the initial `fee_satoshis` according to its
		 *   estimate of cost of inclusion in a block.
		 *
		 *   - SHOULD set `fee_range` according to the minimum and
		 *   maximum fees it is prepared to pay for a close
		 *   transaction.
		 */
		*maxfee = amount_tx_fee(max_feerate, expected_weight);
		status_debug("deriving max fee from rate %u -> %s",
			     max_feerate,
			     fmt_amount_sat(tmpctx, *maxfee));
	}

	/* Can't exceed maxfee. */
	if (amount_sat_greater(*minfee, *maxfee))
		*minfee = *maxfee;

	if (amount_sat_less(*desiredfee, *minfee)) {
		status_unusual("Our ideal fee is %s (%u sats/perkw),"
			       " but our minimum is %s: using that",
			       fmt_amount_sat(tmpctx, *desiredfee),
			       desired_feerate,
			       fmt_amount_sat(tmpctx, *minfee));
		*desiredfee = *minfee;
	}
	if (amount_sat_greater(*desiredfee, *maxfee)) {
		status_unusual("Our ideal fee is %s (%u sats/perkw),"
			       " but our maximum is %s: using that",
			       fmt_amount_sat(tmpctx, *desiredfee),
			       desired_feerate,
			       fmt_amount_sat(tmpctx, *maxfee));
		*desiredfee = *maxfee;
	}

	status_debug("Expected closing weight = %zu, fee %s (min %s, max %s)",
		     expected_weight,
		     fmt_amount_sat(tmpctx, *desiredfee),
		     fmt_amount_sat(tmpctx, *minfee),
		     fmt_amount_sat(tmpctx, *maxfee));
}

/* Calculate the weight of a simple close tx with given variant */
static size_t simple_close_weight(const u8 *closer_script,
				  const u8 *closee_script,
				  enum close_tx_variant variant)
{
	size_t weight = 4 * 10; /* version, locktime in vbytes */

	/* Input: outpoint (36) + sequence (4) + empty scriptsig (1) = 41 bytes */
	weight += 4 * 41;
	/* Witness: 2-of-2 multisig = 1 + 1 + 72 + 1 + 72 = 147 WU (approx) */
	weight += 147;

	/* Outputs depend on variant */
	switch (variant) {
	case CLOSE_TX_BOTH_OUTPUTS:
		/* Two outputs: 8 (value) + 1 (len) + script */
		weight += 4 * (8 + 1 + tal_bytelen(closer_script));
		weight += 4 * (8 + 1 + tal_bytelen(closee_script));
		break;
	case CLOSE_TX_CLOSER_ONLY:
		weight += 4 * (8 + 1 + tal_bytelen(closer_script));
		break;
	case CLOSE_TX_CLOSEE_ONLY:
		weight += 4 * (8 + 1 + tal_bytelen(closee_script));
		break;
	}

	return weight;
}

/* Sign a simple close tx using HSM */
static struct bitcoin_signature sign_simple_close(struct per_peer_state *pps,
						  const struct channel_id *channel_id,
						  struct bitcoin_tx *tx,
						  const struct pubkey *remote_funding_pubkey)
{
	struct bitcoin_signature sig;
	u8 *msg;

	wire_sync_write(HSM_FD,
			take(towire_hsmd_sign_mutual_close_tx(NULL,
							     tx,
							     remote_funding_pubkey)));
	msg = wire_sync_read(tmpctx, HSM_FD);
	if (!fromwire_hsmd_sign_tx_reply(msg, &sig))
		status_failed(STATUS_FAIL_HSM_IO,
			      "Bad hsmd_sign_tx_reply: %s",
			      tal_hex(tmpctx, msg));

	return sig;
}

/* Determine which tx variants we should sign as closer.
 * Returns bitmask: bit 0 = BOTH, bit 1 = CLOSER_ONLY, bit 2 = CLOSEE_ONLY
 * Returns 0 if no valid variant exists (e.g., both outputs dust without OP_RETURN).
 * Based on BOLT rules:
 * - Lesser balance party MUST NOT set closer_output_only
 * - Lesser balance party MUST set closee_output_only if local output is dust
 * - Greater balance party MUST NOT set closee_output_only
 * - Greater balance party MUST set closer_output_only if peer's output is dust
 * - MUST set fee_satoshis so that at least one output is not dust
 */
static unsigned int determine_variants_to_sign(struct amount_sat our_balance,
					       struct amount_sat their_balance,
					       struct amount_sat our_amount_after_fee,
					       struct amount_sat their_amount,
					       struct amount_sat dust_limit,
					       const u8 *our_script,
					       const u8 *their_script)
{
	unsigned int variants = 0;
	bool we_have_lesser = amount_sat_less(our_balance, their_balance);
	bool our_output_dust = amount_sat_less(our_amount_after_fee, dust_limit)
			       && !is_valid_op_return_close(our_script);
	bool their_output_dust = amount_sat_less(their_amount, dust_limit)
				 && !is_valid_op_return_close(their_script);

	status_debug("determine_variants: we_have_lesser=%d, our_dust=%d, their_dust=%d",
		     we_have_lesser, our_output_dust, their_output_dust);

	if (we_have_lesser) {
		/* Lesser balance party rules:
		 * - MUST NOT set closer_output_only
		 * - MUST set closee_output_only if local output is dust */
		if (our_output_dust && their_output_dust) {
			/* Both outputs dust - no valid variant for lesser balance party.
			 * Only greater balance party can close using OP_RETURN. */
			status_debug("Both outputs dust, lesser balance cannot close");
			return 0;
		} else if (our_output_dust) {
			/* Our output is dust, omit it via closee_output_only */
			variants |= (1 << CLOSE_TX_CLOSEE_ONLY);
		} else if (their_output_dust) {
			/* Their output is dust but ours isn't.
			 * We can only use BOTH_OUTPUTS (closee_output_only would be invalid).
			 * Note: BOTH_OUTPUTS will fail if their dust output can't be included,
			 * but that's the only valid option per spec. */
			variants |= (1 << CLOSE_TX_BOTH_OUTPUTS);
		} else {
			/* Both outputs valid: include BOTH and CLOSEE_ONLY */
			variants |= (1 << CLOSE_TX_BOTH_OUTPUTS);
			variants |= (1 << CLOSE_TX_CLOSEE_ONLY);
		}
	} else {
		/* Greater or equal balance party rules:
		 * - MUST NOT set closee_output_only
		 * - MUST set closer_output_only if peer's output is dust
		 * - If own output is dust: MUST use OP_RETURN */
		if (their_output_dust) {
			/* Their output is dust, omit it via closer_output_only.
			 * But we also need our output to be valid (not dust, or OP_RETURN). */
			if (our_output_dust) {
				/* Both dust - we need OP_RETURN for our output */
				if (is_valid_op_return_close(our_script)) {
					variants |= (1 << CLOSE_TX_CLOSER_ONLY);
				} else {
					/* Can't close - both dust without OP_RETURN */
					status_debug("Both outputs dust, need OP_RETURN");
					return 0;
				}
			} else {
				variants |= (1 << CLOSE_TX_CLOSER_ONLY);
			}
		} else if (our_output_dust) {
			/* Our output is dust - we MUST use OP_RETURN per spec */
			if (is_valid_op_return_close(our_script)) {
				/* OP_RETURN with their valid output */
				variants |= (1 << CLOSE_TX_BOTH_OUTPUTS);
			} else {
				/* Can't close - our output dust without OP_RETURN */
				status_debug("Our output dust without OP_RETURN, cannot close");
				return 0;
			}
		} else {
			/* Both outputs valid: include BOTH and CLOSER_ONLY */
			variants |= (1 << CLOSE_TX_BOTH_OUTPUTS);
			variants |= (1 << CLOSE_TX_CLOSER_ONLY);
		}
	}

	return variants;
}

/* Select which variant to use when validating their closing_complete/closing_sig.
 * Returns the appropriate variant, or -1 if no valid variant is available.
 *
 * IMPORTANT: We must validate that the variant they propose is appropriate:
 * - CLOSER_ONLY is only valid if closee output IS dust (omitting valid output is theft)
 * - CLOSEE_ONLY is only valid if closer output IS dust
 * - BOTH is valid if neither output is dust
 */
static enum close_tx_variant select_variant_for_validation(
	const struct tlv_closing_tlvs *tlvs,
	struct amount_sat closer_amount,
	struct amount_sat closee_amount,
	struct amount_sat dust_limit,
	const u8 *closer_script,
	const u8 *closee_script)
{
	bool closer_dust = amount_sat_less(closer_amount, dust_limit)
			   && !is_valid_op_return_close(closer_script);
	bool closee_dust = amount_sat_less(closee_amount, dust_limit)
			   && !is_valid_op_return_close(closee_script);

	/* Determine which variants are VALID given the dust situation.
	 * A variant is only valid if the omitted output (if any) IS dust. */
	bool both_valid = !closer_dust && !closee_dust;
	bool closer_only_valid = !closer_dust && closee_dust;
	bool closee_only_valid = closer_dust && !closee_dust;

	/* Special case: if both are dust, only closer_only with OP_RETURN closer is valid */
	if (closer_dust && closee_dust) {
		if (is_valid_op_return_close(closer_script))
			closer_only_valid = true;
	}

	/* Select based on what they provided AND what's valid */
	if (tlvs->closer_and_closee_outputs && both_valid)
		return CLOSE_TX_BOTH_OUTPUTS;
	if (tlvs->closer_output_only && closer_only_valid)
		return CLOSE_TX_CLOSER_ONLY;
	if (tlvs->closee_output_only && closee_only_valid)
		return CLOSE_TX_CLOSEE_ONLY;

	/* Fallback: select based on what's valid (they may have provided multiple sigs) */
	if (both_valid && tlvs->closer_and_closee_outputs)
		return CLOSE_TX_BOTH_OUTPUTS;
	if (closer_only_valid && tlvs->closer_output_only)
		return CLOSE_TX_CLOSER_ONLY;
	if (closee_only_valid && tlvs->closee_output_only)
		return CLOSE_TX_CLOSEE_ONLY;

	/* Last resort: use what's valid even if they didn't provide signature
	 * (will fail later when we try to get signature) */
	if (both_valid)
		return CLOSE_TX_BOTH_OUTPUTS;
	if (closer_only_valid)
		return CLOSE_TX_CLOSER_ONLY;
	if (closee_only_valid)
		return CLOSE_TX_CLOSEE_ONLY;

	/* Nothing is valid - will fail later */
	return CLOSE_TX_BOTH_OUTPUTS;
}

/* Get the signature from tlvs for a given variant */
static const secp256k1_ecdsa_signature *get_sig_for_variant(
	const struct tlv_closing_tlvs *tlvs,
	enum close_tx_variant variant)
{
	switch (variant) {
	case CLOSE_TX_BOTH_OUTPUTS:
		return tlvs->closer_and_closee_outputs;
	case CLOSE_TX_CLOSER_ONLY:
		return tlvs->closer_output_only;
	case CLOSE_TX_CLOSEE_ONLY:
		return tlvs->closee_output_only;
	}
	return NULL;
}

/* Send closing_complete message */
static void send_closing_complete(struct per_peer_state *pps,
				  const struct channel_id *channel_id,
				  const u8 *our_script,
				  const u8 *their_script,
				  struct amount_sat fee,
				  u32 locktime,
				  const struct bitcoin_signature *sig_both,
				  const struct bitcoin_signature *sig_closer_only,
				  const struct bitcoin_signature *sig_closee_only)
{
	struct tlv_closing_tlvs *tlvs = tlv_closing_tlvs_new(tmpctx);
	u8 *msg;

	/* Include signatures for applicable variants */
	if (sig_both) {
		tlvs->closer_and_closee_outputs = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closer_and_closee_outputs = sig_both->s;
	}
	if (sig_closer_only) {
		tlvs->closer_output_only = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closer_output_only = sig_closer_only->s;
	}
	if (sig_closee_only) {
		tlvs->closee_output_only = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closee_output_only = sig_closee_only->s;
	}

	msg = towire_closing_complete(NULL, channel_id,
				      our_script, their_script,
				      fee, locktime, tlvs);
	peer_write(pps, take(msg));

	status_debug("Sent closing_complete: fee=%s, locktime=%u",
		     fmt_amount_sat(tmpctx, fee), locktime);
}

/* Send closing_sig message (single signature for selected variant) */
static void send_closing_sig(struct per_peer_state *pps,
			     const struct channel_id *channel_id,
			     const u8 *closer_script,
			     const u8 *closee_script,
			     struct amount_sat fee,
			     u32 locktime,
			     const struct bitcoin_signature *sig,
			     enum close_tx_variant variant)
{
	struct tlv_closing_tlvs *tlvs = tlv_closing_tlvs_new(tmpctx);
	u8 *msg;

	/* Include signature for the selected variant */
	switch (variant) {
	case CLOSE_TX_BOTH_OUTPUTS:
		tlvs->closer_and_closee_outputs = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closer_and_closee_outputs = sig->s;
		break;
	case CLOSE_TX_CLOSER_ONLY:
		tlvs->closer_output_only = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closer_output_only = sig->s;
		break;
	case CLOSE_TX_CLOSEE_ONLY:
		tlvs->closee_output_only = tal(tlvs, secp256k1_ecdsa_signature);
		*tlvs->closee_output_only = sig->s;
		break;
	}

	msg = towire_closing_sig(NULL, channel_id,
				 closer_script, closee_script,
				 fee, locktime, tlvs);
	peer_write(pps, take(msg));

	status_debug("Sent closing_sig for variant %d", variant);
}

/* Notify master about received closing_complete (their tx) */
static void tell_master_closing_complete(const struct bitcoin_signature *their_sig,
					 const struct bitcoin_tx *their_tx)
{
	u8 *msg = towire_closingd_received_closing_complete(NULL, their_sig, their_tx);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Writing closing_complete to master: %s",
			      strerror(errno));
}

/* Notify master about received closing_sig (our tx is complete) */
static void tell_master_closing_sig(const struct bitcoin_tx *final_tx,
				    const struct bitcoin_signature *peer_sig)
{
	u8 *msg = towire_closingd_received_closing_sig(NULL, final_tx, peer_sig);
	if (!wire_sync_write(REQ_FD, take(msg)))
		status_failed(STATUS_FAIL_MASTER_IO,
			      "Writing closing_sig to master: %s",
			      strerror(errno));
}

/* Main simple close protocol implementation */
static void do_simple_close(const tal_t *ctx,
			    struct per_peer_state *pps,
			    const struct channel_id *channel_id,
			    const struct pubkey funding_pubkey[NUM_SIDES],
			    const u8 *funding_wscript,
			    u32 *local_wallet_index,
			    const struct ext_key *local_wallet_ext_key,
			    const u8 *our_scriptpubkey,
			    const u8 *their_scriptpubkey,
			    const struct bitcoin_outpoint *funding,
			    struct amount_sat funding_sats,
			    struct amount_sat our_balance,
			    struct amount_sat their_balance,
			    struct amount_sat dust_limit,
			    u32 min_feerate,
			    u32 preferred_feerate,
			    u32 max_feerate)
{
	struct amount_sat our_fee, our_amount_after_fee;
	u32 our_locktime;
	unsigned int our_variants;
	struct bitcoin_tx *tx_both = NULL, *tx_closer_only = NULL, *tx_closee_only = NULL;
	struct bitcoin_signature sig_both, sig_closer_only, sig_closee_only;
	struct bitcoin_signature *p_sig_both = NULL, *p_sig_closer_only = NULL, *p_sig_closee_only = NULL;
	bool received_closing_sig = false;

	/* Calculate our fee based on preferred feerate */
	size_t weight = simple_close_weight(our_scriptpubkey, their_scriptpubkey,
					    CLOSE_TX_BOTH_OUTPUTS);
	our_fee = amount_tx_fee(preferred_feerate, weight);

	/* Ensure fee doesn't exceed our balance */
	if (amount_sat_greater(our_fee, our_balance))
		our_fee = our_balance;

	if (!amount_sat_sub(&our_amount_after_fee, our_balance, our_fee))
		our_amount_after_fee = AMOUNT_SAT(0);

	/* Use current block height as locktime (could get from master, using 0 for now) */
	our_locktime = 0;

	status_debug("Simple close: our_balance=%s, their_balance=%s, fee=%s",
		     fmt_amount_sat(tmpctx, our_balance),
		     fmt_amount_sat(tmpctx, their_balance),
		     fmt_amount_sat(tmpctx, our_fee));

	/* Determine which variants we need to sign */
	our_variants = determine_variants_to_sign(our_balance, their_balance,
						  our_amount_after_fee, their_balance,
						  dust_limit,
						  our_scriptpubkey, their_scriptpubkey);

	status_debug("Variants to sign: 0x%x", our_variants);

	/* Create and sign applicable tx variants (we are closer)
	 * NOTE: Allocate on ctx, not tmpctx, because tmpctx is cleaned in loop */
	if (our_variants & (1 << CLOSE_TX_BOTH_OUTPUTS)) {
		tx_both = create_simple_close_tx(ctx, chainparams,
						 local_wallet_index, local_wallet_ext_key,
						 our_scriptpubkey, their_scriptpubkey,
						 funding_wscript, funding, funding_sats,
						 our_balance, their_balance,
						 our_fee, dust_limit, our_locktime,
						 CLOSE_TX_BOTH_OUTPUTS);
		if (tx_both) {
			sig_both = sign_simple_close(pps, channel_id, tx_both,
						     &funding_pubkey[REMOTE]);
			p_sig_both = &sig_both;
		}
	}

	if (our_variants & (1 << CLOSE_TX_CLOSER_ONLY)) {
		tx_closer_only = create_simple_close_tx(ctx, chainparams,
							local_wallet_index, local_wallet_ext_key,
							our_scriptpubkey, their_scriptpubkey,
							funding_wscript, funding, funding_sats,
							our_balance, their_balance,
							our_fee, dust_limit, our_locktime,
							CLOSE_TX_CLOSER_ONLY);
		if (tx_closer_only) {
			sig_closer_only = sign_simple_close(pps, channel_id, tx_closer_only,
							   &funding_pubkey[REMOTE]);
			p_sig_closer_only = &sig_closer_only;
		}
	}

	if (our_variants & (1 << CLOSE_TX_CLOSEE_ONLY)) {
		tx_closee_only = create_simple_close_tx(ctx, chainparams,
							local_wallet_index, local_wallet_ext_key,
							our_scriptpubkey, their_scriptpubkey,
							funding_wscript, funding, funding_sats,
							our_balance, their_balance,
							our_fee, dust_limit, our_locktime,
							CLOSE_TX_CLOSEE_ONLY);
		if (tx_closee_only) {
			sig_closee_only = sign_simple_close(pps, channel_id, tx_closee_only,
							   &funding_pubkey[REMOTE]);
			p_sig_closee_only = &sig_closee_only;
		}
	}

	/* Validate we have at least one signature to send.
	 * Per BOLT: "MUST set fee_satoshis so that at least one output is not dust"
	 * If we can't create any valid variant, we cannot participate in simple close. */
	if (!p_sig_both && !p_sig_closer_only && !p_sig_closee_only) {
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "Cannot create valid simple close tx: "
			      "our_balance=%s, their_balance=%s, fee=%s, dust_limit=%s. "
			      "Both outputs may be dust without OP_RETURN script.",
			      fmt_amount_sat(tmpctx, our_balance),
			      fmt_amount_sat(tmpctx, their_balance),
			      fmt_amount_sat(tmpctx, our_fee),
			      fmt_amount_sat(tmpctx, dust_limit));
	}

	/* Send closing_complete immediately (only once, no RBF from us) */
	send_closing_complete(pps, channel_id,
			      our_scriptpubkey, their_scriptpubkey,
			      our_fee, our_locktime,
			      p_sig_both, p_sig_closer_only, p_sig_closee_only);

	peer_billboard(false, "Sent closing_complete, waiting for peer's response");

	/* Main message loop */
	while (!received_closing_sig) {
		u8 *msg;
		u16 type;

		clean_tmpctx();
		msg = closing_read_peer_msg(tmpctx, pps);
		type = fromwire_peektype(msg);

		if (type == WIRE_CLOSING_COMPLETE) {
			/* Peer sent closing_complete (they are closer, we are closee) */
			struct channel_id their_channel_id;
			u8 *their_closer_script, *their_closee_script;
			struct amount_sat their_fee;
			u32 their_locktime;
			struct tlv_closing_tlvs *tlvs;
			enum close_tx_variant variant;
			const secp256k1_ecdsa_signature *their_sig_raw;
			struct bitcoin_signature their_sig;
			struct bitcoin_tx *their_tx;
			struct bitcoin_signature our_sig_for_their_tx;
			struct amount_sat their_closer_amount, their_closee_amount;

			if (!fromwire_closing_complete(tmpctx, msg,
						       &their_channel_id,
						       &their_closer_script,
						       &their_closee_script,
						       &their_fee,
						       &their_locktime,
						       &tlvs)) {
				peer_failed_warn(pps, channel_id,
						 "Bad closing_complete: %s",
						 tal_hex(tmpctx, msg));
			}

			if (!channel_id_eq(&their_channel_id, channel_id)) {
				peer_failed_warn(pps, channel_id,
						 "closing_complete channel_id mismatch");
			}

			status_debug("Received closing_complete: fee=%s, locktime=%u",
				     fmt_amount_sat(tmpctx, their_fee), their_locktime);

			/* Validate scripts: closee_script should be OUR script from shutdown */
			if (!tal_arr_eq(their_closee_script, our_scriptpubkey)) {
				peer_failed_warn(pps, channel_id,
						 "closing_complete closee_script doesn't match "
						 "our shutdown script");
			}

			/* Validate scripts: closer_script should be THEIR script from shutdown */
			if (!tal_arr_eq(their_closer_script, their_scriptpubkey)) {
				peer_failed_warn(pps, channel_id,
						 "closing_complete closer_script doesn't match "
						 "peer's shutdown script");
			}

			/* Validate fee: must not exceed their balance */
			if (amount_sat_greater(their_fee, their_balance)) {
				peer_failed_warn(pps, channel_id,
						 "closing_complete fee %s exceeds their balance %s",
						 fmt_amount_sat(tmpctx, their_fee),
						 fmt_amount_sat(tmpctx, their_balance));
			}

			/* In their tx, they are closer (their_closer_script is theirs) */
			/* So from their perspective: closer_amount = their_balance - fee */
			/* closee_amount = our_balance (we're closee in their tx) */
			if (!amount_sat_sub(&their_closer_amount, their_balance, their_fee))
				their_closer_amount = AMOUNT_SAT(0);
			their_closee_amount = our_balance;

			/* Validate: at least one output must be above dust (or OP_RETURN) */
			{
				bool closer_valid = !amount_sat_less(their_closer_amount, dust_limit)
						    || is_valid_op_return_close(their_closer_script);
				bool closee_valid = !amount_sat_less(their_closee_amount, dust_limit)
						    || is_valid_op_return_close(their_closee_script);
				if (!closer_valid && !closee_valid) {
					peer_failed_warn(pps, channel_id,
							 "closing_complete: both outputs would be dust");
				}
			}

			/* Select which variant to validate/sign */
			variant = select_variant_for_validation(tlvs,
								their_closer_amount,
								their_closee_amount,
								dust_limit,
								their_closer_script,
								their_closee_script);

			status_debug("Selected variant %d for their tx", variant);

			/* Get their signature for this variant */
			their_sig_raw = get_sig_for_variant(tlvs, variant);
			if (!their_sig_raw) {
				peer_failed_warn(pps, channel_id,
						 "No signature for variant %d in closing_complete",
						 variant);
			}

			their_sig.sighash_type = SIGHASH_ALL;
			their_sig.s = *their_sig_raw;

			/* Create their tx to validate signature */
			their_tx = create_simple_close_tx(tmpctx, chainparams,
							  NULL, NULL, /* not our wallet output */
							  their_closer_script,
							  their_closee_script,
							  funding_wscript, funding, funding_sats,
							  their_balance, our_balance,
							  their_fee, dust_limit, their_locktime,
							  variant);
			if (!their_tx) {
				peer_failed_warn(pps, channel_id,
						 "Could not create their closing tx");
			}

			/* Validate their signature */
			if (!check_tx_sig(their_tx, 0, NULL, funding_wscript,
					  &funding_pubkey[REMOTE], &their_sig)) {
				peer_failed_warn(pps, channel_id,
						 "Bad signature in closing_complete");
			}

			/* Sign their tx and send closing_sig */
			our_sig_for_their_tx = sign_simple_close(pps, channel_id, their_tx,
								 &funding_pubkey[REMOTE]);

			/* Notify master about their tx */
			tell_master_closing_complete(&their_sig, their_tx);

			/* Send closing_sig for their tx */
			send_closing_sig(pps, channel_id,
					 their_closer_script, their_closee_script,
					 their_fee, their_locktime,
					 &our_sig_for_their_tx, variant);

			notify(LOG_INFORM, "Signed peer's closing tx, fee %s",
			       fmt_amount_sat(tmpctx, their_fee));

		} else if (type == WIRE_CLOSING_SIG) {
			/* Peer sent closing_sig for our tx (we were closer) */
			struct channel_id their_channel_id;
			u8 *sig_closer_script, *sig_closee_script;
			struct amount_sat sig_fee;
			u32 sig_locktime;
			struct tlv_closing_tlvs *tlvs;
			enum close_tx_variant variant;
			const secp256k1_ecdsa_signature *their_sig_raw;
			struct bitcoin_signature their_sig;
			struct bitcoin_tx *final_tx;

			if (!fromwire_closing_sig(tmpctx, msg,
						  &their_channel_id,
						  &sig_closer_script,
						  &sig_closee_script,
						  &sig_fee,
						  &sig_locktime,
						  &tlvs)) {
				peer_failed_warn(pps, channel_id,
						 "Bad closing_sig: %s",
						 tal_hex(tmpctx, msg));
			}

			if (!channel_id_eq(&their_channel_id, channel_id)) {
				peer_failed_warn(pps, channel_id,
						 "closing_sig channel_id mismatch");
			}

			status_debug("Received closing_sig: fee=%s, locktime=%u",
				     fmt_amount_sat(tmpctx, sig_fee), sig_locktime);

			/* Verify it matches our proposal */
			if (!amount_sat_eq(sig_fee, our_fee) || sig_locktime != our_locktime) {
				peer_failed_warn(pps, channel_id,
						 "closing_sig doesn't match our proposal: "
						 "fee %s vs %s, locktime %u vs %u",
						 fmt_amount_sat(tmpctx, sig_fee),
						 fmt_amount_sat(tmpctx, our_fee),
						 sig_locktime, our_locktime);
			}

			/* Validate scripts match what we sent in closing_complete:
			 * We were closer, they were closee */
			if (!tal_arr_eq(sig_closer_script, our_scriptpubkey)) {
				peer_failed_warn(pps, channel_id,
						 "closing_sig closer_script doesn't match "
						 "our closing_complete");
			}
			if (!tal_arr_eq(sig_closee_script, their_scriptpubkey)) {
				peer_failed_warn(pps, channel_id,
						 "closing_sig closee_script doesn't match "
						 "our closing_complete");
			}

			/* Determine which variant they signed */
			if (tlvs->closer_and_closee_outputs) {
				variant = CLOSE_TX_BOTH_OUTPUTS;
				their_sig_raw = tlvs->closer_and_closee_outputs;
				final_tx = tx_both;
			} else if (tlvs->closer_output_only) {
				variant = CLOSE_TX_CLOSER_ONLY;
				their_sig_raw = tlvs->closer_output_only;
				final_tx = tx_closer_only;
			} else if (tlvs->closee_output_only) {
				variant = CLOSE_TX_CLOSEE_ONLY;
				their_sig_raw = tlvs->closee_output_only;
				final_tx = tx_closee_only;
			} else {
				peer_failed_warn(pps, channel_id,
						 "No signature in closing_sig");
				return;
			}

			if (!final_tx) {
				peer_failed_warn(pps, channel_id,
						 "closing_sig for variant %d we didn't propose",
						 variant);
			}

			their_sig.sighash_type = SIGHASH_ALL;
			their_sig.s = *their_sig_raw;

			/* Validate their signature */
			if (!check_tx_sig(final_tx, 0, NULL, funding_wscript,
					  &funding_pubkey[REMOTE], &their_sig)) {
				peer_failed_warn(pps, channel_id,
						 "Bad signature in closing_sig");
			}

			/* Get our signature for this variant */
			struct bitcoin_signature *our_sig;
			switch (variant) {
			case CLOSE_TX_BOTH_OUTPUTS:
				our_sig = p_sig_both;
				break;
			case CLOSE_TX_CLOSER_ONLY:
				our_sig = p_sig_closer_only;
				break;
			case CLOSE_TX_CLOSEE_ONLY:
				our_sig = p_sig_closee_only;
				break;
			default:
				our_sig = NULL;
			}

			if (!our_sig) {
				peer_failed_warn(pps, channel_id,
						 "No signature for variant %d", variant);
			}

			/* Add witness to final tx */
			bitcoin_tx_input_set_witness(final_tx, 0,
						     bitcoin_witness_2of2(final_tx,
									  our_sig,
									  &their_sig,
									  &funding_pubkey[LOCAL],
									  &funding_pubkey[REMOTE]));

			/* Notify master - tx is ready to broadcast */
			tell_master_closing_sig(final_tx, &their_sig);

			struct bitcoin_txid txid;
			bitcoin_txid(final_tx, &txid);
			peer_billboard(true, "Simple close complete, txid: %s",
				       fmt_bitcoin_txid(tmpctx, &txid));

			received_closing_sig = true;

		} else if (type == WIRE_CHANNEL_READY || type == WIRE_SHUTDOWN ||
			   type == WIRE_ANNOUNCEMENT_SIGNATURES) {
			/* Ignore these during close */
			status_debug("Ignoring message type %d during simple close", type);
		} else {
			peer_failed_warn(pps, channel_id,
					 "Unexpected message %s during simple close",
					 peer_wire_name(type));
		}
	}

	/* Clean up tx variants to avoid memleak */
	tal_free(tx_both);
	tal_free(tx_closer_only);
	tal_free(tx_closee_only);
}

/* We've received one offer; if we're opener, that means we've already sent one
 * too. */
static void do_quickclose(struct amount_sat offer[NUM_SIDES],
			  struct per_peer_state *pps,
			  const struct channel_id *channel_id,
			  const struct pubkey funding_pubkey[NUM_SIDES],
			  const u8 *funding_wscript,
			  u32 *local_wallet_index,
			  const struct ext_key *local_wallet_ext_key,
			  u8 *scriptpubkey[NUM_SIDES],
			  const struct bitcoin_outpoint *funding,
			  struct amount_sat funding_sats,
			  const struct amount_sat out[NUM_SIDES],
			  enum side opener,
			  struct amount_sat our_dust_limit,
			  const struct bitcoin_outpoint *wrong_funding,
			  struct bitcoin_txid *closing_txid,
			  const struct tlv_closing_signed_tlvs_fee_range *our_feerange,
			  const struct tlv_closing_signed_tlvs_fee_range *their_feerange)
{
	struct tlv_closing_signed_tlvs_fee_range overlap;


	/* BOLT #2:
	 *   - if the message contains a `fee_range`:
	 *     - if there is no overlap between that and its own `fee_range`:
	 *       - SHOULD send a warning
	 *       - MUST fail the channel if it doesn't receive a satisfying `fee_range` after a reasonable amount of time
	 */
	/* (Note we satisfy the "MUST fail" by our close command unilteraltimeout) */
	if (!get_overlap(our_feerange, their_feerange, &overlap)) {
		peer_failed_warn(pps, channel_id,
			       "Unable to agree on a feerate."
			       " Our range %s-%s, other range %s-%s",
			       fmt_amount_sat(tmpctx, our_feerange->min_fee_satoshis),
			       fmt_amount_sat(tmpctx, our_feerange->max_fee_satoshis),
			       fmt_amount_sat(tmpctx, their_feerange->min_fee_satoshis),
			       fmt_amount_sat(tmpctx, their_feerange->max_fee_satoshis));
		return;
	}

	status_info("performing quickclose in range %s-%s",
		    fmt_amount_sat(tmpctx, overlap.min_fee_satoshis),
		    fmt_amount_sat(tmpctx, overlap.max_fee_satoshis));

	/* BOLT #2:
	 * - otherwise:
	 *   - if it is the funder:
	 *     - if `fee_satoshis` is not in the overlap between the sent
	 *       and received `fee_range`:
	 *       - MUST fail the channel
	 *     - otherwise:
	 *       - MUST reply with the same `fee_satoshis`.
	 */
	if (opener == LOCAL) {
		if (!amount_in_range(offer[REMOTE], &overlap)) {
			peer_failed_warn(pps, channel_id,
			       "Your fee %s was not in range:"
			       " Our range %s-%s, other range %s-%s",
			       fmt_amount_sat(tmpctx, offer[REMOTE]),
			       fmt_amount_sat(tmpctx, our_feerange->min_fee_satoshis),
			       fmt_amount_sat(tmpctx, our_feerange->max_fee_satoshis),
			       fmt_amount_sat(tmpctx, their_feerange->min_fee_satoshis),
			       fmt_amount_sat(tmpctx, their_feerange->max_fee_satoshis));
			return;
		}
		/* Only reply if we didn't already completely agree. */
		if (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
			offer[LOCAL] = offer[REMOTE];
			send_offer(pps, chainparams,
				   channel_id, funding_pubkey, funding_wscript,
				   local_wallet_index, local_wallet_ext_key,
				   scriptpubkey, funding,
				   funding_sats, out, opener,
				   our_dust_limit,
				   offer[LOCAL],
				   wrong_funding,
				   our_feerange);
		}
	} else {
		/* BOLT #2:
		 * - otherwise (it is not the funder):
		 *   - if it has already sent a `closing_signed`:
		 *     - if `fee_satoshis` is not the same as the value it sent:
		 *       - MUST fail the channel
		 *   - otherwise:
		 *     - MUST propose a `fee_satoshis` in the overlap between
		 *       received and (about-to-be) sent `fee_range`.
		 */
		if (!amount_in_range(offer[LOCAL], &overlap)) {
			/* Hmm, go to edges. */
			if (amount_sat_greater(offer[LOCAL],
					       overlap.max_fee_satoshis)) {
				offer[LOCAL] = overlap.max_fee_satoshis;
				status_unusual("Lowered offer to max allowable"
					       " %s",
					       fmt_amount_sat(tmpctx, offer[LOCAL]));
			} else if (amount_sat_less(offer[LOCAL],
						   overlap.min_fee_satoshis)) {
				offer[LOCAL] = overlap.min_fee_satoshis;
				status_unusual("Increased offer to min allowable"
					       " %s",
					       fmt_amount_sat(tmpctx, offer[LOCAL]));
			}
		}
		send_offer(pps, chainparams,
			   channel_id, funding_pubkey, funding_wscript,
			   local_wallet_index, local_wallet_ext_key,
			   scriptpubkey, funding,
			   funding_sats, out, opener,
			   our_dust_limit,
			   offer[LOCAL],
			   wrong_funding,
			   our_feerange);

		/* They will reply unless we completely agreed. */
		if (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
			offer[REMOTE]
				= receive_offer(pps, chainparams,
						channel_id, funding_pubkey,
						funding_wscript,
						local_wallet_index, local_wallet_ext_key,
						scriptpubkey, funding,
						funding_sats,
						out, opener,
						our_dust_limit,
						our_feerange->min_fee_satoshis,
						wrong_funding,
						closing_txid,
						NULL);
			/* BOLT #2:
			 * - otherwise (it is not the funder):
			 *   - if it has already sent a `closing_signed`:
			 *     - if `fee_satoshis` is not the same as the value
			 *       it sent:
			 *       - MUST fail the channel
			 */
			if (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
				peer_failed_warn(pps, channel_id,
						 "Your fee %s was not equal to %s",
						 fmt_amount_sat(tmpctx, offer[REMOTE]),
						 fmt_amount_sat(tmpctx, offer[LOCAL]));
				return;
			}
		}
	}

	peer_billboard(true, "We agreed on a closing fee of %"PRIu64" satoshi for tx:%s",
		       offer[LOCAL],
		       fmt_bitcoin_txid(tmpctx, closing_txid));
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	struct per_peer_state *pps;
	u8 *msg;
	struct pubkey funding_pubkey[NUM_SIDES];
	struct bitcoin_txid closing_txid;
	struct bitcoin_outpoint funding;
	struct amount_sat funding_sats, out[NUM_SIDES];
	struct amount_sat our_dust_limit;
	struct amount_sat min_fee_to_accept, offer[NUM_SIDES],
		max_fee_to_accept;
	u32 min_feerate, initial_feerate, max_feerate;
	struct feerange feerange;
	enum side opener;
	u32 *local_wallet_index;
	struct ext_key *local_wallet_ext_key;
	u8 *scriptpubkey[NUM_SIDES], *funding_wscript;
	u64 fee_negotiation_step;
	u8 fee_negotiation_step_unit;
	char fee_negotiation_step_str[32]; /* fee_negotiation_step + "sat" */
	struct channel_id channel_id;
	enum side whose_turn;
	bool use_quickclose;
	struct tlv_closing_signed_tlvs_fee_range *our_feerange, **their_feerange;
	struct bitcoin_outpoint *wrong_funding;
	bool developer;
	bool option_simple_close;

	developer = subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_closingd_init(ctx, msg,
				    &chainparams,
				    &channel_id,
				    &funding,
				    &funding_sats,
				    &funding_pubkey[LOCAL],
				    &funding_pubkey[REMOTE],
				    &opener,
				    &out[LOCAL],
				    &out[REMOTE],
				    &our_dust_limit,
				    &min_feerate, &initial_feerate, &max_feerate,
				    &local_wallet_index,
				    &local_wallet_ext_key,
				    &scriptpubkey[LOCAL],
				    &scriptpubkey[REMOTE],
				    &fee_negotiation_step,
				    &fee_negotiation_step_unit,
				    &use_quickclose,
				    &wrong_funding,
				    &option_simple_close))
		master_badmsg(WIRE_CLOSINGD_INIT, msg);

	/* stdin == requests, 3 == peer, 4 = hsmd */
	pps = notleak(new_per_peer_state(ctx));
	per_peer_state_set_fd(pps, 3);

	funding_wscript = bitcoin_redeem_2of2(ctx,
					      &funding_pubkey[LOCAL],
					      &funding_pubkey[REMOTE]);

	/* Use simple close protocol if negotiated */
	if (option_simple_close) {
		status_info("Using option_simple_close protocol");
		/* Initialize to NULL since we jump to exit_thru_the_giftshop */
		our_feerange = NULL;
		their_feerange = NULL;
		do_simple_close(ctx, pps, &channel_id,
				funding_pubkey, funding_wscript,
				local_wallet_index, local_wallet_ext_key,
				scriptpubkey[LOCAL], scriptpubkey[REMOTE],
				&funding, funding_sats,
				out[LOCAL], out[REMOTE],
				our_dust_limit,
				min_feerate, initial_feerate, max_feerate);
		goto exit_thru_the_giftshop;
	}

	/* Legacy closing_signed protocol */
	/* Start at what we consider a reasonable feerate for this tx. */
	calc_fee_bounds(closing_tx_weight_estimate(scriptpubkey,
						   funding_wscript,
						   out, funding_sats,
						   our_dust_limit,
						   local_wallet_index,
						   local_wallet_ext_key),
			min_feerate, initial_feerate, max_feerate,
			funding_sats, opener,
			&min_fee_to_accept, &offer[LOCAL], &max_fee_to_accept);

	/* Write values into tlv for updated closing fee neg */
	their_feerange = tal(ctx, struct tlv_closing_signed_tlvs_fee_range *);
	*their_feerange = NULL;

	if (use_quickclose) {
		our_feerange = tal(ctx, struct tlv_closing_signed_tlvs_fee_range);
		our_feerange->min_fee_satoshis = min_fee_to_accept;
		our_feerange->max_fee_satoshis = max_fee_to_accept;
	} else
		our_feerange = NULL;

	snprintf(fee_negotiation_step_str, sizeof(fee_negotiation_step_str),
		 "%" PRIu64 "%s", fee_negotiation_step,
		 fee_negotiation_step_unit ==
			 CLOSING_FEE_NEGOTIATION_STEP_UNIT_PERCENTAGE
		     ? "%"
		     : "sat");

	status_debug("out = %s/%s",
		     fmt_amount_sat(tmpctx, out[LOCAL]),
		     fmt_amount_sat(tmpctx, out[REMOTE]));
	status_debug("dustlimit = %s",
		     fmt_amount_sat(tmpctx, our_dust_limit));
	status_debug("fee = %s",
		     fmt_amount_sat(tmpctx, offer[LOCAL]));
	status_debug("fee negotiation step = %s", fee_negotiation_step_str);
	if (wrong_funding)
		status_unusual("Setting wrong_funding_txid to %s:%u",
			       fmt_bitcoin_txid(tmpctx,
						&wrong_funding->txid),
			       wrong_funding->n);

	peer_billboard(
	    true,
	    "Negotiating closing fee between %s and %s satoshi (ideal %s) "
	    "using step %s",
	    fmt_amount_sat(tmpctx, min_fee_to_accept),
	    fmt_amount_sat(tmpctx, max_fee_to_accept),
	    fmt_amount_sat(tmpctx, offer[LOCAL]),
	    fee_negotiation_step_str);

	/* BOLT #2:
	 *
	 * The funding node:
	 *  - after `shutdown` has been received, AND no HTLCs remain in either
	 *    commitment transaction:
	 *    - SHOULD send a `closing_signed` message.
	 */
	whose_turn = opener;
	for (size_t i = 0; i < 2; i++, whose_turn = !whose_turn) {
		if (whose_turn == LOCAL) {
			send_offer(pps, chainparams,
				   &channel_id, funding_pubkey, funding_wscript,
				   local_wallet_index, local_wallet_ext_key,
				   scriptpubkey, &funding,
				   funding_sats, out, opener,
				   our_dust_limit,
				   offer[LOCAL],
				   wrong_funding,
				   our_feerange);
		} else {
			if (i == 0)
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer");
			else
				peer_billboard(false, "Waiting for their initial"
					       " closing fee offer:"
					       " ours was %s",
					       fmt_amount_sat(tmpctx, offer[LOCAL]));
			offer[REMOTE]
				= receive_offer(pps, chainparams,
						&channel_id, funding_pubkey,
						funding_wscript,
						local_wallet_index,
						local_wallet_ext_key,
						scriptpubkey, &funding,
						funding_sats,
						out, opener,
						our_dust_limit,
						min_fee_to_accept,
						wrong_funding,
						&closing_txid,
						their_feerange);

			if (our_feerange && *their_feerange) {
				do_quickclose(offer,
					      pps, &channel_id, funding_pubkey,
					      funding_wscript,
					      local_wallet_index, local_wallet_ext_key,
					      scriptpubkey,
					      &funding,
					      funding_sats, out, opener,
					      our_dust_limit,
					      wrong_funding,
					      &closing_txid,
					      our_feerange, *their_feerange);
				goto exit_thru_the_giftshop;
			}
		}
	}

	/* Now we have first two points, we can init fee range. */
	init_feerange(&feerange, max_fee_to_accept, offer);

	/* Apply (and check) opener offer now. */
	adjust_feerange(&feerange, offer[opener], opener);

	/* Now any extra rounds required. */
	while (!amount_sat_eq(offer[LOCAL], offer[REMOTE])) {
		/* Still don't agree: adjust feerange based on previous offer */
		adjust_feerange(&feerange,
				offer[!whose_turn], !whose_turn);

		if (whose_turn == LOCAL) {
			offer[LOCAL] = adjust_offer(pps,
						    &channel_id,
						    &feerange, offer[REMOTE],
						    min_fee_to_accept,
						    fee_negotiation_step,
						    fee_negotiation_step_unit);
			send_offer(pps, chainparams, &channel_id,
				   funding_pubkey, funding_wscript,
				   local_wallet_index,
				   local_wallet_ext_key,
				   scriptpubkey, &funding,
				   funding_sats, out, opener,
				   our_dust_limit,
				   offer[LOCAL],
				   wrong_funding,
				   our_feerange);
		} else {
			peer_billboard(false, "Waiting for another"
				       " closing fee offer:"
				       " ours was %"PRIu64" satoshi,"
				       " theirs was %"PRIu64" satoshi,",
				       offer[LOCAL], offer[REMOTE]);
			offer[REMOTE]
				= receive_offer(pps, chainparams, &channel_id,
						funding_pubkey,
						funding_wscript,
						local_wallet_index,
						local_wallet_ext_key,
						scriptpubkey, &funding,
						funding_sats,
						out, opener,
						our_dust_limit,
						min_fee_to_accept,
						wrong_funding,
						&closing_txid,
						their_feerange);
		}

		whose_turn = !whose_turn;
	}

	peer_billboard(true, "We agreed on a closing fee of %"PRIu64" satoshi for tx:%s",
		       offer[LOCAL],
		       fmt_bitcoin_txid(tmpctx, &closing_txid));

exit_thru_the_giftshop:
	/* We don't listen for master commands, so always check memleak here */
	tal_free(wrong_funding);
	tal_free(our_feerange);
	tal_free(their_feerange);
	tal_free(local_wallet_index);
	tal_free(local_wallet_ext_key);
	if (developer)
		closing_dev_memleak(ctx, scriptpubkey, funding_wscript);

	/* We're done! */

	/* Sending the below will kill us! */
	wire_sync_write(REQ_FD, take(towire_closingd_complete(NULL)));
	tal_free(ctx);
	daemon_shutdown();

	return 0;

}
