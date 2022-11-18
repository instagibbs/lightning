#include "config.h"
#include <bitcoin/feerate.h>
#include <bitcoin/script.h>
#include <ccan/asort/asort.h>
#include <ccan/mem/mem.h>
#include <ccan/tal/str/str.h>
#include <common/htlc_tx.h>
#include <common/initial_commit_tx.h>
#include <common/keyset.h>
#include <common/lease_rates.h>
#include <common/memleak.h>
#include <common/overflows.h>
#include <common/peer_billboard.h>
#include <common/psbt_keypath.h>
#include <common/status.h>
#include <common/subdaemon.h>
#include <common/type_to_string.h>
#include <common/update_tx.h>
#include <hsmd/hsmd_wiregen.h>
#include <onchaind/onchain_types.h>
#include <onchaind/onchaind_wiregen.h>
#include <unistd.h>
#include <wally_bip32.h>
#include <wire/wire_sync.h>
#include "onchain_types_names_gen.h"

/* stdin == requests */
#define REQ_FD STDIN_FILENO
#define HSM_FD 3

/* FIXME Everything copy/pasted bc static. Deduplicate later */

/* Full tx we have partial signatures for */
static struct bitcoin_tx *complete_update_tx, *complete_settle_tx;

/* Tx we do not have full signatures for, but may appear on-chain */
static struct bitcoin_tx *committed_update_tx, *committed_settle_tx;

/* Required in various places: keys for commitment transaction. */
static const struct eltoo_keyset *keyset;

/* When to tell master about HTLCs which are missing/timed out */
static u32 reasonable_depth;

/* The messages to send at that depth. */
static u8 **missing_htlc_msgs;

/* The messages which were sent to us before init_reply was processed. */
static u8 **queued_msgs;

/* Our recorded channel balance at 'chain time' */
static struct amount_msat our_msat;

/* If we broadcast a tx, or need a delay to resolve the output. */
struct proposed_resolution {
	/* This can be NULL if our proposal is to simply ignore it after depth */
	const struct bitcoin_tx *tx;
	/* Non-zero if this is CSV-delayed. */
	u32 depth_required;
	enum eltoo_tx_type tx_type;
};

/* How it actually got resolved. */
struct resolution {
	struct bitcoin_txid txid;
	unsigned int depth;
	enum eltoo_tx_type tx_type;
};

struct tracked_output {
	enum eltoo_tx_type tx_type;
	struct bitcoin_outpoint outpoint;
	u32 tx_blockheight;
	/* FIXME: Convert all depths to blocknums, then just get new blk msgs */
	u32 depth;
	struct amount_sat sat;
	enum output_type output_type;

	/* If it is an HTLC, this is set, wscript is non-NULL. */
	struct htlc_stub htlc;
	const u8 *wscript;

	/* If it's an HTLC off our unilateral, this is their sig for htlc_tx */
	const struct bitcoin_signature *remote_htlc_sig;

	/* Our proposed solution (if any) */
	struct proposed_resolution *proposal;

	/* If it is resolved. */
	struct resolution *resolved;

	/* stashed so we can pass it along to the coin ledger */
	struct sha256 payment_hash;
};

static const char *eltoo_tx_type_name(enum eltoo_tx_type tx_type)
{
	size_t i;

	for (i = 0; enum_eltoo_tx_type_names[i].name; i++)
		if (enum_eltoo_tx_type_names[i].v == tx_type)
			return enum_eltoo_tx_type_names[i].name;
	return "unknown";
}

static const char *output_type_name(enum output_type output_type)
{
	size_t i;

	for (i = 0; enum_output_type_names[i].name; i++)
		if (enum_output_type_names[i].v == output_type)
			return enum_output_type_names[i].name;
	return "unknown";
}

static void send_coin_mvt(struct chain_coin_mvt *mvt TAKES)
{
	wire_sync_write(REQ_FD,
			take(towire_onchaind_notify_coin_mvt(NULL, mvt)));

	if (taken(mvt))
		tal_free(mvt);
}

static struct tracked_output *
new_tracked_output(struct tracked_output ***outs,
		   const struct bitcoin_outpoint *outpoint,
		   u32 tx_blockheight,
		   enum eltoo_tx_type tx_type,
		   struct amount_sat sat,
		   enum output_type output_type,
		   const struct htlc_stub *htlc,
		   const u8 *wscript,
		   const struct bitcoin_signature *remote_htlc_sig TAKES)
{
	struct tracked_output *out = tal(*outs, struct tracked_output);

	status_debug("Tracking output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint, outpoint),
		     eltoo_tx_type_name(tx_type),
		     output_type_name(output_type));

	out->tx_type = tx_type;
	out->outpoint = *outpoint;
	out->tx_blockheight = tx_blockheight;
	out->depth = 0;
	out->sat = sat;
	out->output_type = output_type;
	out->proposal = NULL;
	out->resolved = NULL;
	if (htlc)
		out->htlc = *htlc;
	out->wscript = tal_steal(out, wscript);
	out->remote_htlc_sig = tal_dup_or_null(out, struct bitcoin_signature,
					       remote_htlc_sig);

	tal_arr_expand(outs, out);

	return out;
}

static void ignore_output(struct tracked_output *out)
{
	status_debug("Ignoring output %s: %s/%s",
		     type_to_string(tmpctx, struct bitcoin_outpoint,
				    &out->outpoint),
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = out->outpoint.txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = SELF;
}

static enum wallet_tx_type onchain_txtype_to_wallet_txtype(enum eltoo_tx_type t)
{
    /* FIXME put eltoo_tx_type into proper wallet_tx_type */
	switch (t) {
	case ELTOO_FUNDING_TRANSACTION:
		return TX_CHANNEL_FUNDING;
	case ELTOO_MUTUAL_CLOSE:
		return TX_CHANNEL_CLOSE;
    case ELTOO_UPDATE:
    case ELTOO_INVALIDATED_UPDATE:
    case ELTOO_SETTLE:
    case ELTOO_INVALIDATED_SETTLE:
    case ELTOO_SWEEP:
    case ELTOO_IGNORING_TINY_PAYMENT:
    case ELTOO_SELF:
    case ELTOO_UNKNOWN_TXTYPE:
		return TX_UNKNOWN;
	}
	abort();
}

/** eltoo_proposal_is_rbfable
 *
 * @brief returns true if the given proposal
 * would be RBFed if the output it is tracking
 * increases in depth without being spent.
 */
static bool eltoo_proposal_is_rbfable(const struct proposed_resolution *proposal)
{
	/* We may fee bump anything time-sensitive
	 */
	return proposal->tx_type == ELTOO_UPDATE ||
            proposal->tx_type == ELTOO_SETTLE ||
            proposal->tx_type == ELTOO_SWEEP;
}

/** proposal_should_rbf
 *
 * @brief the given output just increased its depth,
 * so the proposal for it should be RBFed and
 * rebroadcast.
 *
 * @desc precondition: the given output must have an
 * rbfable proposal as per `eltoo_proposal_is_rbfable`.
 */
static void eltoo_proposal_should_rbf(struct tracked_output *out)
{
	struct bitcoin_tx *tx = NULL;
	u32 depth;

	assert(out->proposal);
	assert(eltoo_proposal_is_rbfable(out->proposal));

	depth = out->depth;

	/* Do not RBF at depth 1.
	 *
	 * Since we react to *onchain* events, whatever proposal we made,
	 * the output for that proposal is already at depth 1.
	 *
	 * Since our initial proposal was broadcasted with the output at
	 * depth 1, we should not RBF until a new block arrives, which is
	 * at depth 2.
	 */
	if (depth <= 1)
		return;

	/* Add other RBF-able proposals here.  */

	/* Broadcast the transaction.  */
	if (tx) {
		enum wallet_tx_type wtt;

		status_debug("Broadcasting RBF %s (%s) to resolve %s/%s "
			     "depth=%"PRIu32"",
			     eltoo_tx_type_name(out->proposal->tx_type),
			     type_to_string(tmpctx, struct bitcoin_tx, tx),
			     eltoo_tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);

		wtt = onchain_txtype_to_wallet_txtype(out->proposal->tx_type);
		wire_sync_write(REQ_FD,
				take(towire_onchaind_broadcast_tx(NULL, tx,
								 wtt,
								 true)));
	}
}

static void eltoo_proposal_meets_depth(struct tracked_output *out)
{
	bool is_rbf = false;

	/* If there's no proposal, we're not gonna do anything. */
	if (!out->proposal->tx) {
		ignore_output(out);
		return;
	}

	status_debug("Broadcasting %s (%s) to resolve %s/%s",
		     eltoo_tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_tx, out->proposal->tx),
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type));

	if (out->proposal)
		/* Any state transition we want is going to be package-RBFed.  */
		is_rbf = eltoo_proposal_is_rbfable(out->proposal);

    /* FIXME Figure out how fees are going to be paid via anchor */
	wire_sync_write(
	    REQ_FD,
	    take(towire_onchaind_broadcast_tx(
		 NULL, out->proposal->tx,
		 onchain_txtype_to_wallet_txtype(out->proposal->tx_type),
		 is_rbf)));

	/* Don't wait for this if we're ignoring the tiny payment. */
	if (out->proposal->tx_type == ELTOO_IGNORING_TINY_PAYMENT) {
		ignore_output(out);
	}

	/* Otherwise we will get a callback when it's in a block. */
}

static bool is_valid_sig(const u8 *e)
{
	struct bitcoin_signature sig;
	return signature_from_der(e, tal_count(e), &sig);
}

/* We ignore things which look like signatures. */
static bool input_similar(const struct wally_tx_input *i1,
			  const struct wally_tx_input *i2)
{
	u8 *s1, *s2;

	if (!memeq(i1->txhash, WALLY_TXHASH_LEN, i2->txhash, WALLY_TXHASH_LEN))
		return false;

	if (i1->index != i2->index)
		return false;

	if (!scripteq(i1->script, i2->script))
		return false;

	if (i1->sequence != i2->sequence)
		return false;

	if (i1->witness->num_items != i2->witness->num_items)
		return false;

	for (size_t i = 0; i < i1->witness->num_items; i++) {
		/* Need to wrap these in `tal_arr`s since the primitives
		 * except to be able to call tal_bytelen on them */
		s1 = tal_dup_arr(tmpctx, u8, i1->witness->items[i].witness,
				 i1->witness->items[i].witness_len, 0);
		s2 = tal_dup_arr(tmpctx, u8, i2->witness->items[i].witness,
				 i2->witness->items[i].witness_len, 0);

		if (scripteq(s1, s2))
			continue;

		if (is_valid_sig(s1) && is_valid_sig(s2))
			continue;
		return false;
	}

	return true;
}

/* This simple case: true if this was resolved by our proposal. */
static bool resolved_by_proposal(struct tracked_output *out,
				 const struct tx_parts *tx_parts)
{
	/* If there's no TX associated, it's not us. */
	if (!out->proposal->tx)
		return false;

	/* Our proposal can change as feerates change.  Input
	 * comparison (ignoring signatures) works pretty well. */
	if (tal_count(tx_parts->inputs) != out->proposal->tx->wtx->num_inputs)
		return false;

	for (size_t i = 0; i < tal_count(tx_parts->inputs); i++) {
		if (!input_similar(tx_parts->inputs[i],
				   &out->proposal->tx->wtx->inputs[i]))
			return false;
	}

	out->resolved = tal(out, struct resolution);
	out->resolved->txid = tx_parts->txid;
	status_debug("Resolved %s/%s by our proposal %s (%s)",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(out->proposal->tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid,
				    &out->resolved->txid));

	out->resolved->depth = 0;
	out->resolved->tx_type = out->proposal->tx_type;
	return true;
}

/* Otherwise, we figure out what happened and then call this. */
static void resolved_by_other(struct tracked_output *out,
			      const struct bitcoin_txid *txid,
			      enum eltoo_tx_type tx_type)
{
	out->resolved = tal(out, struct resolution);
	out->resolved->txid = *txid;
	out->resolved->depth = 0;
	out->resolved->tx_type = tx_type;

	status_debug("Resolved %s/%s by %s (%s)",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(tx_type),
		     type_to_string(tmpctx, struct bitcoin_txid, txid));
}

static bool is_mutual_close(u32 locktime)
{
    /* If we mask update number, this needs to change */
    return locktime == 0;
}

/* BOLT #5:
 *
 * Outputs that are *resolved* are considered *irrevocably resolved*
 * once the remote's *resolving* transaction is included in a block at least 100
 * deep, on the most-work blockchain.
 */
static size_t num_not_irrevocably_resolved(struct tracked_output **outs)
{
	size_t i, num = 0;

	for (i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->resolved || outs[i]->resolved->depth < 100)
			num++;
	}
	return num;
}

static u32 prop_blockheight(const struct tracked_output *out)
{
	return out->tx_blockheight + out->proposal->depth_required;
}

static void billboard_update(struct tracked_output **outs)
{
	const struct tracked_output *best = NULL;

	/* Highest priority is to report on proposals we have */
	for (size_t i = 0; i < tal_count(outs); i++) {
		if (!outs[i]->proposal || outs[i]->resolved)
			continue;
		if (!best || prop_blockheight(outs[i]) < prop_blockheight(best))
			best = outs[i];
	}

	if (best) {
		/* If we've broadcast and not seen yet, this happens */
		if (best->proposal->depth_required <= best->depth) {
			peer_billboard(false,
				       "%u outputs unresolved: waiting confirmation that we spent %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       eltoo_tx_type_name(best->proposal->tx_type));
		} else {
			peer_billboard(false,
				       "%u outputs unresolved: in %u blocks will spend %s (%s) using %s",
				       num_not_irrevocably_resolved(outs),
				       best->proposal->depth_required - best->depth,
				       output_type_name(best->output_type),
				       type_to_string(tmpctx,
						      struct bitcoin_outpoint,
						      &best->outpoint),
				       eltoo_tx_type_name(best->proposal->tx_type));
		}
		return;
	}

	/* Now, just report on the last thing we're waiting out. */
	for (size_t i = 0; i < tal_count(outs); i++) {
		/* FIXME: Can this happen?  No proposal, no resolution? */
		if (!outs[i]->resolved)
			continue;
		if (!best || outs[i]->resolved->depth < best->resolved->depth)
			best = outs[i];
	}

	if (best) {
		peer_billboard(false,
			       "All outputs resolved:"
			       " waiting %u more blocks before forgetting"
			       " channel",
			       best->resolved->depth < 100
			       ? 100 - best->resolved->depth : 0);
		return;
	}

	/* Not sure this can happen, but take last one (there must be one!) */
	best = outs[tal_count(outs)-1];
	peer_billboard(false, "%u outputs unresolved: %s is one (depth %u)",
		       num_not_irrevocably_resolved(outs),
		       output_type_name(best->output_type), best->depth);
}

static void propose_resolution(struct tracked_output *out,
                   const struct bitcoin_tx *tx,
                   unsigned int depth_required,
                   enum tx_type tx_type)
{
    status_debug("Propose handling %s/%s by %s (%s) after %u blocks",
             eltoo_tx_type_name(out->tx_type),
             output_type_name(out->output_type),
             eltoo_tx_type_name(tx_type),
             tx ? type_to_string(tmpctx, struct bitcoin_tx, tx):"IGNORING",
             depth_required);

    out->proposal = tal(out, struct proposed_resolution);
    out->proposal->tx = tal_steal(out->proposal, tx);
    out->proposal->depth_required = depth_required;
    out->proposal->tx_type = tx_type;

    if (depth_required == 0)
        eltoo_proposal_meets_depth(out);
}

static void unwatch_txid(const struct bitcoin_txid *txid)
{
	u8 *msg;

	msg = towire_onchaind_unwatch_tx(NULL, txid);
	wire_sync_write(REQ_FD, take(msg));
}

static void handle_eltoo_htlc_onchain_fulfill(struct tracked_output *out,
					const struct tx_parts *tx_parts,
					const struct bitcoin_outpoint *htlc_outpoint)
{
	const struct wally_tx_witness_item *preimage_item;
	struct preimage preimage;
	struct sha256 sha;
	struct ripemd160 ripemd;

	/* Our HTLC, they filled (must be an HTLC-success tx). */
	if (out->tx_type == ELTOO_SETTLE
		|| out->tx_type == ELTOO_INVALIDATED_SETTLE) {
        /* BOLTXX
         *   The recipient node can redeem the HTLC with the witness:
         *
         *      <recipient_settlement_pubkey_signature> <payment_preimage>
         */
		if (tx_parts->inputs[htlc_outpoint->n]->witness->num_items != 4) /* +2 for script/control block */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "%s/%s spent with weird witness %zu",
				      eltoo_tx_type_name(out->tx_type),
				      output_type_name(out->output_type),
				      tx_parts->inputs[htlc_outpoint->n]->witness->num_items);

        /* FIXME figure out proper index */
		preimage_item = &tx_parts->inputs[htlc_outpoint->n]->witness->items[1];
	} else
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "onchain_fulfill for %s/%s?",
			      eltoo_tx_type_name(out->tx_type),
			      output_type_name(out->output_type));

	memcpy(&preimage, preimage_item->witness, sizeof(preimage));
	sha256(&sha, &preimage, sizeof(preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	if (!ripemd160_eq(&ripemd, &out->htlc.ripemd))
		status_failed(STATUS_FAIL_INTERNAL_ERROR,
			      "%s/%s spent with bad preimage %s (ripemd not %s)",
			      eltoo_tx_type_name(out->tx_type),
			      output_type_name(out->output_type),
			      type_to_string(tmpctx, struct preimage, &preimage),
			      type_to_string(tmpctx, struct ripemd160,
					     &out->htlc.ripemd));

	/* we stash the payment_hash into the tracking_output so we
	 * can pass it along, if needbe, to the coin movement tracker */
	out->payment_hash = sha;

	/* Tell master we found a preimage. */
	status_debug("%s/%s gave us preimage %s",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     type_to_string(tmpctx, struct preimage, &preimage));
	wire_sync_write(REQ_FD,
			take(towire_onchaind_extracted_preimage(NULL,
							       &preimage)));
}

static void onchain_annotate_txout(const struct bitcoin_outpoint *outpoint,
				   enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txout(
				    tmpctx, outpoint, type)));
}

static void onchain_annotate_txin(const struct bitcoin_txid *txid, u32 innum,
				  enum wallet_tx_type type)
{
	wire_sync_write(REQ_FD, take(towire_onchaind_annotate_txin(
				    tmpctx, txid, innum, type)));
}

/* An output has been spent: see if it resolves something we care about. */
static void output_spent(struct tracked_output ***outs,
			 const struct tx_parts *tx_parts,
			 u32 input_num,
			 u32 tx_blockheight)
{
	for (size_t i = 0; i < tal_count(*outs); i++) {
		struct tracked_output *out = (*outs)[i];
		struct bitcoin_outpoint htlc_outpoint;

		if (out->resolved)
			continue;

		if (!wally_tx_input_spends(tx_parts->inputs[input_num],
					   &out->outpoint))
			continue;

		/* Was this our resolution? */
		if (resolved_by_proposal(out, tx_parts)) {
			return;
		}

		htlc_outpoint.txid = tx_parts->txid;
		htlc_outpoint.n = input_num;

		switch (out->output_type) {
		case OUTPUT_TO_US:
            /* FIXME I'm gonna call this the state output, post-funding */
        /* There is no delayed to us... it just goes into our wallet
		case DELAYED_OUTPUT_TO_US:
			unknown_spend(out, tx_parts);
			break;
        */
		case THEIR_HTLC:
            /* We ignore this timeout tx, since we should
             * resolve by ignoring once we reach depth. */
            onchain_annotate_txout(
                &htlc_outpoint,
                TX_CHANNEL_HTLC_TIMEOUT | TX_THEIRS);
			break;

		case OUR_HTLC:
			/* The only way	they can spend this: fulfill; even
			 * if it's revoked: */
			handle_eltoo_htlc_onchain_fulfill(out, tx_parts,
						    &htlc_outpoint);

            /* FIXME this is impossible, commenting out */
//			if (out->tx_type == THEIR_REVOKED_UNILATERAL) {
//			} else {
            /* BOLT #5:
             *
             * ## HTLC Output Handling: Local Commitment,
             *    Local Offers
             *...
             *  - if the commitment transaction HTLC output
             *    is spent using the payment preimage, the
             *    output is considered *irrevocably resolved*
             */
            ignore_output(out);

            onchain_annotate_txout(
                &htlc_outpoint,
                TX_CHANNEL_HTLC_SUCCESS | TX_THEIRS);
//			}
			break;

		case FUNDING_OUTPUT:
			/* Master should be restarting us, as this implies
			 * that our old tx was unspent. */
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Funding output spent again!");
		/* Um, we don't track these! */
		case OUTPUT_TO_THEM:
		case DELAYED_OUTPUT_TO_THEM:
        case DELAYED_CHEAT_OUTPUT_TO_THEM:
        case DELAYED_OUTPUT_TO_US:
		case ELEMENTS_FEE:
		case ANCHOR_TO_US:
		case ANCHOR_TO_THEM:
			status_failed(STATUS_FAIL_INTERNAL_ERROR,
				      "Tracked spend of %s/%s?",
				      eltoo_tx_type_name(out->tx_type),
				      output_type_name(out->output_type));
		}
		return;
	}

	struct bitcoin_txid txid;
	wally_tx_input_get_txid(tx_parts->inputs[input_num], &txid);
	/* Not interesting to us, so unwatch the tx and all its outputs */
	status_debug("Notified about tx %s output %u spend, but we don't care",
		     type_to_string(tmpctx, struct bitcoin_txid, &txid),
		     tx_parts->inputs[input_num]->index);

	unwatch_txid(&tx_parts->txid);
}

static void update_resolution_depth(struct tracked_output *out, u32 depth)
{
	bool reached_reasonable_depth;

	status_debug("%s/%s->%s depth %u",
		     eltoo_tx_type_name(out->tx_type),
		     output_type_name(out->output_type),
		     eltoo_tx_type_name(out->resolved->tx_type),
		     depth);

	/* We only set this once. */
	reached_reasonable_depth = (out->resolved->depth < reasonable_depth
				    && depth >= reasonable_depth);

	/* BOLT #XX:
     *
     *  - if the settlement transaction HTLC output has *timed out* and hasn't been
     *    *resolved*:
     *    - MUST *resolve* the output by spending it using their own `settlement_pubkey` to
     *     any address deemed necessary.
     *    - once the resolving transaction has reached reasonable depth:
     *      - MUST fail the corresponding incoming HTLC (if any).
     *    - for any committed HTLC that has been trimmed:
     *      - once the update transaction that spent the funding output has reached reasonable depth:
     *        - MUST fail the corresponding incoming HTLC (if any).
     */
	if (out->resolved->tx_type == ELTOO_SWEEP && reached_reasonable_depth) {
		u8 *msg;
		status_debug("%s/%s reached reasonable depth %u",
			     eltoo_tx_type_name(out->tx_type),
			     output_type_name(out->output_type),
			     depth);
		msg = towire_onchaind_htlc_timeout(out, &out->htlc);
		wire_sync_write(REQ_FD, take(msg));
	}
	out->resolved->depth = depth;
}

static void eltoo_tx_new_depth(struct tracked_output **outs,
			 const struct bitcoin_txid *txid, u32 depth)
{
	size_t i;

    /* Special handling for funding-spending update tx reaching depth */
    /* FIXME re-add note_missing_htlcs for TRIMMED ONLY here... should this b
     * done immediately, not at "reasonable depth"?
     */
    if (bitcoin_txid_eq(&outs[0]->resolved->txid, txid)
        && depth >= reasonable_depth
        && missing_htlc_msgs) {
        status_debug("Sending %zu missing htlc messages",
                 tal_count(missing_htlc_msgs));
        for (i = 0; i < tal_count(missing_htlc_msgs); i++)
            wire_sync_write(REQ_FD, missing_htlc_msgs[i]);
        /* Don't do it again. */
        missing_htlc_msgs = tal_free(missing_htlc_msgs);
    }

	for (i = 0; i < tal_count(outs); i++) {
		/* Update output depth. */
		if (bitcoin_txid_eq(&outs[i]->outpoint.txid, txid))
			outs[i]->depth = depth;

		/* Is this tx resolving an output? */
		if (outs[i]->resolved) {
			if (bitcoin_txid_eq(&outs[i]->resolved->txid, txid)) {
				update_resolution_depth(outs[i], depth);
			}
			continue;
		}

		/* Otherwise, is this something we have a pending
		 * resolution for? */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
            && depth >= outs[i]->proposal->depth_required) {
			eltoo_proposal_meets_depth(outs[i]);
		}

		/* Otherwise, is this an output whose proposed resolution
		 * we should RBF?  */
		if (outs[i]->proposal
		    && bitcoin_txid_eq(&outs[i]->outpoint.txid, txid)
		    && eltoo_proposal_is_rbfable(outs[i]->proposal))
			eltoo_proposal_should_rbf(outs[i]);
	}
}

/* BOLT #XX:
 * FIXME add BOLT text
 */
/* Master makes sure we only get told preimages once other node is committed. */
static void eltoo_handle_preimage(struct tracked_output **outs,
			    const struct preimage *preimage)
{
	size_t i;
	struct sha256 sha;
	struct ripemd160 ripemd;

	sha256(&sha, preimage, sizeof(*preimage));
	ripemd160(&ripemd, &sha, sizeof(sha));

	for (i = 0; i < tal_count(outs); i++) {
		if (outs[i]->output_type != THEIR_HTLC)
			continue;

		if (!ripemd160_eq(&outs[i]->htlc.ripemd, &ripemd))
			continue;

		/* Too late? */
		if (outs[i]->resolved) {
			status_broken("HTLC already resolved by %s"
				     " when we found preimage",
				     eltoo_tx_type_name(outs[i]->resolved->tx_type));
			return;
		}

		/* stash the payment_hash so we can track this coin movement */
		outs[i]->payment_hash = sha;

		/* Discard any previous resolution.  Could be a timeout,
		 * could be due to multiple identical rhashes in tx. */
		outs[i]->proposal = tal_free(outs[i]->proposal);

        /* FIXME now that we know this output exists, we should resolve it */
	}
}

#if DEVELOPER
static void memleak_remove_globals(struct htable *memtable, const tal_t *topctx)
{
	if (keyset)
		memleak_remove_region(memtable, keyset, sizeof(*keyset));
	memleak_remove_pointer(memtable, topctx);
	memleak_remove_region(memtable,
			      missing_htlc_msgs, tal_bytelen(missing_htlc_msgs));
	memleak_remove_region(memtable,
			      queued_msgs, tal_bytelen(queued_msgs));
}

static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	struct htable *memtable;
	bool found_leak;

	if (!fromwire_onchaind_dev_memleak(msg))
		return false;

	memtable = memleak_find_allocations(tmpctx, msg, msg);
	/* Top-level context is parent of outs */
	memleak_remove_globals(memtable, tal_parent(outs));
	memleak_remove_region(memtable, outs, tal_bytelen(outs));

	found_leak = dump_memleak(memtable, memleak_status_broken);
	wire_sync_write(REQ_FD,
			take(towire_onchaind_dev_memleak_reply(NULL,
							      found_leak)));
	return true;
}
#else
static bool handle_dev_memleak(struct tracked_output **outs, const u8 *msg)
{
	return false;
}
#endif /* !DEVELOPER */

static void wait_for_resolved(struct tracked_output **outs)
{
	billboard_update(outs);

	while (num_not_irrevocably_resolved(outs) != 0) {
		u8 *msg;
		struct bitcoin_txid txid;
		u32 input_num, depth, tx_blockheight;
		struct preimage preimage;
		struct tx_parts *tx_parts;

		if (tal_count(queued_msgs)) {
			msg = tal_steal(outs, queued_msgs[0]);
			tal_arr_remove(&queued_msgs, 0);
		} else
			msg = wire_sync_read(outs, REQ_FD);

		status_debug("Got new message %s",
			     onchaind_wire_name(fromwire_peektype(msg)));

		if (fromwire_onchaind_depth(msg, &txid, &depth)) {
			eltoo_tx_new_depth(outs, &txid, depth);
        } else if (fromwire_onchaind_spent(msg, msg, &tx_parts, &input_num,
						&tx_blockheight)) {
            /* FIXME walk through logic with someone who knows what's going on  */
			output_spent(&outs, tx_parts, input_num, tx_blockheight);
		} else if (fromwire_onchaind_known_preimage(msg, &preimage))
            /* We could be watching our settlement outputs
               even if they haven't entered utxo set to use for CPFP. */
			eltoo_handle_preimage(outs, &preimage);
		else if (!handle_dev_memleak(outs, msg))
			master_badmsg(-1, msg);

		billboard_update(outs);
		tal_free(msg);
		clean_tmpctx();
	}

	wire_sync_write(REQ_FD,
			take(towire_onchaind_all_irrevocably_resolved(outs)));
}

struct htlcs_info {
	struct htlc_stub *htlcs;
	bool *tell_if_missing;
	bool *tell_immediately;
};

struct htlc_with_tells {
	struct htlc_stub htlc;
	bool tell_if_missing, tell_immediately;
};

static int cmp_htlc_with_tells_cltv(const struct htlc_with_tells *a,
                    const struct htlc_with_tells *b, void *unused)
{
    if (a->htlc.cltv_expiry < b->htlc.cltv_expiry)
        return -1;
    else if (a->htlc.cltv_expiry > b->htlc.cltv_expiry)
        return 1;
    return 0; 
}

/* sends eltoo reply to be handled properly, otherwise the same */
static struct htlcs_info *eltoo_init_reply(const tal_t *ctx, const char *what)
{
    struct htlcs_info *htlcs_info = tal(ctx, struct htlcs_info);
    u8 *msg;
    struct htlc_with_tells *htlcs;

    /* Send init_reply first, so billboard gets credited to ONCHAIND */
    wire_sync_write(REQ_FD,
            take(towire_eltoo_onchaind_init_reply(NULL)));

    peer_billboard(true, what);

    /* Read in htlcs */
    for (;;) {
        msg = wire_sync_read(queued_msgs, REQ_FD);
        if (fromwire_onchaind_htlcs(tmpctx, msg,
                        &htlcs_info->htlcs,
                        &htlcs_info->tell_if_missing,
                        &htlcs_info->tell_immediately)) {
            tal_free(msg);
            break;
        }

        /* Process later */
        tal_arr_expand(&queued_msgs, msg);
    }

    /* One convenient structure, so we sort them together! */
    htlcs = tal_arr(tmpctx, struct htlc_with_tells, tal_count(htlcs_info->htlcs));
    for (size_t i = 0; i < tal_count(htlcs); i++) {
        htlcs[i].htlc = htlcs_info->htlcs[i];
        htlcs[i].tell_if_missing = htlcs_info->tell_if_missing[i];
        htlcs[i].tell_immediately = htlcs_info->tell_immediately[i];
    }

    /* Sort by CLTV, so matches are in CLTV order (and easy to skip dups) */
    asort(htlcs, tal_count(htlcs), cmp_htlc_with_tells_cltv, NULL);

    /* Now put them back (prev were allocated off tmpctx) */
    htlcs_info->htlcs = tal_arr(htlcs_info, struct htlc_stub, tal_count(htlcs));
    htlcs_info->tell_if_missing = tal_arr(htlcs_info, bool, tal_count(htlcs));
    htlcs_info->tell_immediately = tal_arr(htlcs_info, bool, tal_count(htlcs));
    for (size_t i = 0; i < tal_count(htlcs); i++) {
        htlcs_info->htlcs[i] = htlcs[i].htlc;
        htlcs_info->tell_if_missing[i] = htlcs[i].tell_if_missing;
        htlcs_info->tell_immediately[i] = htlcs[i].tell_immediately;
    }

    return htlcs_info;
}

/* We always assume funding input is first index in outs */
static int funding_input_num(struct tracked_output **outs, const struct tx_parts *tx)
{
    int i;
    /* Annotate the input that matches the funding outpoint as close. We can currently only have a
     * single input for these. */
    for (i=0; i<tal_count(tx->inputs); i++) {
        if (tx->inputs[i]->index == outs[0]->outpoint.n &&
            !memcmp(tx->inputs[i]->txhash, &outs[0]->outpoint.txid, 32)) {
            break;
        }
    }
    assert(i != tal_count(tx->inputs));
    return i;
}

static void eltoo_handle_mutual_close(struct tracked_output **outs,
                const struct tx_parts *tx)
{

    /* In this case, we don't care about htlcs: there are none. */
    eltoo_init_reply(tmpctx, "Tracking mutual close transaction");

    onchain_annotate_txin(&tx->txid, funding_input_num(outs, tx), TX_CHANNEL_CLOSE);

    /* BOLT #5:
     *
     * A closing transaction *resolves* the funding transaction output.
     *
     * In the case of a mutual close, a node need not do anything else, as it has
     * already agreed to the output, which is sent to its specified `scriptpubkey`
     */
    resolved_by_other(outs[0], &tx->txid, MUTUAL_CLOSE);
    wait_for_resolved(outs);
}

static void handle_latest_update(const struct tx_parts *tx,
                  u32 tx_blockheight,
                  struct tracked_output **outs,
                  u32 locktime)
{
    struct htlcs_info *htlcs_info;
    struct bitcoin_outpoint outpoint;
    struct amount_asset asset;
    struct amount_sat amt;
    struct tracked_output *out;

    /* State output will match index */
    int state_index = funding_input_num(outs, tx);

    outpoint.txid = tx->txid;
    outpoint.n = state_index;

    asset = wally_tx_output_get_amount(tx->outputs[state_index]);
    amt = amount_asset_to_sat(&asset);

    htlcs_info = eltoo_init_reply(tmpctx, "Tracking final update transaction");
    /* FIXME do something with htlcs_info ? */
    assert(htlcs_info);
    onchain_annotate_txin(&tx->txid, state_index, TX_CHANNEL_UNILATERAL);

    resolved_by_other(outs[0], &tx->txid, ELTOO_UPDATE);

    out = new_tracked_output(&outs,
                 &outpoint, tx_blockheight,
                 UPDATE,
                 amt,
                 DELAYED_OUTPUT_TO_US,
                 NULL /* htlc */, NULL /* wscript */, NULL /* remote_htlc_sig */);

    /* Proposed resolution is the matching settlement tx */
    if (locktime == complete_update_tx->wtx->locktime) {
        bind_settle_tx(tx->txid, state_index, complete_settle_tx);
        propose_resolution(out, complete_settle_tx,  complete_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);
    } else {
        bind_settle_tx(tx->txid, state_index, committed_settle_tx);
        propose_resolution(out, committed_settle_tx, committed_settle_tx->wtx->inputs[0].sequence /* depth_required */, ELTOO_SETTLE);
    }

    /* Wait until we get shared_delay confirms for this output */
    wait_for_resolved(outs);
}

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
    struct tx_parts *spending_tx;
    struct tracked_output **outs;
    struct bitcoin_outpoint funding;
    struct amount_sat funding_sats;
    u32 locktime, tx_blockheight, max_known_version;
    u8 *scriptpubkey[NUM_SIDES];

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

    missing_htlc_msgs = tal_arr(ctx, u8 *, 0);
    queued_msgs = tal_arr(ctx, u8 *, 0);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_eltoo_onchaind_init(tmpctx,
        msg,
        &chainparams,
        &funding,
        &funding_sats,
        &spending_tx,
        &locktime,
        /* Transactions are global for ease of access */
        &complete_update_tx,
        &complete_settle_tx,
        &committed_update_tx,
        &committed_settle_tx,
        &tx_blockheight,
        &our_msat,
        &scriptpubkey[LOCAL],
        &scriptpubkey[REMOTE])) {
		master_badmsg(WIRE_ELTOO_ONCHAIND_INIT, msg);
	}

    // It's not configurable for ln-penalty, just set it here?
    reasonable_depth = 3;

	status_debug("lightningd_eltoo_onchaind is alive!");
	/* We need to keep tx around, but there's only a constant number: not really a leak */
	tal_steal(ctx, notleak(spending_tx));
	tal_steal(ctx, notleak(complete_update_tx));
	tal_steal(ctx, notleak(complete_settle_tx));

    status_debug("Unbound update and settle transactions to potentially broadcast: %s, %s",
        type_to_string(tmpctx, struct bitcoin_tx, complete_update_tx),
        type_to_string(tmpctx, struct bitcoin_tx, complete_settle_tx));

    if (committed_update_tx) {
	    tal_steal(ctx, notleak(committed_update_tx));
	    tal_steal(ctx, notleak(committed_settle_tx));
        status_debug("Unbound update and settle transactions committed but incomplete: %s, %s",
            type_to_string(tmpctx, struct bitcoin_tx, committed_update_tx),
            type_to_string(tmpctx, struct bitcoin_tx, committed_settle_tx));
    }

    /* These are the utxos we are interested in */
    outs = tal_arr(ctx, struct tracked_output *, 0);

    /* Tracking funding output which is spent already */
    new_tracked_output(&outs, &funding,
               0, /* We don't care about funding blockheight */
               FUNDING_TRANSACTION,
               funding_sats,
               FUNDING_OUTPUT, NULL, NULL, NULL);

    /* Record funding output spent */
    send_coin_mvt(take(new_coin_channel_close(NULL, &spending_tx->txid,
                          &funding, tx_blockheight,
                          our_msat,
                          funding_sats,
                          tal_count(spending_tx->outputs))));

    /* Committed state should be one step further max */
    max_known_version = complete_update_tx->wtx->locktime;
    if (committed_update_tx) {
        assert(complete_update_tx->wtx->locktime == committed_update_tx->wtx->locktime ||
                complete_update_tx->wtx->locktime == committed_update_tx->wtx->locktime + 1);
        max_known_version = committed_update_tx->wtx->locktime;
    }

    if (is_mutual_close(locktime)) {
        status_debug("Handling mutual close!");
        eltoo_handle_mutual_close(outs, spending_tx);
    } else {
        status_debug("Handling unilateral close!");
        if (locktime > max_known_version) {
            /* Might as well track the state output, see if it ends up in a settlement tx
             * So `to_node` values can be harvested, HTLCs rescued with counterparty's help?
             * Or we should immediately report all HTLCs as missing, failing these?
             */
            status_debug("Uh-oh, please be nice Mr Counterparty :(");
        } else if (locktime == max_known_version) {
            status_debug("Unilateral close of last known state detected");
            /* 
             * We are simply waiting for this particular update tx to mature
             * before getting the settlement tx on chain and sweeping outputs.
             */
            handle_latest_update(spending_tx, tx_blockheight, outs, locktime);
        } else if (locktime == complete_update_tx->wtx->locktime) {
            status_debug("Unilateral close of last complete state detected");
            /*
             * It's possible this last transaction will be over-written
             * by the committed state we don't have signatures for.
             */
            handle_latest_update(spending_tx, tx_blockheight, outs, locktime);
        } else {
            status_debug("Cheater!");
        }
    }

 	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
