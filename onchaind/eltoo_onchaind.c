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

/* Our recorded channel balance at 'chain time' */
static struct amount_msat our_msat;

/* FIXME looks like a lot of copy/paste, revisit */
struct tracked_output {
    enum tx_type tx_type;
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

static const char *tx_type_name(enum tx_type tx_type)
{
    size_t i;

    for (i = 0; enum_tx_type_names[i].name; i++)
        if (enum_tx_type_names[i].v == tx_type)
            return enum_tx_type_names[i].name;
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
           enum tx_type tx_type,
           struct amount_sat sat,
           enum output_type output_type,
           const struct htlc_stub *htlc,
           const u8 *wscript,
           const struct bitcoin_signature *remote_htlc_sig TAKES)
{
    struct tracked_output *out = tal(*outs, struct tracked_output);

    status_debug("Tracking output %s: %s/%s",
             type_to_string(tmpctx, struct bitcoin_outpoint, outpoint),
             tx_type_name(tx_type),
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

int main(int argc, char *argv[])
{
	setup_locale();

	const tal_t *ctx = tal(NULL, char);
	u8 *msg;
    struct tx_parts *spending_tx;
    struct bitcoin_tx *unbound_update_tx, *unbound_settle_tx;
    struct tracked_output **outs;
    struct bitcoin_outpoint funding;
    u32 input_num;
    struct amount_sat funding_sats;
    u32 tx_blockheight;

	subdaemon_setup(argc, argv);

	status_setup_sync(REQ_FD);

	msg = wire_sync_read(tmpctx, REQ_FD);
	if (!fromwire_eltoo_onchaind_init(tmpctx,
        msg,
        &chainparams,
        &funding_sats,
        &spending_tx,
        &input_num,
        &unbound_update_tx,
        &unbound_settle_tx,
        &tx_blockheight,
        &our_msat)) {
		master_badmsg(WIRE_ELTOO_ONCHAIND_INIT, msg);
	}

	status_debug("lightningd_eltoo_onchaind is alive!");
	/* We need to keep tx around, but there's only one: not really a leak */
	tal_steal(ctx, notleak(spending_tx));
	tal_steal(ctx, notleak(unbound_update_tx));
	tal_steal(ctx, notleak(unbound_settle_tx));

    status_debug("Unbound update and settle transactions to potentially broadcast: %s, %s",
        type_to_string(tmpctx, struct bitcoin_tx, unbound_update_tx),
        type_to_string(tmpctx, struct bitcoin_tx, unbound_settle_tx));

    /* These are the utxos we are interested in */
    outs = tal_arr(ctx, struct tracked_output *, 0);

    assert(tal_count(spending_tx->inputs) > input_num);
    wally_tx_input_get_txid(spending_tx->inputs[0], &funding.txid);
    funding.n = spending_tx->inputs[input_num]->index;

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


    /* FIXME Now that we see the transaction in block, and our latest versions,
      re-bind our transactions and submit them to the mempool */

    /* FIXME More stuff to come, sit and wait for a response that shouldn't come */
	msg = wire_sync_read(tmpctx, REQ_FD);

	/* We're done! */
	tal_free(ctx);
	daemon_shutdown();

	return 0;
}
