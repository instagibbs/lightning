#include "config.h"
#include <bitcoin/psbt.h>
#include <bitcoin/script.h>
#include <ccan/tal/str/str.h>
#include <common/blockheight_states.h>
#include <common/channel_type.h>
#include <common/fee_states.h>
#include <common/initial_channel.h>
#include <common/initial_eltoo_channel.h>
#include <common/initial_settlement_tx.h>
#include <common/keyset.h>
#include <common/type_to_string.h>
#include <common/update_tx.h>

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
				    enum side opener)
{
	struct channel *channel = tal(ctx, struct channel);
	struct amount_msat remote_msatoshi;
    const struct pubkey *pubkey_ptrs[2];
    secp256k1_musig_keyagg_cache keyagg_cache;

	channel->cid = *cid;
	channel->funding = *funding;
	channel->funding_sats = funding_sats;
	channel->minimum_depth = minimum_depth;
	if (!amount_sat_sub_msat(&remote_msatoshi,
				 channel->funding_sats, local_msatoshi))
		return tal_free(channel);

	channel->opener = opener;
	channel->config[LOCAL] = *local;
	channel->config[REMOTE] = *remote;
	channel->eltoo_keyset.self_funding_key = *local_funding_pubkey;
	channel->eltoo_keyset.other_funding_key = *remote_funding_pubkey;
	channel->eltoo_keyset.self_settle_key = *local_settle_pubkey;
	channel->eltoo_keyset.other_settle_key = *remote_settle_pubkey;
	channel->eltoo_keyset.other_settle_key = *remote_settle_pubkey;
	channel->eltoo_keyset.self_psig = *self_psig;
	channel->eltoo_keyset.other_psig = *other_psig;
	channel->eltoo_keyset.session = *session;

	channel->htlcs = NULL;

    pubkey_ptrs[0] = local_funding_pubkey;
    pubkey_ptrs[1] = remote_funding_pubkey;
    bipmusig_inner_pubkey(&channel->eltoo_keyset.inner_pubkey,
           &keyagg_cache,
           pubkey_ptrs,
           2 /* n_pubkeys */);

	channel->view[LOCAL].owed[LOCAL]
		= channel->view[REMOTE].owed[LOCAL]
		= local_msatoshi;
	channel->view[REMOTE].owed[REMOTE]
		= channel->view[LOCAL].owed[REMOTE]
		= remote_msatoshi;

	channel->update_number_obscurer
		= 0;

	channel->option_wumbo = option_wumbo;
	/* takes() if necessary */
	channel->type = tal_dup(channel, struct channel_type, type);

	return channel;
}

struct bitcoin_tx *initial_settle_channel_tx(const tal_t *ctx,
				      const struct channel *channel,
				      struct wally_tx_output *direct_outputs[NUM_SIDES])
{
	struct bitcoin_tx *init_settle_tx;

	/* This assumes no HTLCs! */
	assert(!channel->htlcs);

    /* Note that funding prevout here is not quite right, but we'll re-bind at-chain time */
    init_settle_tx = initial_settlement_tx(ctx,
                    channel->funding_sats,
                    channel->config->shared_delay,
                    &channel->eltoo_keyset,
                    channel->config->dust_limit,
                    channel->view->owed[LOCAL],
                    channel->view->owed[REMOTE],
                    0 ^ channel->update_number_obscurer,
                    direct_outputs);

	if (init_settle_tx) {
		psbt_input_add_pubkey(init_settle_tx->psbt, 0,
				      &channel->eltoo_keyset.self_funding_key);
		psbt_input_add_pubkey(init_settle_tx->psbt, 0,
				      &channel->eltoo_keyset.other_funding_key);
	}

	return init_settle_tx;
}

struct bitcoin_tx *initial_update_channel_tx(const tal_t *ctx,
                      const struct bitcoin_tx *settle_tx,
				      const struct channel *channel)
{
	struct bitcoin_tx *init_update_tx;
    /* This should be gathered from settle_tx PSBT when stored there,
     * it's generated in initial_settlement_tx. This is unused otherwise.
     */
    struct pubkey dummy_inner_pubkey;
    memset(dummy_inner_pubkey.pubkey.data, 0, sizeof(dummy_inner_pubkey.pubkey.data));

	/* This assumes no HTLCs! */
	assert(!channel->htlcs);

	init_update_tx = unbound_update_tx(ctx,
                    settle_tx,
                    channel->funding_sats,
                    &dummy_inner_pubkey);

	if (init_update_tx) {
		psbt_input_add_pubkey(init_update_tx->psbt, 0,
				      &channel->eltoo_keyset.self_funding_key);
		psbt_input_add_pubkey(init_update_tx->psbt, 0,
				      &channel->eltoo_keyset.other_funding_key);
	}

	return init_update_tx;
}
