#include "config.h"
#include <bitcoin/script.h>
#include <bitcoin/tx.h>
#include <ccan/array_size/array_size.h>
#include <common/initial_update_tx.h>
#include <common/keyset.h>
#include <common/permute_tx.h>
#include <common/status.h>
#include <common/type_to_string.h>
#include <stdio.h>
#include <wally_psbt.h>

#ifndef SUPERVERBOSE
#define SUPERVERBOSE(...)
#endif

struct wally_psbt;

int tx_add_settlement_output(struct bitcoin_tx *update_tx, const struct bitcoin_tx *settle_tx)
{
    struct amount_sat amount;
    amount.satoshis = settle_tx->psbt->inputs[0].witness_utxo->satoshi;
    return bitcoin_tx_add_output( 
        update_tx, settle_tx->psbt->inputs[0].witness_utxo->script, /* wscript */ NULL, amount /* FIXME pass in psbt fields for tap outputs */);
}

u8 *make_eltoo_annex(const tal_t *ctx, const struct bitcoin_tx *settle_tx)
{
    int ok;
    struct sha256 result;
    u8 *preimage_cursor;
    u8 *settle_tapscript = make_eltoo_settle_script(tmpctx, settle_tx, /* input_num */ 0);
    u64 tapscript_len = tal_count(settle_tapscript);
    u8 *tapleaf_preimage = tal_arr(ctx, u8, 1 + varint_size(tapscript_len) + tapscript_len);
    /* Enough space for annex flag plus the one hash we want published */
    u8 *annex = tal_arr(ctx, u8, 1 + sizeof(result.u.u8));

    preimage_cursor = tapleaf_preimage;
    preimage_cursor[0] = 0xC0;
    preimage_cursor++;
    preimage_cursor += varint_put(preimage_cursor, tapscript_len);
    memcpy(preimage_cursor, settle_tapscript, tapscript_len);
    preimage_cursor += tapscript_len;

    assert(tal_count(tapleaf_preimage) == preimage_cursor - tapleaf_preimage);
    printf("***ANNEX PREIMAGE***: %s\n", tal_hexstr(tmpctx, tapleaf_preimage, tal_count(tapleaf_preimage)));
    ok = wally_tagged_hash(tapleaf_preimage, tal_count(tapleaf_preimage), "TapLeaf", result.u.u8);
    assert(ok == WALLY_OK);
    printf("TAPLEAF HASH(annex): %s\n", tal_hexstr(tmpctx, result.u.u8, 32));

    annex[0] = 0x50; /* annex flag */
    memcpy(annex + 1, result.u.u8, sizeof(result));
    return annex;
}

void tx_add_funding_input(struct bitcoin_tx *update_tx, const struct bitcoin_tx *settle_tx, const struct bitcoin_outpoint *funding_outpoint, struct amount_sat funding_outpoint_sats, const struct eltoo_keyset *eltoo_keyset)
{
    int input_num;
    const struct pubkey *pubkey_ptrs[2];
    u8 *update_tapscript[1];
    /* For committing to the output's settle path tapleaf hash inside the annex itself */
    u8 *script_pubkey;
    struct sha256 update_merkle_root;
    struct pubkey update_agg_pk;
    secp256k1_musig_keyagg_cache update_keyagg_cache;
    unsigned char update_tap_tweak[32];

   /* For MuSig aggregation for outputs */
    pubkey_ptrs[0] = &(eltoo_keyset->self_funding_key);
    pubkey_ptrs[1] = &(eltoo_keyset->other_funding_key);

    update_tapscript[0] = make_eltoo_funding_update_script(tmpctx);

    compute_taptree_merkle_root(&update_merkle_root, update_tapscript, /* num_scripts */ 1);
    bipmusig_finalize_keys(&update_agg_pk,
           &update_keyagg_cache,
           pubkey_ptrs,
           /* n_pubkeys */ 2,
           &update_merkle_root,
           update_tap_tweak);

    script_pubkey = scriptpubkey_p2tr(tmpctx, &update_agg_pk);

    input_num = bitcoin_tx_add_input(update_tx, funding_outpoint, /* sequence */ 0xFFFFFFFD,
                 /* scriptSig */ NULL, funding_outpoint_sats, script_pubkey, /* input_wscript */ NULL, /* inner_pubkey */ NULL, /* tap_tree */ NULL);
    assert(input_num == 0);
}


struct bitcoin_tx *initial_update_tx(const tal_t *ctx,
                     const struct bitcoin_tx *settle_tx,
				     const struct bitcoin_outpoint *funding_outpoint,
                     struct amount_sat funding_outpoint_sats,
                     const struct eltoo_keyset *eltoo_keyset,
				     char** err_reason)
{
	struct bitcoin_tx *update_tx;
    int pos;

    /* 1 input 1 output tx */
    update_tx = bitcoin_tx(ctx, chainparams, 1, 1, 0);

    /* Add output */
    pos = tx_add_settlement_output(update_tx, settle_tx);
    assert(pos == 0);

    /* Add unsigned funding input (but includes annex commitment!) */
    tx_add_funding_input(update_tx, settle_tx, funding_outpoint, funding_outpoint_sats, eltoo_keyset);

    /* Set global fields */
    assert(update_tx->wtx->version == 2);
    bitcoin_tx_set_locktime(update_tx,
        settle_tx->wtx->locktime);

    bitcoin_tx_finalize(update_tx);

    return update_tx;
}
