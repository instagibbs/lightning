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

void tx_add_unbound_input(struct bitcoin_tx *update_tx, struct amount_sat funding_sats, const secp256k1_xonly_pubkey *inner_pubkey)
{
    int input_num;

    /* FIXME this field needs to be stored in PSBT via bitcoin_tx_add_unbound_input */
    assert(inner_pubkey);

    input_num = bitcoin_tx_add_unbound_input(update_tx, /* sequence */ 0xFFFFFFFD, funding_sats, inner_pubkey);
    assert(input_num == 0);
}

void bind_update_tx_to_funding_outpoint(struct bitcoin_tx *update_tx,
                    const struct bitcoin_tx *settle_tx,
                    const struct bitcoin_outpoint *funding_outpoint,
                    const struct eltoo_keyset *eltoo_keyset,
                    secp256k1_xonly_pubkey *psbt_inner_pubkey,
                    u8 *final_sig)
{
    const struct pubkey *pubkey_ptrs[2];
    u8 *update_tapscript[1];
    int input_num;
    /* For committing to the output's settle path tapleaf hash inside the annex itself */
    u8 *script_pubkey;
    struct pubkey taproot_pk;
    secp256k1_musig_keyagg_cache unused_coop_cache;
    u8 **update_witness;
    struct amount_sat funding_sats;

    /* Stuff that should go in PSBT eventually */
    struct sha256 psbt_tap_merkle_root;
    unsigned char psbt_tap_tweak[32];

   /* For MuSig aggregation for outputs */
    pubkey_ptrs[0] = &(eltoo_keyset->self_funding_key);
    pubkey_ptrs[1] = &(eltoo_keyset->other_funding_key);

    /* FIXME embed this in PSBT as well... */
    update_tapscript[0] = make_eltoo_funding_update_script(tmpctx);

    compute_taptree_merkle_root(&psbt_tap_merkle_root, update_tapscript, /* num_scripts */ 1);

    bipmusig_finalize_keys(&taproot_pk,
           &unused_coop_cache,
           pubkey_ptrs,
           /* n_pubkeys */ 2,
           &psbt_tap_merkle_root,
           psbt_tap_tweak);

    script_pubkey = scriptpubkey_p2tr(tmpctx, &taproot_pk);

    /* Remove existing input since we're over-writing all details */
    funding_sats.satoshis = update_tx->psbt->inputs[0].witness_utxo->satoshi;
    bitcoin_tx_remove_input(update_tx, /* input_num */ 0);

    /* FIXME carry inner pubkey and tapscript/taptree info in PSBT, even though not needed to complete this tx per se */
    input_num = bitcoin_tx_add_input(update_tx, funding_outpoint, /* sequence */ 0xFFFFFFFD,
                 /* scriptSig */ NULL, funding_sats, script_pubkey, /* input_wscript */ NULL, /* inner_pubkey */ NULL, /* tap_tree */ NULL);
    assert(input_num == 0);

    /* FIXME we can now rebind settle_tx's prevout */

    /* Witness stack, bottom to top:  MuSig2 sig + tapscript + control block + Annex data */
    update_witness = tal_arr(tmpctx, u8 *, 4);
    update_witness[0] = final_sig;
    update_witness[1] = update_tapscript[0];
    update_witness[2] = compute_control_block(tmpctx, /* other_script */ NULL, /* annex_hint */ NULL, psbt_inner_pubkey, pubkey_parity(&taproot_pk));
    update_witness[3] = make_eltoo_annex(tmpctx, settle_tx);;
    bitcoin_tx_input_set_witness(update_tx, /* input_num */ 0, update_witness);
}

void bind_update_tx_to_update_outpoint(struct bitcoin_tx *update_tx,
                    struct bitcoin_tx *settle_tx,
                    const struct bitcoin_outpoint *outpoint,
                    const struct eltoo_keyset *eltoo_keyset,
                    const u8 *invalidated_annex_hint,
                    u32 invalidated_update_number,
                    secp256k1_xonly_pubkey *psbt_inner_pubkey,
                    u8 *final_sig)
{
    const struct pubkey *pubkey_ptrs[2];
    u8 *update_tapscript;
    int input_num;
    /* For committing to the output's settle path tapleaf hash inside the annex itself */
    u8 *script_pubkey;
    struct pubkey taproot_pk;
    secp256k1_musig_keyagg_cache unused_coop_cache;
    u8 **update_witness;
    struct amount_sat funding_sats;

    /* Stuff that should go in PSBT eventually */
    struct sha256 psbt_tap_merkle_root;
    unsigned char psbt_tap_tweak[32];

   /* For MuSig aggregation for outputs */
    pubkey_ptrs[0] = &(eltoo_keyset->self_funding_key);
    pubkey_ptrs[1] = &(eltoo_keyset->other_funding_key);

    /* FIXME embed this in PSBT as well... */
    update_tapscript = make_eltoo_update_script(tmpctx, invalidated_update_number);

    compute_taptree_merkle_root_with_hint(&psbt_tap_merkle_root, update_tapscript, invalidated_annex_hint);

    bipmusig_finalize_keys(&taproot_pk,
           &unused_coop_cache,
           pubkey_ptrs,
           /* n_pubkeys */ 2,
           &psbt_tap_merkle_root,
           psbt_tap_tweak);

    script_pubkey = scriptpubkey_p2tr(tmpctx, &taproot_pk);

    /* Remove existing input since we're over-writing all details */
    funding_sats.satoshis = update_tx->psbt->inputs[0].witness_utxo->satoshi;
    bitcoin_tx_remove_input(update_tx, /* input_num */ 0);

    /* FIXME carry inner pubkey and tapscript/taptree info in PSBT, even though not needed to complete this tx per se */
    input_num = bitcoin_tx_add_input(update_tx, outpoint, /* sequence */ 0xFFFFFFFD,
                 /* scriptSig */ NULL, funding_sats, script_pubkey, /* input_wscript */ NULL, /* inner_pubkey */ NULL, /* tap_tree */ NULL);
    assert(input_num == 0);

    /* FIXME we can now rebind settle_tx's prevout */

    /* Witness stack, bottom to top:  MuSig2 sig + tapscript + control block + Annex data */
    update_witness = tal_arr(tmpctx, u8 *, 4);
    update_witness[0] = final_sig;
    update_witness[1] = update_tapscript;
    update_witness[2] = compute_control_block(tmpctx, /* other_script */ NULL, invalidated_annex_hint, psbt_inner_pubkey, pubkey_parity(&taproot_pk));
    update_witness[3] = make_eltoo_annex(tmpctx, settle_tx);
    bitcoin_tx_input_set_witness(update_tx, /* input_num */ 0, update_witness);
}

struct bitcoin_tx *unbound_update_tx(const tal_t *ctx,
                     const struct bitcoin_tx *settle_tx,
                     struct amount_sat funding_sats,
                     const secp256k1_xonly_pubkey *inner_pubkey,
				     char** err_reason)
{
	struct bitcoin_tx *update_tx;
    int pos;

    /* 1 input 1 output tx */
    update_tx = bitcoin_tx(ctx, chainparams, 1, 1, 0);

    /* Add output */
    pos = tx_add_settlement_output(update_tx, settle_tx);
    assert(pos == 0);

    /* Add unsigned, un-bound funding input */
    tx_add_unbound_input(update_tx, funding_sats, inner_pubkey);

    /* Set global fields */
    assert(update_tx->wtx->version == 2);
    bitcoin_tx_set_locktime(update_tx,
        settle_tx->wtx->locktime);

    bitcoin_tx_finalize(update_tx);

    return update_tx;
}
