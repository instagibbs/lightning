#include "config.h"
#include <assert.h>
#include <bitcoin/pubkey.h>
#include <bitcoin/script.h>
#include <bitcoin/signature.h>
#include <common/eltoo_close_tx.h>
#include <common/permute_tx.h>

struct bitcoin_tx *create_eltoo_close_tx(const tal_t *ctx,
					 const struct chainparams *chainparams,
					 const struct bitcoin_outpoint *funding,
					 struct amount_sat funding_sats,
					 const struct pubkey *local_funding_key,
					 const struct pubkey *remote_funding_key,
					 const u8 *local_scriptpubkey,
					 const u8 *remote_scriptpubkey,
					 struct amount_sat to_local,
					 struct amount_sat to_remote)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;
	struct amount_sat total_out;
	u8 *script;
	u8 *funding_spk;

	assert(amount_sat_add(&total_out, to_local, to_remote));
	assert(amount_sat_less_eq(total_out, funding_sats));

	/* Compute the funding scriptPubKey from the funding keys */
	funding_spk = scriptpubkey_eltoo_funding(ctx, local_funding_key, remote_funding_key);

	/* Eltoo close transaction:
	 * - version: 3 (TRUC for package relay)
	 * - locktime: 0
	 * - txin count: 1
	 * - sequence: 0xFFFFFFFF (finalized)
	 *
	 * This is a key-path spend of the funding output using MuSig2
	 * with SIGHASH_ALL (not ANYPREVOUT like update transactions).
	 */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, 0);

	/* Set version to 3 for TRUC (Topologically Restricted Until Confirmation) */
	tx->wtx->version = 3;

	/* Input spends the funding output with max sequence (finalized) */
	bitcoin_tx_add_input(tx, funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_sats, funding_spk, NULL, NULL, NULL);

	/* Add local output if above dust */
	if (amount_sat_greater_eq(to_local, ELTOO_DUST_LIMIT)) {
		script = tal_dup_talarr(tx, u8, local_scriptpubkey);
		bitcoin_tx_add_output(tx, script, NULL, to_local);
		num_outputs++;
	}

	/* Add remote output if above dust */
	if (amount_sat_greater_eq(to_remote, ELTOO_DUST_LIMIT)) {
		script = tal_dup_talarr(tx, u8, remote_scriptpubkey);
		bitcoin_tx_add_output(tx, script, NULL, to_remote);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	/* BIP69 output ordering for deterministic transaction structure */
	permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}
