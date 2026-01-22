#include "config.h"
#include <assert.h>
#include <bitcoin/script.h>
#include <common/close_tx.h>
#include <common/permute_tx.h>
#include <common/psbt_keypath.h>

/* BOLT #2:
 * 4. if (and only if) `option_simple_close` is negotiated:
 *    * `OP_RETURN` followed by one of:
 *      * `6` to `75` inclusive followed by exactly that many bytes
 *      * `76` followed by `76` to `80` followed by exactly that many bytes
 *
 * The 6-byte minimum prevents 64-byte stripped transactions (CVE-2017-12842).
 */
bool is_valid_op_return_close(const u8 *script)
{
	size_t len = tal_bytelen(script);

	if (len < 2)
		return false;

	/* Must start with OP_RETURN (0x6a) */
	if (script[0] != 0x6a)
		return false;

	/* Check push opcode and length */
	u8 push_opcode = script[1];

	/* Direct push: opcode 6-75 means push that many bytes */
	if (push_opcode >= 6 && push_opcode <= 75) {
		/* Script should be: OP_RETURN + opcode + data */
		return len == 2 + push_opcode;
	}

	/* OP_PUSHDATA1 (76): next byte is length 76-80 */
	if (push_opcode == 76 && len >= 3) {
		u8 data_len = script[2];
		if (data_len >= 76 && data_len <= 80) {
			/* Script should be: OP_RETURN + 76 + len_byte + data */
			return len == 3 + data_len;
		}
	}

	return false;
}

struct bitcoin_tx *create_simple_close_tx(const tal_t *ctx,
					  const struct chainparams *chainparams,
					  u32 *local_wallet_index,
					  const struct ext_key *local_wallet_ext_key,
					  const u8 *closer_script,
					  const u8 *closee_script,
					  const u8 *funding_wscript,
					  const struct bitcoin_outpoint *funding,
					  struct amount_sat funding_sats,
					  struct amount_sat closer_balance,
					  struct amount_sat closee_balance,
					  struct amount_sat closer_fee,
					  struct amount_sat dust_limit,
					  u32 locktime,
					  enum close_tx_variant variant)
{
	struct bitcoin_tx *tx;
	struct amount_sat closer_output, closee_output;
	size_t num_outputs = 0;
	bool closer_is_op_return, closee_is_op_return;
	u8 *script;

	/* Closer pays fee from their balance */
	if (!amount_sat_sub(&closer_output, closer_balance, closer_fee))
		return NULL;  /* Can't afford fee */

	closee_output = closee_balance;

	/* Check for OP_RETURN scripts */
	closer_is_op_return = is_valid_op_return_close(closer_script);
	closee_is_op_return = is_valid_op_return_close(closee_script);

	/* Validate outputs for requested variant */
	switch (variant) {
	case CLOSE_TX_BOTH_OUTPUTS:
		/* Both outputs must be valid (>= dust or OP_RETURN) */
		if (!closer_is_op_return &&
		    amount_sat_less(closer_output, dust_limit))
			return NULL;
		if (!closee_is_op_return &&
		    amount_sat_less(closee_output, dust_limit))
			return NULL;
		num_outputs = 2;
		break;

	case CLOSE_TX_CLOSER_ONLY:
		/* Closer output must be valid */
		if (!closer_is_op_return &&
		    amount_sat_less(closer_output, dust_limit))
			return NULL;
		num_outputs = 1;
		break;

	case CLOSE_TX_CLOSEE_ONLY:
		/* Closee output must be valid */
		if (!closee_is_op_return &&
		    amount_sat_less(closee_output, dust_limit))
			return NULL;
		num_outputs = 1;
		break;
	}

	/* BOLT #3:
	 *
	 * ## Closing Transaction (v2)
	 *
	 * This variant is used for `closing_complete` and `closing_sig`
	 * messages (i.e. where `option_simple_close` is negotiated).
	 *
	 * * version: 2
	 * * locktime: `closing_complete.locktime`
	 * * txin count: 1
	 *    * `txin[0]` outpoint: `txid` and `output_index` from `funding_created` message
	 *    * `txin[0]` sequence: 0xFFFFFFFD
	 *    * `txin[0]` script bytes: 0
	 *    * `txin[0]` witness: `0 <signature_for_pubkey1> <signature_for_pubkey2>`
	 */
	tx = bitcoin_tx(ctx, chainparams, 1, num_outputs, locktime);

	/* Input spends the funding output.
	 * Sequence 0xFFFFFFFD allows locktime and signals RBF. */
	bitcoin_tx_add_input(tx, funding,
			     0xFFFFFFFD, NULL,
			     funding_sats, NULL, funding_wscript);

	/* Add closer output if applicable */
	if (variant == CLOSE_TX_BOTH_OUTPUTS || variant == CLOSE_TX_CLOSER_ONLY) {
		struct amount_sat amt;

		script = tal_dup_talarr(tx, u8, closer_script);

		/* OP_RETURN outputs have amount 0 */
		amt = closer_is_op_return ? AMOUNT_SAT(0) : closer_output;

		bitcoin_tx_add_output(tx, script, NULL, amt);

		/* Add keypath for wallet output if not OP_RETURN */
		if (!closer_is_op_return && local_wallet_index) {
			size_t script_len = tal_bytelen(script);
			assert(local_wallet_ext_key != NULL);
			if (!psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index, local_wallet_ext_key,
				    is_p2tr(script, script_len, NULL)))
				return tal_free(tx);
		}
	}

	/* Add closee output if applicable */
	if (variant == CLOSE_TX_BOTH_OUTPUTS || variant == CLOSE_TX_CLOSEE_ONLY) {
		struct amount_sat amt;

		script = tal_dup_talarr(tx, u8, closee_script);

		/* OP_RETURN outputs have amount 0 */
		amt = closee_is_op_return ? AMOUNT_SAT(0) : closee_output;

		bitcoin_tx_add_output(tx, script, NULL, amt);
	}

	/* Permute outputs for privacy (if 2 outputs) */
	if (num_outputs > 1)
		permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}

struct bitcoin_tx *create_close_tx(const tal_t *ctx,
				   const struct chainparams *chainparams,
				   u32 *local_wallet_index,
				   const struct ext_key *local_wallet_ext_key,
				   const u8 *our_script,
				   const u8 *their_script,
				   const u8 *funding_wscript,
				   const struct bitcoin_outpoint *funding,
				   struct amount_sat funding_sats,
				   struct amount_sat to_us,
				   struct amount_sat to_them,
				   struct amount_sat dust_limit)
{
	struct bitcoin_tx *tx;
	size_t num_outputs = 0;
	struct amount_sat total_out;
	u8 *script;

	assert(amount_sat_add(&total_out, to_us, to_them));
	assert(amount_sat_less_eq(total_out, funding_sats));

	/* BOLT #3:
	 *
	 * ## Legacy Closing Transaction
	 *
	 * This variant is used for `closing_signed` messages (i.e. where
	 * `option_simple_close` is not negotiated).
	 *
	 * Note that there are two possible variants for each node.
	 *
	 * * version: 2
	 * * locktime: 0
	 * * txin count: 1
	 */
	/* Now create close tx: one input, two outputs. */
	tx = bitcoin_tx(ctx, chainparams, 1, 2, 0);

	/* Our input spends the anchor tx output. */
	bitcoin_tx_add_input(tx, funding,
			     BITCOIN_TX_DEFAULT_SEQUENCE, NULL,
			     funding_sats, NULL, funding_wscript);

	if (amount_sat_greater_eq(to_us, dust_limit)) {
		script = tal_dup_talarr(tx, u8, our_script);
		/* One output is to us. */
		bitcoin_tx_add_output(tx, script, NULL, to_us);
		assert((local_wallet_index == NULL) == (local_wallet_ext_key == NULL));
		if (local_wallet_index) {
			size_t script_len = tal_bytelen(script);
			/* Should not happen! */
			if (!psbt_add_keypath_to_last_output(
				    tx, *local_wallet_index, local_wallet_ext_key,
				    is_p2tr(script, script_len, NULL)))
				return tal_free(tx);
                }
		num_outputs++;
	}

	if (amount_sat_greater_eq(to_them, dust_limit)) {
		script = tal_dup_talarr(tx, u8, their_script);
		/* Other output is to them. */
		bitcoin_tx_add_output(tx, script, NULL, to_them);
		num_outputs++;
	}

	/* Can't have no outputs at all! */
	if (num_outputs == 0)
		return tal_free(tx);

	permute_outputs(tx, NULL, NULL);

	bitcoin_tx_finalize(tx);
	assert(bitcoin_tx_check(tx));
	return tx;
}
