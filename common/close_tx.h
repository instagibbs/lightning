#ifndef LIGHTNING_COMMON_CLOSE_TX_H
#define LIGHTNING_COMMON_CLOSE_TX_H
#include "config.h"
#include <bitcoin/tx.h>

struct ext_key;

/* Create close tx to spend the anchor tx output; doesn't fill in
 * input scriptsig. */
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
				   struct amount_sat dust_limit);

/* Transaction variants for option_simple_close */
enum close_tx_variant {
	CLOSE_TX_BOTH_OUTPUTS = 0,	/* Both closer and closee outputs */
	CLOSE_TX_CLOSER_ONLY = 1,	/* Only closer's output */
	CLOSE_TX_CLOSEE_ONLY = 2,	/* Only closee's output */
};

/* Check if script is a valid OP_RETURN for option_simple_close.
 * Valid: OP_RETURN followed by 6-80 bytes of data (single push).
 * The 6-byte minimum prevents 64-byte stripped transactions (CVE-2017-12842).
 */
bool is_valid_op_return_close(const u8 *script);

/* Create simple close tx (option_simple_close variant).
 * - closer_script: the sender's (closer's) output script
 * - closee_script: the receiver's (closee's) output script
 * - closer_balance: closer's balance before fee
 * - closee_balance: closee's balance
 * - closer_fee: fee paid by closer from their balance
 * - dust_limit: outputs below this are invalid (unless OP_RETURN)
 * - locktime: nLockTime for the transaction
 * - variant: which outputs to include
 *
 * Returns NULL if the requested variant is invalid (e.g., dust output
 * without OP_RETURN script, or both outputs dust with BOTH variant).
 */
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
					  enum close_tx_variant variant);

#endif /* LIGHTNING_COMMON_CLOSE_TX_H */
