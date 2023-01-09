#ifndef LIGHTNING_COMMON_KEYSET_H
#define LIGHTNING_COMMON_KEYSET_H
#include "config.h"
#include <bitcoin/pubkey.h>
#include <bitcoin/signature.h>

struct basepoints;

/* Keys needed to derive a particular commitment tx. */
struct keyset {
	struct pubkey self_revocation_key;
	struct pubkey self_htlc_key, other_htlc_key;
	struct pubkey self_delayed_payment_key;
	struct pubkey self_payment_key, other_payment_key;
};

/* Holds all information for a particular state being signed */
struct eltoo_sign {
    struct partial_sig self_psig, other_psig;
    struct musig_session session;
};

/* Keys needed to derive a particular update/settlement tx pair. */
struct eltoo_keyset {
	struct pubkey self_settle_key, other_settle_key;
    struct pubkey self_funding_key, other_funding_key;
    /* MuSig2 key using funding keys as input, session
     non-empty once partial sig created locally! */
    struct pubkey inner_pubkey;
    /* Cache for partial signature verification when checking
     * sigs against inner_pubkey
     */
    struct musig_keyagg_cache inner_cache;
    struct nonce self_next_nonce, other_next_nonce;
    /* State we can go to chain with at any point. */
    struct eltoo_sign last_complete_state;
    /* Will be stolen, so needs to be not copied directly with other state */
    struct bitcoin_tx *complete_update_tx;
    struct bitcoin_tx *complete_settle_tx;
    /* State we have committed to but have incomplete signatures for.
     * This may be used in channel reestablishment or for reacting
       to the appearance of the state on-chain. It should always contain
       the most recent partial signatures and session for a node.  */
    struct eltoo_sign last_committed_state;
    /* Will be stolen, so needs to be not copied directly with other state */
    struct bitcoin_tx *committed_update_tx;
    struct bitcoin_tx *committed_settle_tx;
};

/* Self == owner of commitment tx, other == non-owner. */
bool derive_keyset(const struct pubkey *per_commitment_point,
		   const struct basepoints *self,
		   const struct basepoints *other,
		   bool option_static_remotekey,
		   struct keyset *keyset);
#endif /* LIGHTNING_COMMON_KEYSET_H */
