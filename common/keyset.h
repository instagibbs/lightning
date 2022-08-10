#ifndef LIGHTNING_COMMON_KEYSET_H
#define LIGHTNING_COMMON_KEYSET_H
#include "config.h"
#include <bitcoin/pubkey.h>

struct basepoints;

/* Keys needed to derive a particular commitment tx. */
struct keyset {
	struct pubkey self_revocation_key;
	struct pubkey self_htlc_key, other_htlc_key;
	struct pubkey self_delayed_payment_key;
	struct pubkey self_payment_key, other_payment_key;
};

/* Keys needed to derive a particular update/settlement tx pair. */
struct eltoo_keyset {
	struct pubkey self_settle_key, other_settle_key;
    struct pubkey self_funding_key, other_funding_key;
    /* MuSig2 key using funding keys as input */
    struct pubkey inner_pubkey;
};

/* Self == owner of commitment tx, other == non-owner. */
bool derive_keyset(const struct pubkey *per_commitment_point,
		   const struct basepoints *self,
		   const struct basepoints *other,
		   bool option_static_remotekey,
		   struct keyset *keyset);
#endif /* LIGHTNING_COMMON_KEYSET_H */
