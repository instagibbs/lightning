#ifndef LIGHTNING_COMMON_HTLC_STATE_H
#define LIGHTNING_COMMON_HTLC_STATE_H
#include "config.h"

/*
 * /!\ The generated enum values are used in the database, DO NOT
 * reorder or insert new values (appending at the end is ok) /!\
 */
enum htlc_state {
	/* When _we_ add a new htlc, it goes in this order. */
	SENT_ADD_HTLC, /* --update_add_htlc--> */
	SENT_ADD_COMMIT, /* --commitment_signed--> */
	RCVD_ADD_REVOCATION, /* <--revoke_and_ack-- */
	RCVD_ADD_ACK_COMMIT, /* <--commitment_signed-- */
	SENT_ADD_ACK_REVOCATION, /* --revoke_and_ack--> */

	/* ... then when _they_ remove the HTLC: */
	RCVD_REMOVE_HTLC, /* <--update_{fulfill,fail,fail_malformed}_htlc-- */
	RCVD_REMOVE_COMMIT, /* rest of messages same as "add", in reverse direction */
	SENT_REMOVE_REVOCATION,
	SENT_REMOVE_ACK_COMMIT,
	RCVD_REMOVE_ACK_REVOCATION,

	/* When _they_ add a new htlc, it goes in this order. */
	RCVD_ADD_HTLC, 
	RCVD_ADD_COMMIT,
	SENT_ADD_REVOCATION,
	SENT_ADD_ACK_COMMIT,
	RCVD_ADD_ACK_REVOCATION,

	/* ... then when _we_ remove the HTLC: */
	SENT_REMOVE_HTLC,
	SENT_REMOVE_COMMIT,
	RCVD_REMOVE_REVOCATION,
	RCVD_REMOVE_ACK_COMMIT,
	SENT_REMOVE_ACK_REVOCATION,

	HTLC_STATE_INVALID
};

/* Eltoo: Only first three states in htlc_state are used */

/* SENT_ADD_HTLC is same*/
#define SENT_ADD_UPDATE (SENT_ADD_COMMIT)
#define RCVD_ADD_ACK (RCVD_ADD_REVOCATION)

/* SENT_REMOVE_HTLC is same */
#define SENT_REMOVE_UPDATE (SENT_REMOVE_COMMIT)
#define RCVD_REMOVE_ACK (RCVD_REMOVE_REVOCATION)

/* RCVD_ADD_HTLC is same*/
#define RCVD_ADD_UPDATE (RCVD_ADD_COMMIT)
#define SENT_ADD_ACK (SENT_ADD_REVOCATION)

/* RCVD_REMOVE_HTLC is same */
#define RCVD_REMOVE_UPDATE (RCVD_REMOVE_COMMIT)
#define SENT_REMOVE_ACK (SENT_REMOVE_REVOCATION)

/* HTLC_STATE_INVALID is same */

#endif /* LIGHTNING_COMMON_HTLC_STATE_H */
