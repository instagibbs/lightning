---
title: Zero-Fee Commitment Channels
slug: zero-fee-channels
content:
  excerpt: >-
    Technical documentation for CLN's implementation of zero-fee commitment
    channels using v3/TRUC transactions and ephemeral anchors (BOLT #1228).
privacy:
  view: public
---

# Zero-Fee Commitment Channels

This document describes the implementation of zero-fee commitment channels in Core Lightning, based on [BOLT PR #1228](https://github.com/lightning/bolts/pull/1228).

## Overview

Zero-fee commitment channels are a new channel type that eliminates commitment transaction fees by using Bitcoin Core's v3 (TRUC - Topologically Restricted Until Confirmation) transactions with ephemeral anchors. Instead of embedding fees in the commitment transaction at signing time, fees are paid via Child-Pays-For-Parent (CPFP) at broadcast time.

### Key Benefits

- **No `update_fee` messages**: Eliminates a major source of force-closes due to fee disagreements
- **Better pinning resistance**: v3 transaction rules limit descendant size and count
- **Reduced on-chain footprint**: Single shared P2A anchor instead of two 330-sat anchors
- **Deterministic capacity**: No fee buffers needed in channel reserves
- **Future-proof fees**: Fees determined at broadcast time, not signing time

## Feature Bits

- **Feature 40/41**: `option_zero_fee_commitments`
- **Prerequisites**: Requires `option_static_remotekey` (12/13) and `option_anchors_zero_fee_htlc_tx` (22/23)

## Transaction Structure

### Commitment Transaction (v3)

```
Version: 3 (TRUC transaction)
Inputs:
  - funding_txid:funding_output_index (2-of-2 multisig)
Outputs:
  - to_local (if > dust): P2WSH with revocation + CSV delay
  - to_remote (if > dust): P2WSH with static remotekey
  - HTLCs: offered/received as usual
  - anchor: P2A output (OP_1 <0x4e73>)
Fee: 0 satoshis
```

### Pay-to-Anchor (P2A) Output

The anchor output uses the standard P2A script:

```
OP_1 <0x4e73>
```

This is an anyone-can-spend output with a dust limit of 240 satoshis. The anchor amount is calculated as:

```
anchor_amount = MIN(
    sum(trimmed_htlc_values) + sum(msat_remainders),
    240 satoshis
)
```

Where:
- `trimmed_htlc_values`: HTLCs that are below the dust threshold and not included as separate outputs
- `msat_remainders`: Millisatoshi amounts that were rounded down when converting to satoshis for `to_local` and `to_remote` outputs

## Implementation Details

### Affected Files

| File | Changes |
|------|---------|
| `common/features.c/h` | Feature bit 40/41 definition |
| `common/channel_type.c/h` | Zero-fee channel type creation and detection |
| `common/initial_commit_tx.c/h` | v3 commitment tx construction, P2A anchor |
| `lightningd/options.c` | `--experimental-zero-fee-channels` config |
| `channeld/channeld.c` | Skip `update_fee`, validate peer commitments |
| `channeld/commit_tx.c` | Build zero-fee commitment transactions |
| `onchaind/onchaind.c` | Handle P2A anchor, CPFP broadcasting |
| `openingd/common.c` | HTLC limit (114 vs 483) for v3 size constraints |
| `bitcoin/tx.c/h` | P2A script constants |

### Key Functions

#### Channel Type Detection

```c
// common/channel_type.h
bool channel_type_has_zero_fee_commitments(const struct channel_type *type);

// Creates a zero-fee commitment channel type with all prerequisites
struct channel_type *channel_type_zero_fee_commitments(const tal_t *ctx);
```

#### Commitment Transaction Construction

In `common/initial_commit_tx.c`, zero-fee commitment transactions are built with:

1. Transaction version set to 3 (TRUC)
2. Zero fee (no satoshi deduction from outputs)
3. P2A anchor output with calculated amount

```c
if (option_zero_fee_commitments) {
    tx->wtx->version = BITCOIN_TX_VERSION_3;
    // Add P2A anchor output
    // Fee = 0
}
```

#### Protocol Validation

In `channeld/channeld.c`, the `validate_zero_fee_commitment_tx()` function ensures:

1. Transaction version is 3
2. P2A anchor output exists with correct script
3. Anchor amount is within valid range (0-240 sats)

```c
static bool validate_zero_fee_commitment_tx(struct peer *peer,
                                            const struct bitcoin_tx *tx);
```

### update_fee Handling

Zero-fee channels MUST NOT send or receive `update_fee` messages:

```c
// In channeld/channeld.c
static void handle_peer_update_fee(struct peer *peer, const u8 *msg)
{
    if (channel_type_has_zero_fee_commitments(peer->channel_type)) {
        peer_failed_err(peer->pps, &peer->channel_id,
                       "Received update_fee on zero-fee-commitment channel");
        return;
    }
    // ... normal handling
}
```

### HTLC Limits

To comply with v3 transaction size limits (10kvB), zero-fee channels limit `max_accepted_htlcs` to 114 (vs 483 for standard channels):

```c
// openingd/common.c
u16 max_htlcs(bool zero_fee_commitments)
{
    if (zero_fee_commitments)
        return 114;  // v3 10kvB limit
    return 483;      // standard limit
}
```

## Fee Bumping with CPFP

When broadcasting a commitment transaction, CLN creates a child transaction that:

1. Spends the P2A anchor output (anyone can spend)
2. Spends a wallet UTXO to provide fee input
3. Pays appropriate feerate based on urgency

The commitment transaction and CPFP child are submitted together as a package via `submitpackage` RPC (Bitcoin Core v29+).

### Wallet Reserve

Operators should ensure sufficient wallet UTXOs for emergency CPFP:

- Each zero-fee channel may need CPFP at force-close
- Recommended: Reserve 10,000+ sats per zero-fee channel
- Monitor wallet balance vs channel count

## Testing

### Running Tests

```bash
# Run all zero-fee tests
EXPERIMENTAL_DUAL_FUND=1 pytest tests/test_opening.py -k "zero_fee" -v

# Run specific test
EXPERIMENTAL_DUAL_FUND=1 pytest tests/test_opening.py::test_zero_fee_commitments_negotiation -v
```

### Test Coverage

| Test | Description |
|------|-------------|
| `test_zero_fee_commitments_negotiation` | Feature negotiation between two zero-fee nodes |
| `test_zero_fee_commitments_fallback` | Fallback to anchors when peer doesn't support |
| `test_zero_fee_commitments_no_update_fee` | Verifies no update_fee messages sent |
| `test_zero_fee_commitments_unilateral_close` | Local force close, fund recovery |
| `test_zero_fee_commitments_their_unilateral_close` | Remote force close handling |
| `test_zero_fee_commitments_tx_structure` | Validates v3 version and P2A anchor |
| `test_zero_fee_commitments_update_fee_rejected` | Protocol error on update_fee |
| `test_zero_fee_commitments_penalty_tx` | Justice transaction for revoked state |
| `test_zero_fee_commitments_htlc_force_close` | Force close with pending HTLCs |
| `test_zero_fee_commitments_htlc_stress` | High HTLC volume testing |

### Unit Tests

```bash
# Run commitment transaction unit tests
make check VALGRIND=0
# Specifically:
./channeld/test/run-commit_tx
```

## Security Considerations

### Transaction Pinning Prevention

v3/TRUC rules prevent pinning attacks by:
- Limiting child transaction count to 1
- Limiting child size to 10kvB
- Requiring v3 children for v3 parents

### Revoked State Detection

Justice transactions work the same as standard anchor channels. The penalty transaction claims all channel funds if a revoked commitment is broadcast.

### Dust Accumulation

The anchor amount is capped at 240 satoshis, preventing attackers from inflating anchor values through many tiny HTLCs.

## Debugging

### Check if Zero-Fee Channel

```bash
lightning-cli listpeerchannels | jq '.channels[] | {id: .channel_id, type: .channel_type.names}'
```

Look for `option_zero_fee_commitments` in the channel type names.

### Verify Feature Advertisement

```bash
lightning-cli getinfo | jq '.our_features'
```

Feature bit 40 should be present when `--experimental-zero-fee-channels` is enabled.

### Check Commitment Transaction

When a zero-fee commitment is broadcast, verify:
1. Transaction version is 3
2. P2A output exists (script: `51024e73`)
3. Total fee is 0 or minimal

## References

- [BOLT PR #1228](https://github.com/lightning/bolts/pull/1228) - Zero-fee commitments specification
- [Bitcoin Core Package Relay](https://github.com/bitcoin/bitcoin/issues/27463)
- [Ephemeral Dust PR](https://github.com/bitcoin/bitcoin/pull/30239)
- [Bitcoin Optech - Ephemeral Anchors](https://bitcoinops.org/en/topics/ephemeral-anchors/)
