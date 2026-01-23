---
title: Zero-Fee Commitment Channels
slug: zero-fee-channels
content:
  excerpt: >-
    Guide to using zero-fee commitment channels, an experimental feature that
    eliminates fee-related force closes.
privacy:
  view: public
---

# Zero-Fee Commitment Channels

Zero-fee commitment channels are an experimental feature that changes how channel commitment transactions handle fees. Instead of embedding fees at signing time, fees are paid dynamically when a force close actually occurs.

## Why Use Zero-Fee Channels?

### Problem with Traditional Channels

Traditional Lightning channels embed fees in commitment transactions when they're signed. This creates problems:

1. **Fee disagreements cause force closes**: If nodes disagree on appropriate fees, channels can be force closed
2. **Fee estimation is difficult**: Fees embedded weeks ago may be too low or too high when actually needed
3. **Capacity is reduced**: Channels must reserve funds for potential fees, reducing usable capacity

### How Zero-Fee Channels Solve This

Zero-fee commitment transactions have **no embedded fees**. When a force close occurs:

1. The commitment transaction is broadcast with zero fees
2. Your node creates a child transaction that spends from the commitment
3. The child transaction pays the actual fees needed at that moment
4. Both transactions are submitted together as a "package"

This means fees are always appropriate for current network conditions.

## Requirements

Before enabling zero-fee channels, ensure you have:

### Bitcoin Core v29+

Zero-fee channels require Bitcoin Core version 29 or later for v3 transaction and package relay support.

```bash
bitcoin-cli --version
# Should show v29.0.0 or higher
```

### Dual-Funding Support

Zero-fee channels use the v2 channel opening protocol:

```
# In your config or command line
experimental-dual-fund
experimental-zero-fee-channels
```

### Wallet Funds for CPFP

Your node's wallet needs funds to pay fees during force closes. Each zero-fee channel could potentially need CPFP (Child-Pays-For-Parent) fee bumping.

**Recommendation**: Keep at least 10,000 satoshis per zero-fee channel in your wallet.

## Enabling Zero-Fee Channels

Add to your `~/.lightning/config`:

```
experimental-dual-fund
experimental-zero-fee-channels
```

Or start lightningd with:

```bash
lightningd --experimental-dual-fund --experimental-zero-fee-channels
```

## Opening a Zero-Fee Channel

When both you and your peer have zero-fee channels enabled, new channels automatically use the zero-fee format:

```bash
# Connect to peer
lightning-cli connect <node_id>@<ip>:<port>

# Open channel (will use zero-fee if both support it)
lightning-cli fundchannel <node_id> 1000000
```

### Verify Channel Type

Check if your channel is using zero-fee commitments:

```bash
lightning-cli listpeerchannels | jq '.channels[] | select(.channel_type.names | index("option_zero_fee_commitments"))'
```

## Fallback Behavior

If your peer doesn't support zero-fee channels, the channel will automatically fall back to the standard `anchors_zero_fee_htlc_tx` format. You don't need to do anything special.

## What Changes

### No More update_fee Messages

Zero-fee channels don't send or receive `update_fee` protocol messages. This eliminates a common source of channel problems.

### Different HTLC Limits

Zero-fee channels support up to 114 concurrent HTLCs (vs 483 for standard channels). This is due to transaction size limits in v3 transactions. For most use cases, 114 HTLCs is more than sufficient.

### Force Close Behavior

When force closing a zero-fee channel:

1. CLN broadcasts your commitment transaction (with zero fees)
2. CLN automatically creates a fee-bumping transaction using wallet funds
3. Both are submitted together for mining
4. Your funds return to your wallet after the CSV delay (same as standard channels)

## Monitoring

### Check Wallet Balance

Ensure you have funds for emergency fee bumping:

```bash
lightning-cli listfunds | jq '.outputs[] | select(.status == "confirmed") | .amount_msat'
```

### Startup Warning

If zero-fee channels are enabled without Bitcoin Core v29+, you'll see a startup warning:

```
WARNING: zero-fee commitments enabled but submitpackage not available.
Force closes may fail to propagate without manual intervention.
```

Upgrade your Bitcoin Core if you see this warning.

## Troubleshooting

### Force Close Not Confirming

If a zero-fee commitment transaction isn't confirming:

1. Check that your wallet has confirmed UTXOs
2. Verify Bitcoin Core supports `submitpackage` RPC
3. Check `lightning-cli listpeerchannels` for the channel state

### Peer Rejected Channel

If a peer rejects your zero-fee channel open:

1. The peer may not support the feature
2. CLN will automatically retry with standard anchor channels
3. Check peer's advertised features with `lightning-cli listnodes <node_id>`

## Comparison with Standard Anchor Channels

| Feature | Zero-Fee | Standard Anchors |
|---------|----------|------------------|
| Commitment fee | 0 sats | Variable feerate |
| Fee updates | None | update_fee messages |
| Anchor outputs | 1 shared P2A | 2 separate (330 sat each) |
| HTLC limit | 114 | 483 |
| Bitcoin Core | v29+ required | v0.21+ |
| Force close | Package relay | Standard broadcast |

## Current Limitations

- **Experimental**: This feature is still experimental; use with caution on mainnet
- **Bitcoin Core v29+**: Requires recent Bitcoin Core version
- **Interoperability**: Not all Lightning implementations support this yet
- **HTLC limit**: Lower concurrent HTLC limit (114 vs 483)

## Further Reading

- [Developer documentation](../developers-guide/zero-fee-channels.md) for technical details
- [BOLT #1228](https://github.com/lightning/bolts/pull/1228) specification
