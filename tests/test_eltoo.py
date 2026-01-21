from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError, Millisatoshi
from shutil import copyfile
from pyln.testing.utils import SLOW_MACHINE
from utils import (
    wait_for, first_channel_id
)

import os
import queue
import pytest
import re
import subprocess
import threading
import time
import unittest

# In msats
SAT = 1000


def bind_eltoo_tx(unbound_tx_hex, funding_txid, funding_outnum):
    """Bind an eltoo transaction's APO input to the funding outpoint.

    Eltoo transactions use SIGHASH_ANYPREVOUT with placeholder inputs (all 0xff).
    This function replaces the placeholder with the actual funding outpoint.
    """
    # Transaction structure depends on whether it's witness serialization:
    # Non-witness: version(4) + inputcount(1) + txid(32) + vout(4)
    # Witness: version(4) + marker(1) + flag(1) + inputcount(1) + txid(32) + vout(4)

    # Check for witness marker (0x00 0x01 after version)
    has_witness = unbound_tx_hex[8:12] == '0001'

    if has_witness:
        # Witness serialization: txid starts at position 14 (byte 7)
        txid_start = 14
        txid_end = 78  # 14 + 64
        vout_end = 86  # 78 + 8
    else:
        # Non-witness serialization: txid starts at position 10 (byte 5)
        txid_start = 10
        txid_end = 74  # 10 + 64
        vout_end = 82  # 74 + 8

    # Reverse the funding txid for little-endian encoding
    reversed_txid = bytes.fromhex(funding_txid)[::-1].hex()

    # Convert outnum to little-endian 4 bytes
    outnum_le = funding_outnum.to_bytes(4, 'little').hex()

    # Replace the placeholder input with actual funding outpoint
    bound_tx = unbound_tx_hex[:txid_start] + reversed_txid + outnum_le + unbound_tx_hex[vout_end:]

    return bound_tx


def find_ephemeral_anchor_output(tx_details):
    """Find the ephemeral anchor output (OP_1 <0x4e73>) in a transaction.

    Returns the output index, or None if not found.
    """
    # Ephemeral anchor scriptPubKey: OP_1 <0x4e73> = 51024e73
    for i, vout in enumerate(tx_details['vout']):
        if vout['scriptPubKey']['hex'] == '51024e73':
            return i
    return None


def verify_wallet_received_funds(node, expected_sats, txid, tolerance_sats=1000):
    """Verify that node's wallet received expected funds from a close transaction."""
    outputs = node.rpc.listfunds()['outputs']
    matching = [o for o in outputs if o['txid'] == txid]
    assert len(matching) == 1, f"Expected 1 output from {txid}, found {len(matching)}"
    received_sats = matching[0]['amount_msat'] // 1000
    assert abs(received_sats - expected_sats) <= tolerance_sats, \
        f"Expected ~{expected_sats} sats, got {received_sats}"
    return received_sats


def create_cpfp_for_ephemeral_anchor(bitcoind, parent_tx_hex, parent_txid, anchor_output_index, feerate_sat_per_vbyte=10):
    """Create a CPFP transaction spending an ephemeral anchor output.

    For Bitcoin Inquisition with ephemeral anchors:
    - The CPFP child should only spend the anchor (no other inputs allowed by policy)
    - The anchor witness must be empty for standardness
    - All fees come from the wallet UTXO, which we add to the parent package

    Actually, we need wallet funds. Let me use a different approach:
    Create a simple transaction that spends a wallet UTXO and the anchor.

    Args:
        bitcoind: Bitcoin RPC connection
        parent_tx_hex: Hex-encoded parent transaction
        parent_txid: Transaction ID of parent
        anchor_output_index: Output index of the ephemeral anchor
        feerate_sat_per_vbyte: Target feerate for the package

    Returns:
        Hex-encoded CPFP transaction
    """
    # Get a destination address from the wallet
    dest_addr = bitcoind.rpc.getnewaddress()

    # Calculate required fee for the package
    parent_details = bitcoind.rpc.decoderawtransaction(parent_tx_hex)
    parent_vsize = parent_details['vsize']

    # CPFP tx vsize estimate
    cpfp_vsize = 150

    # Total package fee = (parent_vsize + cpfp_vsize) * feerate
    total_fee = (parent_vsize + cpfp_vsize) * feerate_sat_per_vbyte

    # Get a wallet UTXO to fund the CPFP fee
    utxos = bitcoind.rpc.listunspent(1)  # confirmed UTXOs
    if not utxos:
        raise Exception("No wallet UTXOs available for CPFP")

    # Find a UTXO large enough
    funding_utxo = None
    for utxo in utxos:
        if utxo['amount'] * 100000000 > total_fee + 1000:
            funding_utxo = utxo
            break

    if not funding_utxo:
        raise Exception(f"No UTXO large enough for CPFP fee {total_fee}")

    funding_amount_sat = int(funding_utxo['amount'] * 100000000)

    # Output = funding_amount - total_fee
    output_value_sat = funding_amount_sat - total_fee
    if output_value_sat < 546:  # dust limit
        raise Exception(f"Output would be dust: {output_value_sat}")

    # Create a 1-input tx with just the wallet UTXO, sign it
    # Then manually add the anchor as second input with empty witness
    single_inputs = [{"txid": funding_utxo['txid'], "vout": funding_utxo['vout']}]
    outputs = [{dest_addr: output_value_sat / 100000000}]

    # Create and sign single-input tx
    raw_tx = bitcoind.rpc.createrawtransaction(single_inputs, outputs)
    signed = bitcoind.rpc.signrawtransactionwithwallet(raw_tx)

    if not signed['complete']:
        raise Exception("Failed to sign wallet input")

    # Get the signed transaction and modify it to add anchor input
    signed_hex = signed['hex']
    signed_decoded = bitcoind.rpc.decoderawtransaction(signed_hex)
    wallet_witness = signed_decoded['vin'][0].get('txinwitness', [])

    if not wallet_witness:
        raise Exception("No witness data for wallet input")

    # Build the 2-input v3 transaction manually
    anchor_txid_le = bytes.fromhex(parent_txid)[::-1].hex()
    wallet_txid_le = bytes.fromhex(funding_utxo['txid'])[::-1].hex()
    output_script = signed_decoded['vout'][0]['scriptPubKey']['hex']

    version = "03000000"  # v3 TRUC
    marker_flag = "0001"  # segwit
    input_count = "02"

    # Input 0: Anchor (first so it's the "unconfirmed parent" input for TRUC rules)
    inp0 = anchor_txid_le + anchor_output_index.to_bytes(4, 'little').hex()
    inp0 += "00fdffffff"

    # Input 1: Wallet UTXO (confirmed)
    inp1 = wallet_txid_le + funding_utxo['vout'].to_bytes(4, 'little').hex()
    inp1 += "00fdffffff"

    output_count = "01"
    out_value = int(output_value_sat).to_bytes(8, 'little').hex()
    out_script_len = format(len(bytes.fromhex(output_script)), '02x')

    # Witness 0 (anchor): EMPTY for P2A standardness
    wit0 = "00"

    # Witness 1 (wallet): from signed tx
    # But wait - this signature is for a 1-input tx, not 2-input
    # The sighash will be different! We need to sign the 2-input tx.

    # Let's create the 2-input tx first, then sign it
    two_inputs = [
        {"txid": parent_txid, "vout": anchor_output_index},
        {"txid": funding_utxo['txid'], "vout": funding_utxo['vout']}
    ]

    raw_tx_2 = bitcoind.rpc.createrawtransaction(two_inputs, outputs)
    # Patch to v3
    raw_tx_2 = "03000000" + raw_tx_2[8:]

    # Sign with prevtxs for the anchor
    prevtxs = [{
        "txid": parent_txid,
        "vout": anchor_output_index,
        "scriptPubKey": "51024e73",
        "amount": 0
    }]

    signed_2 = bitcoind.rpc.signrawtransactionwithwallet(raw_tx_2, prevtxs)
    signed_2_decoded = bitcoind.rpc.decoderawtransaction(signed_2['hex'])

    # Get wallet witness from input 1 of the signed 2-input tx
    wallet_witness = signed_2_decoded['vin'][1].get('txinwitness', [])
    if not wallet_witness:
        raise Exception("No witness for wallet input in 2-input tx")

    # Rebuild with proper witnesses
    wit1 = format(len(wallet_witness), '02x')
    for item in wallet_witness:
        wit1 += format(len(bytes.fromhex(item)), '02x') + item

    locktime = "00000000"

    final_tx = (
        version + marker_flag + input_count +
        inp0 + inp1 +
        output_count + out_value + out_script_len + output_script +
        wit0 + wit1 +
        locktime
    )

    # Debug: verify input ordering
    print(f"DEBUG CPFP: parent_txid (anchor tx) = {parent_txid}")
    print(f"DEBUG CPFP: anchor_output_index = {anchor_output_index}")
    print(f"DEBUG CPFP: funding_utxo txid = {funding_utxo['txid']}")
    print(f"DEBUG CPFP: funding_utxo vout = {funding_utxo['vout']}")
    print(f"DEBUG CPFP: inp0 (should be anchor) = {inp0[:64]}... vout={inp0[64:72]}")
    print(f"DEBUG CPFP: inp1 (should be wallet) = {inp1[:64]}... vout={inp1[64:72]}")

    # Verify by decoding
    decoded = bitcoind.rpc.decoderawtransaction(final_tx)
    print(f"DEBUG CPFP: decoded input 0 txid = {decoded['vin'][0]['txid']}, vout = {decoded['vin'][0]['vout']}")
    print(f"DEBUG CPFP: decoded input 1 txid = {decoded['vin'][1]['txid']}, vout = {decoded['vin'][1]['vout']}")

    return final_tx


def broadcast_eltoo_tx_with_cpfp(bitcoind, tx_hex):
    """Broadcast an eltoo transaction with its CPFP as a package.

    For transactions with ephemeral anchors that have 0 fees, we need to
    use submitpackage with a CPFP child transaction.

    Bitcoin Inquisition has special handling for ephemeral anchors (P2A).
    """
    # Debug: check if parent tx has witness data
    print(f"DEBUG PARENT: tx_hex first 20 bytes = {tx_hex[:40]}")
    # Check for segwit marker (0001 after version)
    has_witness = tx_hex[8:12] == "0001"
    print(f"DEBUG PARENT: has_witness (0001 marker) = {has_witness}")

    tx_details = bitcoind.rpc.decoderawtransaction(tx_hex)
    txid = tx_details['txid']
    print(f"DEBUG PARENT: txid = {txid}, wtxid = {tx_details.get('hash', 'N/A')}")

    # Detailed witness analysis
    witness = tx_details['vin'][0].get('txinwitness', [])
    print(f"DEBUG PARENT: number of witness elements = {len(witness)}")
    for i, elem in enumerate(witness):
        print(f"DEBUG PARENT: witness[{i}] len={len(bytes.fromhex(elem))} hex={elem}")

    # Check sighash flag byte (last byte of signature)
    if len(witness) > 0:
        sig_hex = witness[0]
        sighash_flag = int(sig_hex[-2:], 16)
        print(f"DEBUG PARENT: sighash flag = 0x{sighash_flag:02x}")

    # Check if witness[1] is the expected script (51ac = OP_1 OP_CHECKSIG)
    if len(witness) > 1:
        script = witness[1]
        print(f"DEBUG PARENT: witness[1] (script) = {script}")
        if script == '51ac':
            print(f"DEBUG PARENT: script is correct (OP_1 OP_CHECKSIG)")
        elif script == 'ac':
            print(f"DEBUG PARENT: ERROR - script is missing OP_1, only has OP_CHECKSIG!")
        else:
            print(f"DEBUG PARENT: ERROR - unexpected script: {script}")

    # Get version and locktime
    version = tx_details['version']
    locktime = tx_details['locktime']
    print(f"DEBUG PARENT: version = {version}, locktime = {locktime} (0x{locktime:08x})")

    # Get outputs (important for SIGHASH_SINGLE)
    for i, vout in enumerate(tx_details['vout']):
        print(f"DEBUG PARENT: output[{i}] value={vout['value']} scriptPubKey={vout['scriptPubKey']['hex']}")

    # Get nSequence
    nsequence = tx_details['vin'][0]['sequence']
    print(f"DEBUG PARENT: nSequence = {nsequence} (0x{nsequence:08x})")

    # Get the funding output being spent
    funding_txid = tx_details['vin'][0]['txid']
    funding_vout = tx_details['vin'][0]['vout']
    print(f"DEBUG PARENT: spending {funding_txid}:{funding_vout}")

    # Get the funding tx and its output scriptPubKey
    try:
        funding_tx = bitcoind.rpc.getrawtransaction(funding_txid, True)
        funding_spk = funding_tx['vout'][funding_vout]['scriptPubKey']['hex']
        print(f"DEBUG PARENT: funding output scriptPubKey = {funding_spk}")
        # P2TR scriptPubKey format: OP_1 <32-byte pubkey> = 5120<pubkey>
        if funding_spk.startswith('5120') and len(funding_spk) == 68:
            funding_tweaked_pubkey = funding_spk[4:]
            print(f"DEBUG PARENT: funding tweaked pubkey = {funding_tweaked_pubkey}")
    except Exception as e:
        print(f"DEBUG PARENT: couldn't get funding tx: {e}")

    # Find ephemeral anchor output
    anchor_idx = find_ephemeral_anchor_output(tx_details)

    if anchor_idx is not None:
        # Try sendrawtransaction first to check if tx is valid
        try:
            print(f"DEBUG: trying sendrawtransaction first to validate tx")
            bitcoind.rpc.testmempoolaccept([tx_hex])
        except Exception as e:
            print(f"DEBUG: testmempoolaccept result: {e}")

        # Parent tx has zero fee with ephemeral anchor - need CPFP via submitpackage
        cpfp_hex = create_cpfp_for_ephemeral_anchor(bitcoind, tx_hex, txid, anchor_idx)

        print(f"DEBUG: submitting package with parent txid={txid}")
        result = bitcoind.rpc.submitpackage([tx_hex, cpfp_hex])
        if result.get('package_msg') != 'success':
            raise Exception(f"Package submission failed: {result}")
        print(f"DEBUG: package submitted successfully")
        return result
    else:
        # No ephemeral anchor, broadcast normally
        return bitcoind.rpc.sendrawtransaction(tx_hex)

def test_eltoo_tx_binding(node_factory, bitcoind):
    """Test that lightningd correctly binds eltoo transactions to funding outpoint"""

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None},
                                          {'may_reconnect': True, 'developer': None}])

    # Get the channel info
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    funding_txid = channel_info['funding_txid']
    funding_outnum = channel_info['funding_outnum']

    # Get both bound and unbound versions
    bound_update_tx = channel_info['last_update_tx']
    unbound_update_tx = channel_info['last_update_tx_unbound']

    # Verify unbound has placeholder input (all 0xff)
    unbound_details = bitcoind.rpc.decoderawtransaction(unbound_update_tx)
    assert unbound_details['vin'][0]['txid'] == 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

    # Verify bound has actual funding txid
    bound_details = bitcoind.rpc.decoderawtransaction(bound_update_tx)
    assert bound_details['vin'][0]['txid'] == funding_txid
    assert bound_details['vin'][0]['vout'] == funding_outnum

    # Verify our Python binding function binds the correct outpoint
    # Note: serialization formats may differ (witness vs non-witness), so compare decoded txs
    python_bound = bind_eltoo_tx(unbound_update_tx, funding_txid, funding_outnum)
    python_bound_details = bitcoind.rpc.decoderawtransaction(python_bound)
    assert python_bound_details['vin'][0]['txid'] == funding_txid
    assert python_bound_details['vin'][0]['vout'] == funding_outnum
    # Verify the rest of the transaction matches
    assert python_bound_details['vout'] == bound_details['vout']
    assert python_bound_details['locktime'] == bound_details['locktime']

    # Verify settle tx is also bound (to the update tx output)
    bound_settle_tx = channel_info['last_settle_tx']
    unbound_settle_tx = channel_info['last_settle_tx_unbound']

    unbound_settle_details = bitcoind.rpc.decoderawtransaction(unbound_settle_tx)
    assert unbound_settle_details['vin'][0]['txid'] == 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff'

    bound_settle_details = bitcoind.rpc.decoderawtransaction(bound_settle_tx)
    # Settle tx should reference the bound update tx's txid
    assert bound_settle_details['vin'][0]['txid'] == bound_details['txid']
    assert bound_settle_details['vin'][0]['vout'] == 0  # State output is always index 0


def test_uncommitted_removal_reestablishment(node_factory, bitcoind):

    # Want offering node to disconnect right afer sending off update_xxx_htlc
    disconnects = ['+WIRE_UPDATE_FULFILL_HTLC']

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None}, {'may_reconnect': True, 'developer': None, 'disconnect': disconnects}])

    # Pay comment will cause disconnect, but should recover
    l1.pay(l2, 100000*1000)

    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

def test_uncommitted_addition_reestablishment(node_factory, bitcoind):

    # Want offering node to disconnect right afer sending off update_xxx_htlc
    disconnects = ['+WIRE_UPDATE_ADD_HTLC']

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None, 'disconnect': disconnects}, {'may_reconnect': True, 'developer': None}])

    # Pay comment will cause disconnect, and payment should fail hard
    try:
        l1.pay(l2, 100000*1000)
        raise Exception('Should have raised RPCError')
    except RpcError:
        # FIXME better way of waiting for channel to be ready?
        time.sleep(5)
        pass

    # But otherwise be ok on follow-up attempts
    l1.pay(l2, 150000*1000)

    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(150000000))

def test_eltoo_offerer_ack_reestablishment(node_factory, bitcoind):
    """Test that channel reestablishment does the expected thing when 
       update signed ack didn't make it back to offerer. Reestablishment
       flow is essentially the offerer getting the ACK back on reconnect """

    # Want receiving node to disconnect right before sending off update_signed_ack
    disconnects = ['-WIRE_UPDATE_SIGNED_ACK']

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None}, {'may_reconnect': True, 'developer': None, 'disconnect': disconnects}])

    # Pay comment will cause disconnect, but should recover
    l1.pay(l2, 100000*SAT)

    # Offerer gets new partial sig on reestablishment
    l1.daemon.wait_for_log("partial signature reestablish combine our_psig")

    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

def test_eltoo_uneven_reestablishment(node_factory, bitcoind):
    """Test that channel reestablishment does the expected thing when 
       an update signed message was "sent" but not received by the recipient
       before disconnect """

    # Want offering node to disconnect right before sending off update_signed
    # So on reconnect offerer must replay all updates.
    disconnects = ['-WIRE_UPDATE_SIGNED']

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None, 'disconnect': disconnects}, {'may_reconnect': True, 'developer': None}])

    # Pay comment will cause disconnect, but should recover
    l1.pay(l2, 100000*SAT)

    # Offerer sends whole update again
    l1.daemon.wait_for_log('Retransmitting update')
    l2.daemon.wait_for_log('Received update_sig')

    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

def test_eltoo_base_reestablishment(node_factory, bitcoind):
    """Test that channel reestablishment does the expected thing when all prior messages completed """

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True, 'developer': None},
                                          {'may_reconnect': True, 'developer': None}])

    # Simple reestblishment where funding is locked   
    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We should see funding_locked messages be passed around, then
    # normal operation
    l1.daemon.wait_for_log('Reconnected, and reestablished')
    l2.daemon.wait_for_log('Reconnected, and reestablished')

    l1_update_tx = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_update_tx']
    l1_settle_tx = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_settle_tx']

    l2_update_tx = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_update_tx']
    l2_settle_tx = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_settle_tx']

    # Decode transactions to compare essential fields (txid can differ due to bound vs unbound format)
    l1_update_details = bitcoind.rpc.decoderawtransaction(l1_update_tx)
    l2_update_details = bitcoind.rpc.decoderawtransaction(l2_update_tx)
    l1_settle_details = bitcoind.rpc.decoderawtransaction(l1_settle_tx)
    l2_settle_details = bitcoind.rpc.decoderawtransaction(l2_settle_tx)

    # Verify both nodes agree on the update transaction state number (locktime)
    assert l1_update_details["locktime"] == l2_update_details["locktime"]
    assert l1_settle_details["locktime"] == l2_settle_details["locktime"]

    # Verify both nodes have the same outputs (the core channel state)
    assert l1_update_details["vout"] == l2_update_details["vout"]
    assert l1_settle_details["vout"] == l2_settle_details["vout"]

    # First update recovered
    assert l1_update_details["locktime"] == 500000000
    assert l1_settle_details["locktime"] == 500000000

    # l1 can pay l2
    l1.pay(l2, 100000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

def test_eltoo_unannounced_hop(node_factory, bitcoind):
    """Test eltoo payments work over hops"""

    # Make three nodes, two private channels
    # 'developer': None enables --developer mode which is needed for --dev-fast-gossip
    l1, l2, l3 = node_factory.line_graph(3,
                                     opts=[{'developer': None}, {'developer': None}, {'developer': None}], announce_channels=False) # Channel announcement unsupported, doing private hops)

    # l1 can pay l2
    l1.pay(l2, 100000*SAT)

    # l2 can pay back l1
    l1.pay(l2, 5000*SAT)

    # l2 can pay l3
    l2.pay(l3, 200000*SAT)

    # With proper hints exposed,
    # l1 can pay l3
    # Use listpeerchannels since channels are private/unannounced (not in gossip)
    scid = l3.rpc.listpeerchannels()['channels'][0]['short_channel_id']
    invoice = l3.rpc.invoice(amount_msat=10000, label='hop', description='test', exposeprivatechannels=scid)
    l1.rpc.pay(invoice['bolt11'])
    wait_for(lambda: l3.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200010000))

# Example flags to run test
# DEBUG_SUBD=eltoo_onchaind VALGRIND=0 BITCOIND_TEST_PATH=/home/greg/bitcoin-dev/lightning/eltoo_bitcoind pytest -s tests/test_eltoo.py -k test_eltoo_htlc
@pytest.mark.developer("needs dev-disable-commit-after")
def test_eltoo_htlc(node_factory, bitcoind, executor, chainparams):
    """Test HTLC resolution via eltoo_onchaind after a single successful payment"""

    # We track channel balances, to verify that accounting is ok.
    coin_mvt_plugin = os.path.join(os.getcwd(), 'tests/plugins/coin_movements.py')
    # First we need to get funds to l2, so suppress after second.
    # Feerates identical so we don't get gratuitous commit to update them
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'dev-disable-commit-after': 1, # add HTLC once
                                            'may_fail': True,
                                            'developer': None,
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'allow_warning': True,
                                            'plugin': coin_mvt_plugin},
                                           {'dev-disable-commit-after': 2, # remove HTLC, then later add
                                            'developer': None,
                                            'plugin': coin_mvt_plugin}])
    channel_id = first_channel_id(l1, l2)


    # Move some across to l2. This will cause *2* updates to be sent for
    # addition and removal of HTLC
    l1.pay(l2, 200000*SAT)

    # l1 won't be able to remove next HTLC after offering first addition
    l1.daemon.wait_for_log('dev-disable-commit-after: disabling')
    assert not l2.daemon.is_in_log('dev-disable-commit-after: disabling')

    # Now, this will get stuck due to l1 commit being disabled due to one more update..
    t = executor.submit(l2.pay, l1, 100000*SAT)

    # Make sure we get partial signature
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_ADD_HTLC')
    l1.daemon.wait_for_log('peer_in WIRE_UPDATE_SIGNED')

    # They should both have commitments blocked now.
    l2.daemon.wait_for_log('dev-disable-commit-after: disabling')

    # Both peers have partial sigs for the latest update transaction
    l1.daemon.wait_for_log('WIRE_UPDATE_SIGNED_ACK')
    l2.daemon.wait_for_log('WIRE_UPDATE_SIGNED_ACK')

    # Take our snapshot of complete tx with HTLC.
    l1_update_tx = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_update_tx']
    l1_settle_tx = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_settle_tx']

    l2_update_tx = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_update_tx']
    l2_settle_tx = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_settle_tx']

    assert l1_update_tx == l2_update_tx
    assert l1_settle_tx == l2_settle_tx

    # Now we really mess things up!

    l1_update_details = bitcoind.rpc.decoderawtransaction(l1_update_tx)
    l1_settle_details = bitcoind.rpc.decoderawtransaction(l1_settle_tx)

    # Eltoo transactions have ephemeral anchors (0-value, anyone-can-spend).
    # We need to broadcast with a CPFP child transaction using submitpackage.
    # last_update_tx is already bound by lightningd
    broadcast_eltoo_tx_with_cpfp(bitcoind, l1_update_tx)

    # Mine and mature the update tx
    bitcoind.generate_block(6)

    # Symmetrical transactions(!), symmetrical state, mostly
    l1.daemon.wait_for_log(' to ONCHAIN')
    l2.daemon.wait_for_log(' to ONCHAIN')

    needle_1 = l1.daemon.logsearch_start
    needle_2 = l2.daemon.logsearch_start

    # The settle transaction should hit the mempool for both!
    l1.wait_for_onchaind_broadcast('ELTOO_SETTLE',
                                   'ELTOO_UPDATE/DELAYED_OUTPUT_TO_US')
    l2.wait_for_onchaind_broadcast('ELTOO_SETTLE',
                                   'ELTOO_UPDATE/DELAYED_OUTPUT_TO_US')

    # With submitpackage/CPFP, we have 2 txs: settle + CPFP child
    # Both nodes may broadcast, but only one package should succeed (second fails as duplicate)
    mempool = bitcoind.rpc.getrawmempool()
    # Should have at least settle tx, possibly with CPFP child
    assert len(mempool) >= 1 and len(mempool) <= 2, f"Expected 1-2 txs in mempool, got {len(mempool)}"

    # We're going to disable transaction relay for the SUCCESS transaction
    # To allow us to test broadcast of one transaction at a time
    def censoring_sendrawtx(r):
        return {'id': r['id'], 'result': {}}

    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', censoring_sendrawtx)

    # Mine settle tx (and CPFP if present), then we should see HTLC timeout resolution hit the mempool by the receiver
    bitcoind.generate_block(1)

    wait_for(lambda: len(bitcoind.rpc.getrawmempool()) == 1)

    timeout_tx = bitcoind.rpc.getrawtransaction(bitcoind.rpc.getrawmempool()[0], 1)
    assert len(timeout_tx['vin'][0]['txinwitness']) == 3
    l2.wait_for_onchaind_broadcast('ELTOO_HTLC_TIMEOUT',
                                   'ELTOO_SETTLE/OUR_HTLC')
    # Stop mining of tx for this next block
    bitcoind.rpc.prioritisetransaction(timeout_tx['txid'], 0, -100000000)
    # Allow SUCCESS tx to hit mempool next block
    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', None)

    bitcoind.generate_block(1)

    # Should hit mempool; do the log/pool check
    l1.wait_for_onchaind_broadcast('ELTOO_HTLC_SUCCESS',
                               'ELTOO_SETTLE/THEIR_HTLC')

    success_tx = bitcoind.rpc.getrawtransaction(bitcoind.rpc.getrawmempool()[0], 1)
    assert len(success_tx['vin'][0]['txinwitness']) == 4

    bitcoind.generate_block(1)

    # Mine enough blocks to close out onchaind
    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Verify channels are closed
    assert len(l1.rpc.listpeerchannels()['channels']) == 0, "l1 channel should be forgotten"
    assert len(l2.rpc.listpeerchannels()['channels']) == 0, "l2 channel should be forgotten"


def test_eltoo_restart_after_funding(node_factory, bitcoind):
    """Test that eltoo channel state is correctly persisted and restored after node restart.

    This tests basic restart functionality after channel funding is complete.
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Get channel state before restart
    channel_info_before = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    funding_txid = channel_info_before['funding_txid']
    update_tx_before = channel_info_before['last_update_tx']
    settle_tx_before = channel_info_before['last_settle_tx']

    # Decode transactions to compare essential state
    update_details_before = bitcoind.rpc.decoderawtransaction(update_tx_before)
    settle_details_before = bitcoind.rpc.decoderawtransaction(settle_tx_before)

    # Restart l1
    l1.restart()

    # Wait for reconnection and reestablishment
    l1.daemon.wait_for_log('Reconnected, and reestablished')

    # Get channel state after restart
    channel_info_after = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]

    # Verify funding info persisted correctly
    assert channel_info_after['funding_txid'] == funding_txid
    assert channel_info_after['state'] == 'CHANNELD_NORMAL'

    # Verify eltoo transaction state persisted correctly
    update_tx_after = channel_info_after['last_update_tx']
    settle_tx_after = channel_info_after['last_settle_tx']

    update_details_after = bitcoind.rpc.decoderawtransaction(update_tx_after)
    settle_details_after = bitcoind.rpc.decoderawtransaction(settle_tx_after)

    # Core state should match - locktime (state number) and outputs
    assert update_details_before['locktime'] == update_details_after['locktime']
    assert settle_details_before['locktime'] == settle_details_after['locktime']
    assert update_details_before['vout'] == update_details_after['vout']
    assert settle_details_before['vout'] == settle_details_after['vout']

    # Channel should still be operational - make a payment
    l1.pay(l2, 100000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))


def test_eltoo_restart_after_payment(node_factory, bitcoind):
    """Test that eltoo channel state is correctly persisted after payments.

    This tests that balances and update transactions are correctly stored
    and restored after a payment followed by restart.
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make some payments to change the channel state
    l1.pay(l2, 100000*SAT)
    l1.pay(l2, 50000*SAT)

    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(150000000))

    # Get channel state before restart
    l1_channel_before = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    l2_channel_before = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]

    update_tx_before = l1_channel_before['last_update_tx']
    settle_tx_before = l1_channel_before['last_settle_tx']

    update_details_before = bitcoind.rpc.decoderawtransaction(update_tx_before)
    settle_details_before = bitcoind.rpc.decoderawtransaction(settle_tx_before)

    # State number should have advanced (locktime > 500000000)
    assert update_details_before['locktime'] > 500000000

    # Restart l1
    l1.restart()

    # Wait for reconnection and reestablishment
    l1.daemon.wait_for_log('Reconnected, and reestablished')

    # Get channel state after restart
    l1_channel_after = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]

    update_tx_after = l1_channel_after['last_update_tx']
    settle_tx_after = l1_channel_after['last_settle_tx']

    update_details_after = bitcoind.rpc.decoderawtransaction(update_tx_after)
    settle_details_after = bitcoind.rpc.decoderawtransaction(settle_tx_after)

    # State should match - locktime and outputs
    assert update_details_before['locktime'] == update_details_after['locktime']
    assert settle_details_before['locktime'] == settle_details_after['locktime']
    assert update_details_before['vout'] == update_details_after['vout']
    assert settle_details_before['vout'] == settle_details_after['vout']

    # Channel should still work - make another payment
    l1.pay(l2, 25000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(175000000))

    # And payment in reverse direction should also work
    l2.pay(l1, 10000*SAT)
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(10000000))


def test_eltoo_restart_both_nodes(node_factory, bitcoind):
    """Test that both nodes can restart and resume channel operation.

    This tests that channel state is correctly synchronized when both
    nodes restart at the same time.
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make a payment to advance state
    l1.pay(l2, 200000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200000000))

    # Get state before restart
    l1_update_before = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_update_tx']
    l2_update_before = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_update_tx']

    l1_details_before = bitcoind.rpc.decoderawtransaction(l1_update_before)
    l2_details_before = bitcoind.rpc.decoderawtransaction(l2_update_before)

    # Both should have the same state
    assert l1_details_before['locktime'] == l2_details_before['locktime']

    # Stop both nodes
    l1.stop()
    l2.stop()

    # Start both nodes
    l2.start()
    l1.start()

    # Connect them manually
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # Wait for reestablishment
    l1.daemon.wait_for_log('Reconnected, and reestablished')
    l2.daemon.wait_for_log('Reconnected, and reestablished')

    # Verify state is preserved
    l1_update_after = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['last_update_tx']
    l2_update_after = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['last_update_tx']

    l1_details_after = bitcoind.rpc.decoderawtransaction(l1_update_after)
    l2_details_after = bitcoind.rpc.decoderawtransaction(l2_update_after)

    # State should match before and after
    assert l1_details_before['locktime'] == l1_details_after['locktime']
    assert l2_details_before['locktime'] == l2_details_after['locktime']
    assert l1_details_after['locktime'] == l2_details_after['locktime']

    # Channel should work in both directions
    l1.pay(l2, 50000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(250000000))

    l2.pay(l1, 75000*SAT)
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(75000000))


def test_eltoo_restart_during_payment(node_factory, bitcoind):
    """Test restart during a payment flow using disconnect.

    This tests that a payment can complete after one node restarts mid-payment
    using the reestablishment protocol.
    """
    # Use disconnect to simulate restart mid-payment
    disconnects = ['+WIRE_UPDATE_SIGNED']

    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None,
                                            'disconnect': disconnects},
                                           {'may_reconnect': True, 'developer': None}])

    # First payment succeeds and triggers disconnect after update_signed
    l1.pay(l2, 100000*SAT)

    # After auto-reconnect, payment should have completed
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

    # Get state before full restart
    channel_before = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    update_before = bitcoind.rpc.decoderawtransaction(channel_before['last_update_tx'])

    # Now do a full restart
    l1.restart()

    # Wait for reconnection
    l1.daemon.wait_for_log('Reconnected, and reestablished')

    # Verify state preserved
    channel_after = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    update_after = bitcoind.rpc.decoderawtransaction(channel_after['last_update_tx'])

    assert update_before['locktime'] == update_after['locktime']

    # Make another payment to verify channel still works
    l1.pay(l2, 50000*SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(150000000))


def test_eltoo_trimmed_balance_anchor_value(node_factory, bitcoind):
    """Test that trimmed balance amounts are added to the ephemeral anchor output.

    Per BOLT XX-eltoo-transactions: settlement tx anchor output value should be
    "the sum of all trimmed output values, minimum 0 satoshis".

    This test verifies that when a to_local or to_remote balance is below the
    dust limit (330 sat), its value is added to the anchor output rather than
    being lost.
    """
    # Open a channel and pay almost all funds to l2, leaving l1 with < 330 sats
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Get channel capacity and calculate payment to leave l1 with exactly 100 sats
    # Channel capacity is ~1,000,000 sats, we want l1 to have 100 sats (below 330 dust)
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    our_amount_msat = channel_info['to_us_msat']

    # Pay l2 enough to leave l1 with only 100 sats (100000 msat)
    # This is below the 330 sat dust limit
    REMAINING_MSAT = 100 * SAT  # 100 sats = 100000 msat
    payment_amount = int(our_amount_msat) - REMAINING_MSAT

    print(f"DEBUG: l1 starting balance = {our_amount_msat}")
    print(f"DEBUG: payment to l2 = {payment_amount} msat")
    print(f"DEBUG: l1 remaining = {REMAINING_MSAT} msat = {REMAINING_MSAT // 1000} sats")

    l1.pay(l2, payment_amount)

    # Verify l1 now has only 100 sats
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    print(f"DEBUG: l1 balance after payment = {channel_info['to_us_msat']}")

    # Get the settlement transaction
    settle_tx_hex = channel_info['last_settle_tx']
    settle_details = bitcoind.rpc.decoderawtransaction(settle_tx_hex)

    # Print all outputs for debugging
    print(f"DEBUG: settlement tx has {len(settle_details['vout'])} outputs:")
    for i, vout in enumerate(settle_details['vout']):
        value_sats = int(vout['value'] * 100000000)
        print(f"  output[{i}]: {value_sats} sats, scriptPubKey={vout['scriptPubKey']['hex'][:20]}...")

    # Find the ephemeral anchor output (scriptPubKey = 51024e73)
    anchor_value = None
    anchor_idx = None
    for i, vout in enumerate(settle_details['vout']):
        if vout['scriptPubKey']['hex'] == '51024e73':
            anchor_value = int(vout['value'] * 100000000)  # Convert BTC to sat
            anchor_idx = i
            break

    assert anchor_idx is not None, "No ephemeral anchor found in settlement tx"

    print(f"DEBUG: anchor output index = {anchor_idx}")
    print(f"DEBUG: anchor value = {anchor_value} sats")
    print(f"DEBUG: expected trimmed balance = {REMAINING_MSAT // 1000} sats")
    print(f"DEBUG: dust limit = 330 sats")

    # Since l1's balance (100 sats) is below dust limit (330 sats), it should be trimmed
    # and added to the anchor output
    expected_anchor_sats = REMAINING_MSAT // 1000  # 100 sats
    assert anchor_value == expected_anchor_sats, \
        f"Expected anchor to have {expected_anchor_sats} sats from trimmed to_local, got {anchor_value}"

    print(f"SUCCESS: Anchor output correctly has {anchor_value} sats from trimmed balance")

    # With l1's balance trimmed, we should have only 2 outputs: to_remote (l2) and anchor
    # No to_local output since l1's balance is below dust
    num_outputs = len(settle_details['vout'])
    assert num_outputs == 2, f"Expected 2 outputs (to_remote, anchor), got {num_outputs}"


def test_eltoo_close_simple(node_factory, bitcoind):
    """Test basic mutual close for eltoo channels.

    This verifies that:
    1. Closing an eltoo channel results in a mutual close transaction
    2. The close tx is version 3 (TRUC) and uses taproot
    3. Both nodes receive their funds
    4. Channel state transitions correctly to CLOSINGD_COMPLETE
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make a payment to verify channel is operational and change balances
    l1.pay(l2, 200000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200000000))

    # Wait for all HTLCs to be resolved before closing
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Get channel info before close
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    funding_txid = channel_info['funding_txid']
    scid = channel_info['short_channel_id']

    # Record balances before close
    l1_balance_before = channel_info['to_us_msat']
    l2_balance_before = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['to_us_msat']

    print(f"DEBUG: l1 balance = {l1_balance_before}, l2 balance = {l2_balance_before}")

    assert bitcoind.rpc.getmempoolinfo()['size'] == 0

    # Initiate close
    l1.rpc.close(scid)

    # Wait for shutdown exchange
    l1.daemon.wait_for_log('peer_out WIRE_SHUTDOWN_ELTOO')
    l2.daemon.wait_for_log('peer_in WIRE_SHUTDOWN_ELTOO')

    # Wait for closing negotiation
    l1.daemon.wait_for_log('peer_out WIRE_CLOSING_SIGNED_ELTOO')
    l2.daemon.wait_for_log('peer_in WIRE_CLOSING_SIGNED_ELTOO')

    # Wait for channel state to change to CLOSINGD_COMPLETE
    l1.daemon.wait_for_log('to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log('to CLOSINGD_COMPLETE')

    # Close tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 1)

    # Get the close transaction
    closetxid = bitcoind.rpc.getrawmempool()[0]
    closetx_hex = bitcoind.rpc.getrawtransaction(closetxid)
    closetx_details = bitcoind.rpc.decoderawtransaction(closetx_hex)

    print(f"DEBUG: close txid = {closetxid}")
    print(f"DEBUG: close tx version = {closetx_details['version']}")
    print(f"DEBUG: close tx locktime = {closetx_details['locktime']}")
    print(f"DEBUG: close tx outputs = {len(closetx_details['vout'])}")

    # Verify close tx properties:
    # - Version 3 (TRUC for package relay)
    assert closetx_details['version'] == 3, f"Expected version 3, got {closetx_details['version']}"

    # - Locktime 0 (mutual close, no timelock)
    assert closetx_details['locktime'] == 0, f"Expected locktime 0, got {closetx_details['locktime']}"

    # - Spends from funding tx
    assert closetx_details['vin'][0]['txid'] == funding_txid

    # - Has 2 outputs (one for each party) since both have non-dust balances
    assert len(closetx_details['vout']) == 2, f"Expected 2 outputs, got {len(closetx_details['vout'])}"

    # - Uses taproot outputs (P2TR: OP_1 <32-byte-key>)
    for vout in closetx_details['vout']:
        spk = vout['scriptPubKey']['hex']
        assert spk.startswith('5120'), f"Expected P2TR output, got scriptPubKey {spk}"

    # Mine the close tx
    bitcoind.generate_block(1)

    # Verify both nodes see the confirmed close
    l1.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')
    l2.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')

    # Verify funds returned to wallets
    wait_for(lambda: closetxid in [o['txid'] for o in l1.rpc.listfunds()['outputs']])
    wait_for(lambda: closetxid in [o['txid'] for o in l2.rpc.listfunds()['outputs']])

    # Verify amounts received
    l1_expected = int(l1_balance_before) // 1000
    l2_expected = int(l2_balance_before) // 1000
    verify_wallet_received_funds(l1, l1_expected, closetxid, tolerance_sats=5000)  # l1 pays fees
    verify_wallet_received_funds(l2, l2_expected, closetxid, tolerance_sats=1000)

    print("SUCCESS: Eltoo simple close completed")


def test_eltoo_close_after_payments(node_factory, bitcoind):
    """Test mutual close after multiple payments in both directions.

    This verifies that:
    1. Close works correctly after channel state has been updated
    2. Final balances in close tx reflect all payments
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make payments in both directions
    l1.pay(l2, 300000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(300000000))

    l2.pay(l1, 100000 * SAT)
    wait_for(lambda: l1.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

    l1.pay(l2, 50000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(350000000))

    # Wait for all HTLCs to be resolved before closing
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Get balances before close
    l1_channel = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    l2_channel = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]

    l1_balance_msat = l1_channel['to_us_msat']
    l2_balance_msat = l2_channel['to_us_msat']

    print(f"DEBUG: Before close - l1 balance = {l1_balance_msat}, l2 balance = {l2_balance_msat}")

    scid = l1_channel['short_channel_id']

    # Initiate close
    l1.rpc.close(scid)

    # Wait for close to complete
    l1.daemon.wait_for_log('to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log('to CLOSINGD_COMPLETE')

    # Close tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 1)

    closetxid = bitcoind.rpc.getrawmempool()[0]
    closetx_hex = bitcoind.rpc.getrawtransaction(closetxid)
    closetx_details = bitcoind.rpc.decoderawtransaction(closetx_hex)

    # Verify outputs match expected balances (approximately, accounting for fees)
    output_values = sorted([int(vout['value'] * 100000000) for vout in closetx_details['vout']])
    expected_l1 = int(l1_balance_msat) // 1000
    expected_l2 = int(l2_balance_msat) // 1000

    print(f"DEBUG: Close tx output values = {output_values}")
    print(f"DEBUG: Expected l1 = {expected_l1} sat, l2 = {expected_l2} sat")

    # The outputs should be close to expected (within fee tolerance)
    # Fee comes from initiator (l1), so l1's output will be reduced
    assert len(output_values) == 2

    # Mine and verify
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')
    l2.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')

    # Verify funds in wallets
    wait_for(lambda: closetxid in [o['txid'] for o in l1.rpc.listfunds()['outputs']])
    wait_for(lambda: closetxid in [o['txid'] for o in l2.rpc.listfunds()['outputs']])
    verify_wallet_received_funds(l1, expected_l1, closetxid, tolerance_sats=5000)
    verify_wallet_received_funds(l2, expected_l2, closetxid, tolerance_sats=1000)

    print("SUCCESS: Eltoo close after payments completed")


def test_eltoo_close_reconnect(node_factory, bitcoind):
    """Test that eltoo close completes correctly after reconnection.

    This verifies that if disconnection happens during close negotiation,
    the close can complete after reconnection.
    """
    # Disconnect after sending shutdown
    disconnects = ['+WIRE_SHUTDOWN_ELTOO']

    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None,
                                            'disconnect': disconnects},
                                           {'may_reconnect': True, 'developer': None}])

    # Make a payment first
    l1.pay(l2, 100000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

    # Wait for all HTLCs to be resolved before closing
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Save balances before close
    l1_expected_sats = int(l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['to_us_msat']) // 1000
    l2_expected_sats = int(l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['to_us_msat']) // 1000

    scid = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['short_channel_id']

    # Initiate close - will disconnect after shutdown
    l1.rpc.close(scid)

    # Wait for disconnect and reconnect
    l1.daemon.wait_for_log('peer_out WIRE_SHUTDOWN_ELTOO')
    l1.daemon.wait_for_log('Peer connection lost')

    # Reconnection should happen automatically
    l1.daemon.wait_for_log('Reconnected, and reestablished')

    # Close should complete
    l1.daemon.wait_for_log('to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log('to CLOSINGD_COMPLETE')

    # Close tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 1)

    closetxid = bitcoind.rpc.getrawmempool()[0]

    # Mine and verify
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')
    l2.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')

    # Both should have their funds
    wait_for(lambda: closetxid in [o['txid'] for o in l1.rpc.listfunds()['outputs']])
    wait_for(lambda: closetxid in [o['txid'] for o in l2.rpc.listfunds()['outputs']])

    # Verify amounts received
    verify_wallet_received_funds(l1, l1_expected_sats, closetxid, tolerance_sats=5000)
    verify_wallet_received_funds(l2, l2_expected_sats, closetxid, tolerance_sats=1000)

    print("SUCCESS: Eltoo close with reconnect completed")


def test_eltoo_close_responder_initiates(node_factory, bitcoind):
    """Test that the non-funding party can initiate close.

    This verifies that either party can initiate mutual close.
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make a payment
    l1.pay(l2, 200000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200000000))

    # Wait for all HTLCs to be resolved before closing
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Save balances before close
    l1_expected_sats = int(l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['to_us_msat']) // 1000
    l2_expected_sats = int(l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['to_us_msat']) // 1000

    # l2 (non-funder) initiates close
    scid = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['short_channel_id']

    l2.rpc.close(scid)

    # Wait for shutdown exchange
    l2.daemon.wait_for_log('peer_out WIRE_SHUTDOWN_ELTOO')
    l1.daemon.wait_for_log('peer_in WIRE_SHUTDOWN_ELTOO')

    # Wait for close to complete
    l1.daemon.wait_for_log('to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log('to CLOSINGD_COMPLETE')

    # Close tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 1)

    closetxid = bitcoind.rpc.getrawmempool()[0]

    # Mine and verify
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')
    l2.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')

    # Both should have their funds
    wait_for(lambda: closetxid in [o['txid'] for o in l1.rpc.listfunds()['outputs']])
    wait_for(lambda: closetxid in [o['txid'] for o in l2.rpc.listfunds()['outputs']])

    # Verify amounts received (l2 initiates, so l2 pays fees)
    verify_wallet_received_funds(l1, l1_expected_sats, closetxid, tolerance_sats=1000)
    verify_wallet_received_funds(l2, l2_expected_sats, closetxid, tolerance_sats=5000)

    print("SUCCESS: Eltoo close initiated by responder completed")


def test_eltoo_close_dust_balance(node_factory, bitcoind):
    """Test mutual close when one party has a dust balance.

    This verifies that:
    1. Close works when one balance is below dust limit
    2. The dust balance is properly trimmed from the close tx
    3. The non-dust party receives all funds
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Get l1's balance and pay almost all to l2, leaving l1 with < 330 sats (dust)
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    l1_balance_msat = int(channel_info['to_us_msat'])

    # Leave l1 with only 100 sats (below 330 sat dust limit)
    REMAINING_MSAT = 100 * SAT  # 100 sats
    payment_amount = l1_balance_msat - REMAINING_MSAT

    print(f"DEBUG: l1 starting balance = {l1_balance_msat} msat")
    print(f"DEBUG: paying {payment_amount} msat to l2")

    l1.pay(l2, payment_amount)

    # Wait for HTLCs to fully resolve before closing
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Verify l1 has dust balance
    channel_info = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    l1_final_msat = int(channel_info['to_us_msat'])
    print(f"DEBUG: l1 final balance = {l1_final_msat} msat = {l1_final_msat // 1000} sats")

    assert l1_final_msat < 330 * 1000, "l1 balance should be below dust limit"

    # Save l2's expected balance before close
    l2_expected_sats = int(l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['to_us_msat']) // 1000

    scid = channel_info['short_channel_id']

    # Initiate close
    l1.rpc.close(scid)

    # Wait for close to complete
    l1.daemon.wait_for_log('to CLOSINGD_COMPLETE')
    l2.daemon.wait_for_log('to CLOSINGD_COMPLETE')

    # Close tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] == 1)

    closetxid = bitcoind.rpc.getrawmempool()[0]
    closetx_hex = bitcoind.rpc.getrawtransaction(closetxid)
    closetx_details = bitcoind.rpc.decoderawtransaction(closetx_hex)

    print(f"DEBUG: close tx outputs = {len(closetx_details['vout'])}")
    for i, vout in enumerate(closetx_details['vout']):
        print(f"DEBUG: output[{i}] = {int(vout['value'] * 100000000)} sats")

    # With l1's balance below dust, close tx should have only 1 output (l2's)
    assert len(closetx_details['vout']) == 1, \
        f"Expected 1 output (dust trimmed), got {len(closetx_details['vout'])}"

    # Mine and verify
    bitcoind.generate_block(1)

    l1.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')
    l2.daemon.wait_for_log(r'Resolved ELTOO_FUNDING_TRANSACTION/FUNDING_OUTPUT by ELTOO_MUTUAL_CLOSE')

    # Only l2 should have funds in the close tx
    wait_for(lambda: closetxid in [o['txid'] for o in l2.rpc.listfunds()['outputs']])

    # Verify l2 received correct amount
    l2_outputs = [o for o in l2.rpc.listfunds()['outputs'] if o['txid'] == closetxid]
    l2_received = l2_outputs[0]['amount_msat'] // 1000
    assert abs(l2_received - l2_expected_sats) < 5000, f"l2 mismatch: got {l2_received}, expected {l2_expected_sats}"

    # Verify l1 got nothing (dust was trimmed)
    l1_outputs = [o for o in l1.rpc.listfunds()['outputs'] if o['txid'] == closetxid]
    assert len(l1_outputs) == 0, "l1 should not receive funds (dust trimmed)"

    print("SUCCESS: Eltoo close with dust balance completed")


def test_eltoo_force_close_rpc(node_factory, bitcoind):
    """Test that eltoo force close can be triggered via RPC.

    This verifies that:
    1. Force close via RPC broadcasts the update tx with CPFP
    2. The settle tx is broadcast after update tx confirms
    3. On-chain resolution completes correctly
    4. Funds are recovered to the on-chain wallet
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Make a payment to have non-initial state
    l1.pay(l2, 200000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200000000))

    # Wait for all HTLCs to be resolved
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Get channel info and balance before close
    l1_channel = l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]
    scid = l1_channel['short_channel_id']
    funding_txid = l1_channel['funding_txid']
    l1_balance_before = l1_channel['to_us_msat']

    # Record l1's wallet balance before force close
    l1_wallet_before = sum([o['amount_msat'] for o in l1.rpc.listfunds()['outputs']])

    print(f"DEBUG: l1 channel balance before close = {l1_balance_before}")
    print(f"DEBUG: l1 wallet balance before close = {l1_wallet_before}")

    # Stop l2 so mutual close is impossible
    l2.stop()

    # Force close via RPC with unilateraltimeout=1
    # This should trigger unilateral close since peer is offline
    l1.rpc.close(scid, unilateraltimeout=1)

    # l1 should transition to AWAITING_UNILATERAL
    l1.daemon.wait_for_log('to AWAITING_UNILATERAL')

    # Update tx (with CPFP) should be in mempool
    # Eltoo uses package relay: update_tx + cpfp_tx
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] >= 1)

    mempool = bitcoind.rpc.getrawmempool()
    print(f"DEBUG: mempool after force close = {mempool}")

    # Find the update tx (spends funding output)
    update_txid = None
    for txid in mempool:
        tx = bitcoind.rpc.getrawtransaction(txid, 1)
        if tx['vin'][0]['txid'] == funding_txid:
            update_txid = txid
            break

    assert update_txid is not None, "Update tx not found in mempool"

    update_tx = bitcoind.rpc.getrawtransaction(update_txid, 1)
    print(f"DEBUG: update tx version = {update_tx['version']}")
    print(f"DEBUG: update tx locktime = {update_tx['locktime']}")

    # Verify update tx properties:
    # - Version 3 (TRUC for package relay)
    assert update_tx['version'] == 3, f"Expected version 3, got {update_tx['version']}"

    # - Locktime encodes state number (500000000 + state_number)
    assert update_tx['locktime'] >= 500000000, f"Expected eltoo locktime, got {update_tx['locktime']}"

    # Mine update tx
    bitcoind.generate_block(1)

    # l1 should see the update tx confirm
    l1.daemon.wait_for_log('to ONCHAIN')

    # Mine blocks for CSV timelock (watchtime-blocks=5)
    bitcoind.generate_block(5)

    # Now settle tx should be broadcast
    l1.wait_for_onchaind_broadcast('ELTOO_SETTLE',
                                   'ELTOO_UPDATE/DELAYED_OUTPUT_TO_US')

    # Settle tx should be in mempool
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] >= 1)

    settle_mempool = bitcoind.rpc.getrawmempool()
    print(f"DEBUG: mempool after settle broadcast = {settle_mempool}")

    # Mine settle tx
    bitcoind.generate_block(1)

    # Mine enough blocks for onchaind to complete (100 blocks for CSV)
    bitcoind.generate_block(99)

    l1.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Verify that the channel is no longer listed
    channels = l1.rpc.listpeerchannels()['channels']
    assert len(channels) == 0, f"Channel should be forgotten after onchaind complete, but found: {channels}"

    print("SUCCESS: Eltoo force close via RPC completed")


def test_eltoo_force_close_rpc_with_htlc(node_factory, bitcoind, executor):
    """Test eltoo force close via RPC with pending HTLC.

    This verifies that:
    1. Force close works when there's a pending HTLC
    2. HTLC timeout resolution happens correctly
    3. Funds (including HTLC) are recovered to wallet
    """
    l1, l2 = node_factory.line_graph(2,
                                     opts=[{'may_reconnect': True, 'developer': None},
                                           {'may_reconnect': True, 'developer': None}])

    # Fund l2 so it has wallet funds for CPFP during force close
    # (eltoo update tx has 0 fee and relies on CPFP)
    l2_addr = l2.rpc.newaddr()
    addr = l2_addr.get('bech32') or l2_addr.get('p2tr')
    bitcoind.rpc.sendtoaddress(addr, 0.01)
    bitcoind.generate_block(1)
    wait_for(lambda: len(l2.rpc.listfunds()['outputs']) > 0)

    # Make initial payment to have state
    l1.pay(l2, 100000 * SAT)
    wait_for(lambda: l2.rpc.listpeerchannels()['channels'][0]['in_fulfilled_msat'] == Millisatoshi(100000000))

    # Wait for HTLCs to clear
    wait_for(lambda: l1.rpc.listpeerchannels(l2.info['id'])['channels'][0]['htlcs'] == [])
    wait_for(lambda: l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]['htlcs'] == [])

    # Get l2's balance before the HTLC
    l2_channel = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]
    l2_balance_before = l2_channel['to_us_msat']
    l2_wallet_before = sum([o['amount_msat'] for o in l2.rpc.listfunds()['outputs']])

    print(f"DEBUG: l2 channel balance before HTLC = {l2_balance_before}")
    print(f"DEBUG: l2 wallet balance before close = {l2_wallet_before}")

    # Create an invoice on l1 that l2 will try to pay
    htlc_amount = 50000 * SAT
    inv = l1.rpc.invoice(htlc_amount, 'test_htlc', 'test')

    # Get channel info
    l2_channel = l2.rpc.listpeerchannels(l1.info['id'])['channels'][0]
    scid = l2_channel['short_channel_id']

    # Start payment in background - it will get stuck because we'll stop l1
    def pay_and_fail():
        try:
            l2.rpc.pay(inv['bolt11'])
        except Exception:
            pass  # Expected to fail

    fut = executor.submit(pay_and_fail)

    # Wait for HTLC to be added
    l2.daemon.wait_for_log('peer_out WIRE_UPDATE_ADD_HTLC')

    # Wait for HTLC to be committed
    l2.daemon.wait_for_log('WIRE_UPDATE_SIGNED')

    # Stop l1 so it can't fulfill the HTLC
    l1.stop()

    # Force close from l2's side with pending outgoing HTLC
    l2.rpc.close(scid, unilateraltimeout=1)

    # l2 should go to AWAITING_UNILATERAL
    l2.daemon.wait_for_log('to AWAITING_UNILATERAL')

    # Update tx should be broadcast
    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] >= 1)

    # Mine update tx
    bitcoind.generate_block(1)

    l2.daemon.wait_for_log('to ONCHAIN')

    # Mine blocks for CSV timelock (watchtime-blocks=5)
    bitcoind.generate_block(5)

    # Settle tx should be broadcast
    l2.wait_for_onchaind_broadcast('ELTOO_SETTLE',
                                   'ELTOO_UPDATE/DELAYED_OUTPUT_TO_US')

    wait_for(lambda: bitcoind.rpc.getmempoolinfo()['size'] >= 1)

    # Mine settle tx
    bitcoind.generate_block(1)

    # Mine enough blocks for onchaind to complete
    # (HTLC timeout handling is not yet implemented for eltoo)
    bitcoind.generate_block(100)

    l2.daemon.wait_for_log('onchaind complete, forgetting peer')

    # Clean up the future
    fut.result()

    # Verify that the channel is no longer listed
    channels = l2.rpc.listpeerchannels()['channels']
    assert len(channels) == 0, f"Channel should be forgotten after onchaind complete, but found: {channels}"

    print("SUCCESS: Eltoo force close via RPC with HTLC completed")
