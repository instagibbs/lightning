from fixtures import *  # noqa: F401,F403
from pyln.client import RpcError, Millisatoshi
from shutil import copyfile
from pyln.testing.utils import SLOW_MACHINE
from utils import (
    only_one, sync_blockheight, wait_for, TIMEOUT,
    account_balance, first_channel_id, closing_fee, TEST_NETWORK,
    scriptpubkey_addr, calc_lease_fee, EXPERIMENTAL_FEATURES,
    check_utxos_channel, anchor_expected, check_coin_moves,
    check_balance_snaps, mine_funding_to_announce
)

import os
import queue
import pytest
import re
import subprocess
import threading
import unittest

# In msats
SAT = 1000

def test_eltoo_empty_reestablishment(node_factory, bitcoind):
    """Test that channel reestablishment does the expected thing"""

    l1, l2 = node_factory.line_graph(2,
                                    opts=[{'may_reconnect': True}, {'may_reconnect': True}])

    # Simple reestblishment where funding is locked   
    l1.rpc.disconnect(l2.info['id'], force=True)
    l1.rpc.connect(l2.info['id'], 'localhost', l2.port)

    # We should see funding_locked messages be passed around, then
    # normal operation
    l1.daemon.wait_for_log('Reconnected, and reestablished')
    l2.daemon.wait_for_log('Reconnected, and reestablished')

    l1_update_tx = l1.rpc.listpeers(l2.info['id'])["peers"][0]["channels"][0]['last_update_tx']
    l1_settle_tx = l1.rpc.listpeers(l2.info['id'])["peers"][0]["channels"][0]['last_settle_tx']

    l2_update_tx = l2.rpc.listpeers(l1.info['id'])["peers"][0]["channels"][0]['last_update_tx']
    l2_settle_tx = l2.rpc.listpeers(l1.info['id'])["peers"][0]["channels"][0]['last_settle_tx']

    assert l1_update_tx == l2_update_tx
    assert l1_settle_tx == l2_settle_tx

    l1_update_details = bitcoind.rpc.decoderawtransaction(l1_update_tx)
    l1_settle_details = bitcoind.rpc.decoderawtransaction(l1_settle_tx)

    # First update recovered
    assert l1_update_details["locktime"] == 500000000
    assert l1_settle_details["locktime"] == 500000000

    from pdb import set_trace
    set_trace()

    # l1 can pay l2
    l1.pay(l2, 100000*SAT)


def test_eltoo_unannounced_hop(node_factory, bitcoind):
    """Test eltoo payments work over hops"""

    # Make three nodes, two private channels
    l1, l2, l3 = node_factory.line_graph(3,
                                     opts=[{}, {}, {}], announce_channels=False) # Channel announcement unsupported, doing private hops)

    # l1 can pay l2
    l1.pay(l2, 100000*SAT)

    # l2 can pay back l1
    l1.pay(l2, 5000*SAT)

    # l2 can pay l3
    l2.pay(l3, 200000*SAT)

    # With proper hints exposed,
    # l1 can pay l3
    scid = l3.rpc.listchannels()['channels'][0]['short_channel_id']
    invoice = l3.rpc.invoice(msatoshi=10000, label='hop', description='test', exposeprivatechannels=scid)
    l1.rpc.pay(invoice['bolt11'])
    wait_for(lambda: l3.rpc.listpeers()['peers'][0]['channels'][0]['in_fulfilled_msat'] == Millisatoshi(200010000))

# Example flags to run test
# DEBUG_SUBD=eltoo_onchaind VALGRIND=0 BITCOIND_ELTOO_ARGS=1 BITCOIND_TEST_PATH=/home/greg/bitcoin-dev/bitcoin/src/bitcoind pytest -s tests/test_eltoo.py -k test_eltoo_htlc
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
                                            'feerates': (7500, 7500, 7500, 7500),
                                            'allow_broken_log': True,
                                            'plugin': coin_mvt_plugin},
                                           {'dev-disable-commit-after': 2, # remove HTLC, then later add
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
    l1_update_tx = l1.rpc.listpeers(l2.info['id'])["peers"][0]["channels"][0]['last_update_tx']
    l1_settle_tx = l1.rpc.listpeers(l2.info['id'])["peers"][0]["channels"][0]['last_settle_tx']

    l2_update_tx = l2.rpc.listpeers(l1.info['id'])["peers"][0]["channels"][0]['last_update_tx']
    l2_settle_tx = l2.rpc.listpeers(l1.info['id'])["peers"][0]["channels"][0]['last_settle_tx']

    assert l1_update_tx == l2_update_tx
    assert l1_settle_tx == l2_settle_tx

    # Now we really mess things up!

    # FIXME we need real anchor CPFP + package relay to pay fees
    l1_update_details = bitcoind.rpc.decoderawtransaction(l1_update_tx)
    l1_settle_details = bitcoind.rpc.decoderawtransaction(l1_settle_tx)
    bitcoind.rpc.prioritisetransaction(l1_update_details["txid"], 0, 100000000)
    bitcoind.rpc.prioritisetransaction(l1_settle_details["txid"], 0, 100000000)
    bitcoind.rpc.sendrawtransaction(l1_update_tx)

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

    assert len(bitcoind.rpc.getrawmempool()) == 1

    # We're going to disable transaction relay for the SUCCESS transaction
    # To allow us to test broadcast of one transaction at a time
    def censoring_sendrawtx(r):
        return {'id': r['id'], 'result': {}}

    l1.daemon.rpcproxy.mock_rpc('sendrawtransaction', censoring_sendrawtx)

    # Mine settle tx, then we should see HTLC timeout resolution hit the mempool by the receiver
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

    # FIXME Check wallet related things, balances
    # FIXME The mounds of memleaks
    
    # Mine enough blocks to closed out onchaind
    bitcoind.generate_block(99)
    l1.daemon.wait_for_log('onchaind complete, forgetting peer')
    l2.daemon.wait_for_log('onchaind complete, forgetting peer')
