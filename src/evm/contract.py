from utils import *
import secrets
import json
from evm.provider import provider
# from web3 import Web3, EthereumTesterProvider

# w3 = Web3(EthereumTesterProvider())

# eth-tester populates accounts with test ether:
# acct1 = w3.eth.accounts[0]
# TODO: temporary

TMPADDR = provider.eth.accounts[0]

    
class Contract:
    def __init__(self, sb: SolidityBinary) -> None:
        # self.caller  = Todo()
        self.address         = secrets.token_hex(32) #Todo()
        self.balance         = 10 #Todo()
        self.block_timestamp = 1  # Todo()
        self.block_number    = 1  #Todo
        self.chainid         = 1  #Todo
        self.artifact = sb.artifact
        self.sb = sb

        self._contract = provider.eth.contract(bytecode=sb.artifact.initbc, abi=json.dumps(sb.artifact.abi))
        # logger.debug(json.dumps(sb.artifact.abi, indent=2))
        # tx_hash = self._contract.constructor().transact({"from": TMPADDR}) # TODO:
        # receipt = w3.eth.get_transaction_receipt(tx_hash)

        unsent_billboard_tx = self._contract.functions["vuln"](TMPADDR).build_transaction({
            "to": TMPADDR,
            # "from": TMPADDR,
            # "nonce": w3.eth.get_transaction_count(TMPADDR),
        })

        logger.debug(unsent_billboard_tx)
    
    @property
    def functions(self):
        return self._contract.functions