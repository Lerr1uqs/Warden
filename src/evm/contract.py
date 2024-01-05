import secrets
import json

from disassembler import SolidityBinary
from evm          import provider
from compiler     import Compiler
from utils        import *
# from web3 import Web3, EthereumTesterProvider

# w3 = Web3(EthereumTesterProvider())

# eth-tester populates accounts with test ether:
# acct1 = w3.eth.accounts[0]
# TODO: temporary

TMPADDR = provider.eth.accounts[0]

    
class Contract:
    def __init__(self, contract_name: str) -> None:
        # self.caller  = Todo()
        self.address         = secrets.token_hex(32) # TODO: generate contract address by web3 module
        self.balance         = 10 # TODO: 什么指令会调整balance
        self.block_timestamp = 1  # TODO: 用web3模块
        self.block_number    = 1  # TODO: ditto
        self.chainid         = 1  # TODO: ditto

        
        comp = Compiler("./contracts")
        af = comp.contract_artifact(contract_name)

        sb = SolidityBinary(af)
        self.artifact = sb.artifact
        self.sb = sb

        self._contract = provider.eth.contract(
            bytecode=sb.artifact.initbc, 
            abi=json.dumps(sb.artifact.abi)
        )
        # logger.debug(json.dumps(sb.artifact.abi, indent=2))
        # tx_hash = self._contract.constructor().transact({"from": TMPADDR}) # TODO:
        # receipt = w3.eth.get_transaction_receipt(tx_hash)

    @property
    def functions(self):
        return self._contract.functions