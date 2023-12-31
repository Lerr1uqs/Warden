import secrets
import json

from disassembler import SolidityBinary
from evm          import provider
from compiler     import Compiler
from utils        import *

    
class Contract:
    def __init__(self, contract_name: str) -> None:
        # self.caller  = Todo()
        self.address         = secrets.token_hex(32) # TODO: generate contract address by web3 module
        self.balance         = 10 # TODO: 什么指令会调整balance
        
        comp = Compiler("./contracts")
        af = comp.contract_artifact(contract_name)

        sb = SolidityBinary(af)
        self.artifact = sb.artifact
        self.sb = sb

        self._contract = provider.eth.contract(
            bytecode=sb.artifact.initbc, 
            abi=json.dumps(sb.artifact.abi),
        )
    
    @property
    def functions(self):
        return self._contract.functions