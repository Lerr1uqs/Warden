from evm   import Transaction
from evm   import Contract
from evm   import provider
from utils import *

TMPADDR = provider.eth.accounts[0]

class Fuzzer:
    '''
    generate transaction sequence for fuzz
    '''

    def __init__(self, con: Contract) -> None:
        self.con = con
        pass

    def generate_txn_seq(self) -> Sequence[Transaction]:
        pass

    def build_one_txn(self, fname: str) -> Transaction:
        # TODO: 
    
        # TODO: 参数设置
        # TODO: 自动设置
        unsent_txn = self.con.functions[fname](TMPADDR, 0x0721, 0x0d00, b'\xff' * 32).build_transaction({
            "to": TMPADDR,
            "gas": 123456
            # "from": TMPADDR,
            # "nonce": w3.eth.get_transaction_count(TMPADDR),
        })
        '''
        {
            'value': 0, 
            'gas': 21432, 
            'maxFeePerGas': 3000000000, 
            'maxPriorityFeePerGas': 1000000000, 
            'chainId': 131277322940537, 
            'to': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 
            'data': '0x94321f820000000000000000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf'
        }
        '''
        # TODO:
        return Transaction(unsent_txn, self.con.artifact.func_input_types[fname])


        

