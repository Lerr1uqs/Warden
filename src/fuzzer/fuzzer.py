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

    # TODO: add a prolong mechanism
    def generate_txn_seq(self) -> Sequence[Transaction]:

        fseqs = self.con.artifact.fseqorder
        
        if len(fseqs) == 0:
            for fname in self.con.artifact.funcnames:
                yield self.build_one_txn(fname)

        else:
            # TODO: 此处可以加入更多随机策略
            for fnames in fseqs:
                for fname in fnames:
                    yield self.build_one_txn(fname)

    def build_one_txn(self, fname: str) -> Transaction:

        fits = self.con.artifact.func_input_types[fname]
        args = []

        # NOTE: here insufficient type handle
        for t in fits:

            if t == "uint256":
                args.append(0x0d000721)

            elif t == "address":
                args.append(TMPADDR)

            elif t == "bytes":
                args.append(b'\xff' * 0x20) # NOTE: only handle the 0x20 bytes
                
            else:
                raise TypeError(f"unhandled type {t}")
                

        unsent_txn = self.con.functions[fname](*args).build_transaction({
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
        return Transaction(unsent_txn, fname, self.con.artifact.func_input_types[fname])


        

