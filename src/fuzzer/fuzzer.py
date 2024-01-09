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
    def generate_txn_seq(self) -> List[List[Transaction]]:

        fseqs = self.con.artifact.fseqorder
        
        # a group for indenpendent functions
        # e.g ((A, B), (C, D, E), (F))
        res = []

        # fseq e.g: [[A, B], [], [C]] (C depend on A and B, AB indegree is 0, C indegree is 2)
        for i, fseq in enumerate(fseqs):
            res.append([])
            # TODO: 此处可以加入更多随机策略
            # NOTE: 当依赖图中的节点较多的时候 对多数进行fuzz 较少的时候就只fuzz一两次
            for fnames in fseq:
                for j in range(1, len(fnames) + 1):
                    for fname in fnames * j: # prelong up to triple
                        res[i].append(self.build_one_txn(fname))
        
        return res

    def build_one_txn(self, fname: str) -> Transaction:

        if type(fname) != str:
            raise TypeError
        
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
        return Transaction(unsent_txn, fname, self.con.artifact.func_input_types[fname])


        

