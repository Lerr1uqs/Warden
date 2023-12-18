from utils import *
from web3 import Web3
from evm.calldata import Calldata
# TODO:
'''
{
	"block.chainid": "3333",
	"block.coinbase": "0x0000000000000000000000000000000000000000",
	"block.difficulty": "0",
	"block.gaslimit": "50276",
	"block.number": "2",
	"block.timestamp": "1701618090",
	"msg.sender": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	"msg.sig": "0x6057361d",
	"msg.value": "0 Wei",
	"tx.origin": "0x5B38Da6a701c568545dCfcB03FcB875f56beddC4",
	"block.basefee": "1 Wei (1)"
}
'''


class Transaction:
    def __init__(self, caller: int) -> None:
        self.caller: int = caller
        self.value = Web3.toWei(10 ** 6, "ether")# TODO:
        self.gas = 10000 # TODO: 专门单位
        self.calldata: Calldata = None # TODO:
        self.msgvalue = 10 # TODO: 根据混合符号执行和单纯的符号执行 结果不一样


