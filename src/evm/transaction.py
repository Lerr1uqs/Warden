from utils import *
from web3 import Web3
from evm.calldata import Calldata # remove it
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
# from web3 import Web3, EthereumTesterProvider

# w3 = Web3(EthereumTesterProvider())

# # eth-tester populates accounts with test ether:
# acct1 = w3.eth.accounts[0]

# some_address = "0x0000000000000000000000000000000000000000"

# # when using one of its generated test accounts,
# # eth-tester signs the tx (under the hood) before sending:
# tx_hash = w3.eth.send_transaction({
#     "from": acct1,
#     "to": some_address,
#     "value": 123123123123123
# })
# tx = w3.eth.get_transaction(tx_hash)

from binascii import unhexlify, hexlify
from numbers import Integral

def split_bytes32_into_list(byte_string: bytes) -> List[bytes]:
    chunk_size = 32
    # 使用 rjust 将 byte_string 填充到长度为 chunk_size 的整数倍
    if len(byte_string) % 32 != 0:
        pandding = len(byte_string) // chunk_size + 1
    else:
        pandding = len(byte_string) // chunk_size 

    padded_string = byte_string.rjust(pandding * chunk_size, b'\x00')
    # 分割字节序列并返回结果
    return [padded_string[i:i+chunk_size] for i in range(0, len(padded_string), chunk_size)]

class _Msg:
    @property
    def signature(self) -> BV:
        sig = self.data[0:4].ljust(32, b'\x00')
        assert len(sig) == 32
        return claripy.BVV(sig, 256)
        
    def __init__(self, calldata: str, func_param_types: Dict) -> None:

        assert isinstance(calldata, str)
        # logger.debug(calldata)
        self.data = bytes.fromhex(calldata[2:]) # remove 0x prefix
        self.len = len(calldata) // 2 - 1
        self._arguments = []

        data = self.data[4:] # remove first 4-bytes signature

        paramsize = len(func_param_types)
        logger.debug(func_param_types)
        logger.debug(hexlify(data).decode('utf-8'))
        
        '''
        ref: https://ethereum.stackexchange.com/questions/14037/what-is-msg-data
        0xd1621754 // (1) methodId
        000000000000000000000000c6e012db5298275a4c11b3e07d2caba88473fce1 // (2) "_address"
     <- 00000000000000000000000000000000000000000000000000000000000000a0 // (3) location of start of "_bytes" data (item 7) = 160 bytes
    ↓   000000000000000000000000000000000000000000000000000000000000000c // (4) "_val" = 12
    ↓   00000000000000000000000000000000000000000000000000000000000000e0 // (5) location of start of "_array" data (item 9) = 224 bytes
    ↓   0000000000000000000000000000000000000000000000000000000000000160 // (6) location of start of "_string" data (item 13) = 352 bytes
     -> 0000000000000000000000000000000000000000000000000000000000000008 // (7) size of "_bytes" data in bytes (32 bytes)
        6d79206279746573000000000000000000000000000000000000000000000000 // (8) "_bytes" data padded to 32 bytes
        0000000000000000000000000000000000000000000000000000000000000003 // (9) length of "_array" data = 3
        0000000000000000000000000000000000000000000000000000000000000001 // (10) _array[0] value = 1
        0000000000000000000000000000000000000000000000000000000000000004 // (11) _array[2] value = 4
        000000000000000000000000000000000000000000000000000000000000019c // (12) _array[3] value = 412
        0000000000000000000000000000000000000000000000000000000000000024 // (13) size of "_string" data in bytes (64 bytes)
        7468697369736c61726765727468616e74686972747974776f6279746573737472696e670..0 // (14) "_string" data padded to 64 bytes
        '''

        data32s: List[Union[bytes, BV]] = split_bytes32_into_list(data)
        start_at_idx = [] # bytes array string的长度所在索引

        for (i, ftype) in enumerate(func_param_types):

            if ftype == "address":
                data32s[i] = claripy.BVS("input-addr", 256)

            elif ftype in ["bytes", "array", "string"]:

                n = int.from_bytes(data32s[i], byteorder='big')
                assert n % 32 == 0
                
                start_at_idx.append(
                    (n // 32, ftype)
                )

            # TODO: uint256??
            # TODO: int[] ???
            elif ftype == "uint256": # TODO: int256?
                data32s[i] = claripy.BVS(f"input-{ftype}", 256)

            else:
                raise NotImplementedError(f"unhandled function type {ftype}")

        for i, ftype in start_at_idx:

            length = int.from_bytes(data32s[i], byteorder='big')

            if ftype == "bytes" or ftype == "string":
                assert length <= 32 # TODO: 当前不支持更长的bytes
                # TODO: 是否需要长度校验？
                data32s[i+1] = claripy.BVS(f"input-{ftype}", length * 8)

            elif ftype == "array":
                for j in range(length):
                    data32s[i+j+1] = claripy.BVS(f"input-{ftype}[{j}]", 256) # TODO: 注意int位数

            else:
                raise NotImplementedError(f"error type {ftype}")
            
        self.data32s = data32s

    def __repr__(self) -> str:

        r = []
        
        for i, v in enumerate(self.data32s):
            r.append(f"{i} {v}")
            
        return "\n".join(r)


    def __getitem__(self, idx: Integral) -> BV:

        assert isinstance(idx, Integral)

        ret = self.data32s[idx]

        if isinstance(ret, BV):
            return ret
        elif isinstance(ret, bytes):
            return claripy.BVV(ret, 256)
        else:
            raise TypeError(f"{type(ret)}")
            



        
class Transaction:
    def __init__(self, txn: Dict, func_types: List) -> None:
        '''
        e.g. txn = {
            'value': 0, 
            'gas': 21432, 
            'maxFeePerGas': 3000000000, 
            'maxPriorityFeePerGas': 1000000000, 
            'chainId': 131277322940537, 
            'to': '0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf', 
            'data': '0x94321f820000000000000000000000007e5f4552091a69125d5dfcb7b8c2659029395bdf'
        }
        '''

        self.caller: int        = txn["to"] # TODO: what is to?
        # self.value = Web3.toWei(txn["value"], "ether")# TODO:
        # self.value              = txn["value"] # TODO: symbolize it
        self.value              = claripy.BVS("msg.value", 256) # TODO: symbolize it
        self.gas                = txn["gas"]
        self.chainid            = txn["chainId"]
        # self.msgvalue = 10 # TODO: 根据混合符号执行和单纯的符号执行 结果不一样
        self.msg                = _Msg(txn["data"], func_types) # TODO:
        self.func_types = func_types



        # CALLDATALOAD[idx] <- msg.data[idx:idx+32] (32 granularity is word)

