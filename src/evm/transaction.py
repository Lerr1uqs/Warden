from evm   import w3
from utils import *
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

from binascii import unhexlify, hexlify

def split_bytes32_into_list(byte_string: bytes) -> List[bytes]:
    '''
    split bytes into groups of 32 bytes, with zeros filling in parts less than 32
    '''
    chunk_size = 32

    if len(byte_string) % 32 != 0:
        pandding = len(byte_string) // chunk_size + 1
    else:
        pandding = len(byte_string) // chunk_size 

    padded_string = byte_string.rjust(pandding * chunk_size, b'\x00')

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

        # logger.debug(func_param_types)
        # logger.debug(hexlify(data).decode('utf-8'))
        
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

            # NOTE: not handle array e.g. int[] 
            # NOTE: not handle other uintxx e.g. uint128
            elif ftype == "uint256":
                data32s[i] = claripy.BVS(f"input-{ftype}", 256)

            else:
                raise NotImplementedError(f"unhandled function type {ftype}")

        for i, ftype in start_at_idx:

            length = int.from_bytes(data32s[i], byteorder='big')

            if ftype == "bytes" or ftype == "string":

                if length > 32:
                    raise NotImplementedError(f"not supperted length {length}")

                data32s[i+1] = claripy.BVS(f"input-{ftype}", length * 8)

            elif ftype == "array":
                for j in range(length):
                    # NOTE: sanity check the int bits
                    data32s[i+j+1] = claripy.BVS(f"input-{ftype}[{j}]", 256)

            else:
                raise NotImplementedError(f"error type {ftype}")
            
        self.data32s = data32s

    def __repr__(self) -> str:

        r = []
        
        for i, v in enumerate(self.data32s):
            r.append(f"{i} {v}")
            
        return "\n".join(r)


    def __getitem__(self, idx: int) -> BV:

        if not isinstance(idx, int):
            raise TypeError

        ret = self.data32s[idx]

        if isinstance(ret, BV):
            return ret
        elif isinstance(ret, bytes):
            return claripy.BVV(ret, 256)
        else:
            raise TypeError(f"{type(ret)}")
            



        
class Transaction:
    def __init__(self, txn: Dict, fname: str, func_types: List) -> None:
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

        self.caller: int        = int(txn["to"], 16)
        self.value              = claripy.BVS("msg.value", 256) # IMPROVE: adjust money according whether payable for function
        self.gas                = txn["gas"]
        self.chainid            = txn["chainId"]
        self.msg                = _Msg(txn["data"], func_types)
        self.func_types         = func_types
        # NOTE: be sure the NUMBER instruction is aim to get the lastest block number
        self.block_number       = w3.eth.get_block_number
        self.timestamp          = w3.eth.get_block('latest')["timestamp"]
        self.fname              = fname

        # CALLDATALOAD[idx] <- msg.data[idx:idx+32] (32 granularity is word)

    def __repr__(self) -> str:
        return f"Txn({self.fname})"