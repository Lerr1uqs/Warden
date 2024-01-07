from utils import *
import copy

def combine_bv8_to_bv256(bv8s: List[BV]) -> BV:

    res = BVVify(0)

    assert len(bv8s) == 32
    assert all(bv8.length == 8 for bv8 in bv8s)

    for bv8 in bv8s:
        res <<= 8
        res |= bv8.zero_extend(256 - 8)
    
    return res
    

# NOTE: 内存的写入操作是找到freemem_pointer然后写4个字节过去 每一个slot还是32字节 所以这里只需要按地址编排写入位置即可 不需要管slot的索引了
class Memory:
    # NOTE: I not provide the extend operation which Memory actual needed.
    def __init__(self) -> None:
        self._mem: List[BV] = [claripy.BVV(0, 8)] * 1024 # TEMP:
    
    def __hash__(self) -> int:
        r = 0
        for v in self._mem:
            r ^= hash(v)
        return r

    def __repr__(self) -> str:
        r = "\n"
        for i in range(0, len(self._mem), 32):
            r += f"{i // 32:03x} {combine_bv8_to_bv256(self._mem[i:i+32])}\n"
        return r

    def clone(self):
        new_memory = Memory()
        new_memory._mem = copy.deepcopy(self._mem)
        return new_memory

    def _read_one_byte(self, addr: int) -> BV:

        if not isinstance(addr, int):
            raise TypeError(f"addr must be int but found {type(addr)}")
        
        return self._mem[addr]
    
    def _write_one_byte(self, addr: int, v: BV) -> None:

        if not isinstance(addr, int):
            raise TypeError(f"addr must be int but found {type(addr)}")

        if not isinstance(v, BV):
            raise TypeError(f"v must be BV but found {type(v)}")
        
        if v.length != 8:
            raise TypeError(f"length not match {v.length}")

        self._mem[addr] = v


    def write(self, addr: int, bytes_size: int, value: BV) -> None:
        '''
        write bytes_size length value at given address.
        '''
        # sanity check: avoid confusing concrate and concrate_value in upper caller
        if not isinstance(addr, int):
            raise TypeError(f"addr must be int but found {type(addr)}")

        if not isinstance(value, BV):
            raise TypeError(f"value must be BV but found {type(value)}")

        if bytes_size * 8 != value.length:
            raise TypeError(f"length not match!")

        chops = value.chop(8)
        for i in range(len(chops)):
            self._write_one_byte(addr + i, chops[i])

    def read(self, addr: int, bytes_size: int) -> BV:
        '''
        read a slot from given address
        '''
        if not isinstance(addr, int):
            raise TypeError(f"addr must be int but found {type(addr)}")
        
        '''
        notes that addr can start from anywhere
        000005c1: PUSH1 0x11
        000005c3: PUSH1 0x4
        000005c5: MSTORE
        '''

        res = claripy.BVV(0, bytes_size * 8)

        for i in range(bytes_size):
            res <<= 8
            bytebv = self._read_one_byte(addr + i)
            res += bytebv.zero_extend(res.length - 8)

        return claripy.simplify(res)


@DeprecationWarning
class _Memory:
    '''
    memory的存储粒度是word 也就是4字节
    RETURN指令执行的时候是借助return mem[ost:ost+len-1]的 所以返回值一定会加载到内存中
    '''

    # TODO: 检查逻辑 一个合约只需要初始化一次rtcode
    def __init__(self, rtcode: Optional[bytes]=None) -> None:
        super().__init__()# 一定要先初始化pydantic的基类 不然很多东西都没注册
        # self._msize = 0
        # NOTE: 粒度为1byte
        # self._mem: Dict[int, BV] = {}
        # import pdb;pdb.set_trace()

        self._msize = 0
        self._mem_limit    = 0x2000# TODO: 暂时

        # self._have_read    = set()
        # self._have_written = set()# TODO:

        self._mem: Dict[int, BV] = {}

        # if rtcode is not None: # TODO: non mem init?
            # self.init_rt_bytecode(rtcode)
        
    def __hash__(self) -> int:# TODO:
        r = 0
        for k, v in self._mem.items():
            r ^= hash(k) ^ hash(v)
        return r ^ hash(self._msize)

    def __repr__(self) -> str:
        r = "\n"
        for k, v in self._mem.items():
            r += f"{k:03x} {v}\n"
        return r
    
    def __len__(self):
        return self._msize

    def clone(self):
        new_memory = Memory()
        new_memory._mem = copy.deepcopy(self._mem)
        new_memory._msize = self._msize
        return new_memory

    def extend(self, size: int):
        self._msize += size

    def init_rt_bytecode(self, rtcode: bytes) -> None:
        for i in range(len(rtcode)):
            self._write_one_byte(i, claripy.BVV(rtcode[i], 8))
        
    def _inner_read(self, addr: int, size: int) -> BV:
        '''
        size: granularity is byte
        return a 256-bits BV
        '''
        v = BVV0
        for i in range(size):
            v = v << 8
            v = v & ~0xff
            # assert self._mem.get(addr + i).length == 8, f"{self._mem.get(addr + i, 0).length}"
            b = self._mem.get(addr + i, BVV0_8) # TODO: 这里读了未初始化的内存
            v += b.zero_extend(256 - 8)

        return claripy.simplify(v)

    def _inner_write(self, addr: int, size: int, val: BV) -> None:
        '''
        return a 256-bits BV

        size: byte granularity
        '''
        assert isinstance(val, BV)
        assert isinstance(size, int)


        '''
        >>> from claripy import *
        >>> a = BVV(0xffffffffffffffff, 64)
        >>> b = a[63:56]
        >>> b.size()
        8
        '''
        for i in range(size):
            self._mem[addr + i] = val[size * 8 - i * 8 - 1:size * 8 - i * 8 - 8]
            assert self._mem[addr + i].size() == 8


    
    def _read_one_word(self, addr: int) -> Union[CONCRETE, BV]:
        '''
        return 4-byte BV
        '''
        assert addr % 2 == 0
        # TODO:???? 从未初始化的内存读吗
        # assert self._mem.get(addr) is not None, f"get uninit mem at {hex(addr)}" # NOTE: 应该没有人从未初始化的内存中读东西吧？

        ret256 = self._inner_read(addr, 4)
        return ret256[31:0]
    
    def _write_one_byte(self, addr: int, val: BV) -> None:

        assert isinstance(val, BV)
        assert isinstance(addr, int)
        
        assert val.length == 8
        self._mem[addr] = val

    def _read_one_byte(self, addr: int) -> BV:
        assert isinstance(addr, int)
        # 默认为0
        return self._mem.get(addr, claripy.BVV(0, 8))

    # TODO: change it to byte width
    # TODO: 重构 变成slot + byte更改的形式效率更高
    def read(self, addr: int, bytes_size: int) -> BV:# TODO: type
        '''
        size: bits-width
        '''
        assert isinstance(addr, int)
        assert isinstance(bytes_size, int)
        assert addr % 2 == 0
        # assert self._mem.get(addr) is not None # NOTE: 应该没有人从未初始化的内存中读东西吧？

        assert bytes_size % 32 == 0
        assert 0 <= bytes_size and bytes_size <= 0xff     # TODO: maybe?
        
        v = BVV0
        # TODO: simplify it
        for i in range(bytes_size):
            v = v << 8 
            e = self._read_one_byte(addr + i)
            assert isinstance(e, BV)
            assert e.size() == 8, repr(e.size())
            v = v | e.zero_extend(256 - 8)

        # self._have_read.add(addr)
        return claripy.simplify(v)
    
    # TODO: MSTORE8 ?????
    # NOTE: solidity can only use MSTORE to write 32-bytes value but 
    #       can read any bits from memory in other instruction
    # def write(self, addr: int, bits_size: int, val: Union[CONCRETE, BV]) -> None:
    #     # CHECK: LOGIC
    #     if isinstance(val, BV):
    #         if val.size() != 32:
    #             if val.concrete:
    #                 val = claripy.BVV(val.concrete_value, 32)
    #             else: # symbolic
    #                 # REF: https://api.angr.io/projects/claripy/en/latest/api.html#claripy.ast.BV
    #                 val = val[31:0] # rightmost 32-bits
    #     elif isinstance(val, int):
    #         val = claripy.BVV(val, 32)
    #     else:
    #         raise TypeError(type(val))

    #     assert isinstance(val, BV)

    #     assert bits_size % 8 == 0
    #     self._inner_write(addr, bits_size // 8, val)

    # NOTE: solidity can only use MSTORE to write 32-bytes value but 
    #       can read any bits from memory in other instruction
    def write(self, addr: int, bytes_size: int, val: BV) -> None:
        
        # avoid confusing concrate and concrate_value 
        assert not isinstance(addr, bool)

        if bytes_size == 32:

            if isinstance(val, BV):
                assert val.length == 256
                # if val.concrete:
                #     val = claripy.BVV(val.concrete_value, 32)
                # else: # symbolic
                #     # REF: https://api.angr.io/projects/claripy/en/latest/api.html#claripy.ast.BV
                #     val = val[31:0] # rightmost 32-bits
            elif isinstance(val, int):
                val = claripy.BVV(val, 256)
            else:
                raise TypeError(type(val))

            self._write256(addr, val)
        
        else:
            assert isinstance(val, BV)
            assert val.length == bytes_size

            bvs = val.chop(8)
            for i in range(bytes_size):
                self._write_one_byte(addr+i, bvs[i])

    def _write256(self, addr: int, val: BV) -> None:
        bvs = val.chop(8)
        for i in range(32):
            self._mem[addr+i] = bvs[i]

    # 增加 set get方法 假设是mem[ost:ost+64] 就拆分成两个32去读 先不考虑8bits
    ...

# def convert_bv(val: Union[int, BV]) -> BV:
#     if isinstance(val, BV):
#         return val
#     return symbol_factory.BVVal(val, 256)


# No of iterations to perform when iteration size is symbolic
# APPROX_ITR = 100


# class Memory:
#     """A class representing contract memory with random access."""

#     def __init__(self):
#         """"""
#         self._msize = 0
#         self._memory: Dict[BV, Union[int, BV]] = {}

#     def __len__(self):
#         """

#         :return:
#         """
#         return self._msize

#     def __copy__(self):
#         new_memory = Memory()
#         new_memory._memory = copy.deepcopy(self._memory)
#         new_memory._msize = self._msize
#         return new_memory

#     def extend(self, size: int):
#         """

#         :param size:
#         """
#         self._msize += size

#     def get_word_at(self, index: int) -> Union[int, BV]:
#         """Access a word from a specified memory index.

#         :param index: integer representing the index to access
#         :return: 32 byte word at the specified index
#         """
#         try:
#             return symbol_factory.BVVal(
#                 util.concrete_int_from_bytes(
#                     bytes([util.get_concrete_int(b) for b in self[index : index + 32]]),
#                     0,
#                 ),
#                 256,
#             )
#         except TypeError:
#             result = simplify(
#                 Concat(
#                     [
#                         b if isinstance(b, BV) else symbol_factory.BVVal(b, 8)
#                         for b in cast(
#                             List[Union[int, BV]], self[index : index + 32]
#                         )
#                     ]
#                 )
#             )
#             assert result.size() == 256
#             return result

#     def write_word_at(self, index: int, value: Union[int, BV, bool, Bool]) -> None:
#         """Writes a 32 byte word to memory at the specified index`

#         :param index: index to write to
#         :param value: the value to write to memory
#         """
#         try:
#             # Attempt to concretize value
#             if isinstance(value, bool):
#                 _bytes = (
#                     int(1).to_bytes(32, byteorder="big")
#                     if value
#                     else int(0).to_bytes(32, byteorder="big")
#                 )
#             else:
#                 _bytes = util.concrete_int_to_bytes(value)
#             assert len(_bytes) == 32
#             self[index : index + 32] = list(bytearray(_bytes))
#         except (Z3Exception, AttributeError):  # BVtor or BoolRef
#             value = cast(Union[BV, Bool], value)
#             if isinstance(value, Bool):
#                 value_to_write = If(
#                     value,
#                     symbol_factory.BVVal(1, 256),
#                     symbol_factory.BVVal(0, 256),
#                 )
#             else:
#                 value_to_write = value
#             assert value_to_write.size() == 256

#             for i in range(0, value_to_write.size(), 8):
#                 self[index + 31 - (i // 8)] = Extract(i + 7, i, value_to_write)

#     @overload
#     def __getitem__(self, item: BV) -> Union[int, BV]:
#         ...

#     @overload
#     def __getitem__(self, item: slice) -> List[Union[int, BV]]:
#         ...

#     def __getitem__(
#         self, item: Union[BV, slice]
#     ) -> Union[BV, int, List[Union[int, BV]]]:
#         """

#         :param item:
#         :return:
#         """
#         if isinstance(item, slice):
#             start, step, stop = item.start, item.step, item.stop
#             if start is None:
#                 start = 0
#             if stop is None:  # 2**256 is just a bit too big
#                 raise IndexError("Invalid Memory Slice")
#             if step is None:
#                 step = 1
#             bvstart, bvstop, bvstep = (
#                 convert_bv(start),
#                 convert_bv(stop),
#                 convert_bv(step),
#             )
#             ret_lis = []
#             symbolic_len = False
#             itr = symbol_factory.BVVal(0, 256)
#             if (bvstop - bvstart).symbolic:
#                 symbolic_len = True

#             while simplify(bvstep * itr != simplify(bvstop - bvstart)) and (
#                 not symbolic_len or itr <= APPROX_ITR
#             ):
#                 ret_lis.append(self[bvstart + bvstep * itr])
#                 itr += 1
#             return ret_lis
#         item = simplify(convert_bv(item))
#         return self._memory.get(item, 0)

#     def __setitem__(
#         self,
#         key: Union[int, BV, slice],
#         value: Union[BV, int, List[Union[int, BV]]],
#     ):
#         """

#         :param key:
#         :param value:
#         """
#         if isinstance(key, slice):
#             start, step, stop = key.start, key.step, key.stop

#             if start is None:
#                 start = 0
#             if stop is None:
#                 raise IndexError("Invalid Memory Slice")
#             if step is None:
#                 step = 1
#             else:
#                 assert False, "Currently mentioning step size is not supported"
#             assert isinstance(value, list)
#             bvstart, bvstop, bvstep = (
#                 convert_bv(start),
#                 convert_bv(stop),
#                 convert_bv(step),
#             )
#             symbolic_len = False
#             itr = symbol_factory.BVVal(0, 256)
#             if (bvstop - bvstart).symbolic:
#                 symbolic_len = True
#             while simplify(bvstep * itr != simplify(bvstop - bvstart)) and (
#                 not symbolic_len or itr <= APPROX_ITR
#             ):
#                 self[bvstart + itr * bvstep] = cast(List[Union[int, BV]], value)[
#                     itr.value
#                 ]
#                 itr += 1

#         else:
#             bv_key = simplify(convert_bv(key))
#             if bv_key >= len(self):
#                 return
#             if isinstance(value, int):
#                 assert 0 <= value <= 0xFF
#             if isinstance(value, BV):
#                 assert value.size() == 8
#             self._memory[bv_key] = cast(Union[int, BV], value)
