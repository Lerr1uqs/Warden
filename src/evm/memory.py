from utils import *
import bisect
import copy
# TODO:
BV = claripy.ast.BV
bvv = lambda v : claripy.BVV(v, 256)
# NOTE: 内存的写入操作是找到freemem_pointer然后写4个字节过去 每一个slot还是32字节 所以这里只需要按地址编排写入位置即可 不需要管slot的索引了
class Memory(BaseModel):
# class Memory():
    '''
    memory的存储粒度是word 也就是4字节
    RETURN指令执行的时候是借助return mem[ost:ost+len-1]的 所以返回值一定会加载到内存中
    '''


    def __init__(self) -> None:
        super().__init__()# 一定要先初始化pydantic的基类 不然很多东西都没注册
        # self._msize = 0
        # NOTE: 粒度为1byte
        # self._mem: Dict[int, BV] = {}
        # import pdb;pdb.set_trace()

        self._msize = 0
        self._mem_limit    = 0x2000# TODO: 暂时

        self._have_read    = set()
        self._have_written = set()# TODO:

        self._mem: Dict[int, BV] = {}
        
    def __hash__(self) -> int:# TODO:
        r = 0
        for k, v in self._mem.items():
            r ^= hash(k) ^ hash(v)
        return r ^ hash(self._msize)


    def __len__(self):
        return self._msize

    def clone(self):
        new_memory = Memory()
        new_memory._mem = copy.deepcopy(self._mem)
        new_memory._msize = self._msize
        return new_memory

    def extend(self, size: int):
        self._msize += size

    def _inner_read(self, addr: int, size: int) -> BV:
        '''
        return a 256-bits BV
        '''
        v = BVV0
        for i in range(size):
            v = v << 8
            v += self._mem.get(addr + i, 0)

        return v

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
        assert addr % 2 == 0
        assert self._mem.get(addr) is not None # NOTE: 应该没有人从未初始化的内存中读东西吧？

        return self._inner_read(addr, 4)
    
    def _write_one_byte(self, addr: int, val: Union[CONCRETE, BV]) -> None:

        if isinstance(val, BV):
            assert val.size() == 8
        else:
            assert val <= 0xff
            val = claripy.BVV(val, 8)

        self._mem[addr] = val

    
    # TODO: change it to byte width
    def read(self, addr: int, bits_size: int) -> Union[CONCRETE, BV]:# TODO: type
        '''
        size: bits-width
        '''
        assert isinstance(addr, int)
        assert isinstance(bits_size, int)
        assert addr % 2 == 0
        assert self._mem.get(addr) is not None # NOTE: 应该没有人从未初始化的内存中读东西吧？

        assert bits_size % 32 == 0
        assert 0 <= bits_size and bits_size <= 0xff     # TODO: maybe?
        
        v = BVV0
        # TODO: simplify it
        for i in range(bits_size // 8):
            v = v << 8 * 4
            e = self._read_one_word(addr + i * 32)
            assert isinstance(e, BV)
            assert e.size() == 32
            v = v & e

        # self._have_read.add(addr)
        return v
    
    # TODO: MSTORE8 ?????
    # REMINDER: solidity can only use MSTORE to write 32-bits value but 
    #           can read any bits from memory in other instruction
    def write(self, addr: int, bits_size: int, val: Union[CONCRETE, BV]) -> None:
        # CHECK: LOGIC
        if isinstance(val, BV):
            if val.size() != 32:
                if val.concrete:
                    val = claripy.BVV(val.concrete_value, 32)
                else: # symbolic
                    # Ref: https://api.angr.io/projects/claripy/en/latest/api.html#claripy.ast.BV
                    val = val[31:0] # rightmost 32-bits
        else:
            val = bvv(val)

        assert isinstance(val, BV)

        assert bits_size % 8 == 0
        self._inner_write(addr, bits_size // 8, val)

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
