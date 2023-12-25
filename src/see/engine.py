# symbolic execute engine
from utils import *
from queue import PriorityQueue, Queue
from fuzzer import Fuzzer
import numbers
import const
import math
import pdb

from vulns import VulnTypes
from collections import defaultdict

from evm.state import State
from disassembler import SolidityBinary
from evm.contract import Contract
from evm.transaction import Transaction
from assistant.observer import Observer
from assistant.statewindow import StateWindow
from threading import Thread
from rich.console import Console
console = Console()

class SymExecEngine:
    def __init__(self, sb: SolidityBinary, con: Contract) -> None:
        # self.branch_queue = PriorityQueue() #TODO:
        self.branch_queue = Queue() 
        self.sb = sb
        self.states_hash_seen = set()
        # add a init state
        self.contract = con # TODO:

        self.add_branch(State(con))# initial state 

        self.tracer = [] # for debug
        self.fuzz = Fuzzer(con)
        self.bugs: Dict[VulnTypes, List[State]] = defaultdict(lambda: []) # TODO: vuln catalogue
        self.observer = Observer(sb.instructions)
        # self.observer.notify_statewindow_shutdown = True # TODO: debug mode
    
    # TEMP:
    def add_for_fuzz(self, s: State, var: BV, tries: List[Callable]=[]) -> None:
        '''
        fuzz a var and generate corresponding state for this variable
        '''
        raise NotImplementedError
        logger.critical("add_for_fuzz")
        # TODO: sketchy fuzz strategy
        to_try = set()
        nb_random = 0
        for t in tries:  # pylint:disable=invalid-name
            if isinstance(t, numbers.Number) and s.solver.solution(var, t):
                to_try.add(t)
            elif t is min:
                to_try.add(self.solver.min(var))
            elif t is max:
                to_try.add(s.solver.max(var))
            elif t is None:
                nb_random += 1
        if nb_random:
            to_try |= set(s.solver.eval(var, nb_random))

        s.depth += (
            1 if len(to_try) == 1 else 10 # TODO:
        )  # Lower the priority of what we got by fuzzing.
        for value in to_try:
            new_state = s.clone()
            new_state.solver.add(var == value)
            self.add_branch(new_state)


    def add_branch(self, s: State) -> None:

        s.solver.downsize()
        s.solver.simplify()

        # 对一个约束条件起两个分支 其中一个可能走不了
        logger.debug(s.solver.constraints)
        if not s.solver.satisfiable():
            logger.warning(f"state can't satisfiable {s.solver.constraints}")
            return 

        if hash(s) in self.states_hash_seen:
            logger.debug("avoided adding visited state")
            return

        self.states_hash_seen.add(hash(s))
        # 默认小顶堆
        self.branch_queue.put((s.depth, s))
    
    def execute(self):# NOTE: timeout

        assert not self.branch_queue.empty()

        txn = self.fuzz.build_one_txn("vuln") # TODO:
        
        # wind thread
        wt = Thread(
            target=StateWindow().show_terminal, 
            args=(self.observer,)
        )
        wt.start()

        try:
            temp_flag = False
            while not self.branch_queue.empty():
                # NOTE: qsize only work in single-thread environment
                from evm.state import STATE_COUNTER #TODO： 记录
                logger.debug(f"self.branch_queue len is {self.branch_queue.qsize()}")
                logger.debug(f"total states cound is is {STATE_COUNTER}")
                self.observer.cur_state_count = self.branch_queue.qsize()
                self.observer.total_state_count = STATE_COUNTER

                depth: int; state: State
                depth, state = self.branch_queue.get()

                state.depth += 1

                # TODO: temporary avoid circular traverse
                if state.pc == 0:
                    if temp_flag == False:
                        temp_flag = True
                    else:
                        logger.warning("circular detected")
                        continue

                # logger.info("execute at pc: %#x with depth %i." % (state.pc, depth))

                success = self.exec_branch(state, txn)

                # success means copy a new state and not encounter any terminal instruction TODO:
                # state.print_exec_trace()
                if not success:
                    pass
                    # logger.info("execution failed")

            for bug in VulnTypes:
                if len(self.bugs[bug]) > 0:
                    logger.critical(f"found {bug}")

        except Exception:
            self.observer.notify_statewindow_shutdown = True
            wt.join() # 一定要让join能把thread收回来 不然就没法中断了
            console.print_exception(show_locals=True)
        finally:
            self.observer.notify_statewindow_shutdown = True
            wt.join()

    def exec_branch(self, state: State, txn: Transaction) -> bool:
        """Execute forward from a state, queuing new states if needed."""
        # logger.debug("Constraints: %s" % state.solver.constraints)

        while True:
            if state.pc > self.sb.end_addr:
                return True
            
            state.exec_addrs.append(state.pc)
            # need to setup a map in pc => inst or 
            # provide a method in sb for next_inst call
            curinst = self.sb.pc2inst(state.pc)
            # curinst = self.sb.instructions[state.pc]
            op = curinst.opcode
            self.tracer.append(
                "{:08x}: {}".format(state.pc, curinst)
            )
            # self.coverage[state.pc] += 1

            logger.debug("------- NEW STEP -------")
            # logger.debug("Memory: %s" % state.memory)
            logger.debug("PC: %#x, op: %#x(%s)" % (state.pc, op, curinst.name))
            logger.debug("\nStorage: %s\n" % state.storage)
            logger.debug("\nStack: %s" % state.stack)

            # if len(state.stack) > 0 and state.stack[-1].symbolic and "input-uint256_3" in str(state.stack[-1]) and curinst.name == "SSTORE":
            #     self.observer.notify_statewindow_shutdown = True
            #     import pdb;pdb.set_trace()

            assert isinstance(op, numbers.Number)
            assert all(
                isinstance(i, claripy.ast.base.BV) for i in state.stack
            ), "The stack musty only contains claripy BV's"

            self.observer.hit_at(state.pc)

            bps = []
            for bp in bps:
                if state.pc == bp:
                    self.observer.notify_statewindow_shutdown = True
                    import pdb; pdb.set_trace()

            # Trivial operations first
            # TODO: sanity check
            if False:
                ...
            # if not self.code.is_valid_opcode(state.pc):
                # raise Exception("Trying to execute PUSH data")
            elif op == 254:  # INVALID opcode
                # TODO: handle it
                ...
                # return False
                # raise Exception("designed INVALID opcode")
            elif op == const.opcode.JUMPDEST:
                pass
            elif op == const.opcode.ADD:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(s0 + s1)
            elif op == const.opcode.SUB:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(s0 - s1)
            elif op == const.opcode.MUL:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(s0 * s1)
            elif op == const.opcode.DIV:
                # TODO: 除数为0会导致revert
                # We need to use claripy.LShR instead of a division if possible,
                # because the solver is bad dealing with divisions, better
                # with shifts. And we need shifts to handle the solidity ABI
                # for function selection.
                [s0, s1] = state.stack_pop(2) # s0 / s1
                try:
                    s1 = state.find_one_solution(s1)  # pylint:disable=invalid-name 获得一个具体值
                except SymbolicMultiSolutions:

                    assert s1.symbolic
                    # 有多个解 s1 是symbolic的
                    state.solver.add(s1 != 0)
                    state.stack_push(s0 // s1)
                    # state.stack_push(claripy.If(s1 == 0, BVV0, s0 / s1))# 这里是不是可以抛出一个div zero 异常
                else:
                    if s1 == 0:
                        raise NotImplementedError("divide by zero")
                    elif s1 == 1:
                        state.stack_push(s0)
                    elif s1 % 2 == 0:
                        exp = int(math.log(s1, 2))
                        state.stack_push(s0.LShR(exp))
                    else:
                        raise NotImplementedError("奇数除法")
                        state.stack_push(s0 // s1)
            elif op == const.opcode.SDIV:
                [s0, s1] = state.stack_pop(2)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s1 == 0, BVV0, s0.SDiv(s1))) # TODO: 除数为0
                else:
                    state.stack_push(BVV0 if s1 == 0 else s0.SDiv(s1))
            elif op == const.opcode.MOD:
                [s0, s1] = state.stack_pop(2)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s1 == 0, BVV0, s0 % s1)) # TODO: mod 0
                else:
                    state.stack_push(BVV0 if s1 == 0 else s0 % s1)
            elif op == const.opcode.SMOD:
                [s0, s1] = state.stack_pop(2)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s1 == 0, BVV0, s0.SMod(s1))) # TODO: mod 0
                else:
                    state.stack_push(BVV0 if s1 == 0 else s0.SMod(s1))
            elif op == const.opcode.ADDMOD: # (a + b) % N
                [s0, s1, s2] = state.stack_pop(3)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s2 == 0, BVV0, (s0 + s1) % s2))
                else:
                    state.stack_push(BVV0 if s2 == 0 else (s0 + s1) % s2)
            elif op == const.opcode.MULMOD:
                [s0, s1, s2] = state.stack_pop(3)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s2 == 0, BVV0, (s0 * s1) % s2))
                else:
                    state.stack_push(BVV0 if s2 == 0 else (s0 * s1) % s2)
            elif op == const.opcode.SHL:
                [shift, value] = state.stack_pop(2)
                state.stack_push(value << shift)
            elif op == const.opcode.SHR:
                [shift, value] = state.stack_pop(2)
                state.stack_push(value.LShR(shift))
            elif op == const.opcode.SAR:
                [shift, value] = state.stack_pop(2)
                state.stack_push(claripy.RotateRight(value, shift))
            elif op == const.opcode.EXP: # a ** b
                [base, exp] = state.stack_pop(2)
                base_solu = state.find_one_solution(base)
                if base_solu == 2:
                    state.stack_push(1 << exp)
                else:
                    try:
                        exp_solu = state.find_one_solution(exp)
                    except MultipleSolutionsError:
                        state.stack_push(exp)  # restore stack
                        state.stack_push(base)
                        self.add_for_fuzz(state, exp, EXP_EXPONENT_FUZZ)
                        return False
                    else:
                        state.stack_push(claripy.BVV(base_solu ** exp_solu, 256))
            elif op == const.opcode.LT: # a < b
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(claripy.ULT(s0, s1), BVV1, BVV0)
                )
            elif op == const.opcode.GT:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(claripy.UGT(s0, s1), BVV1, BVV0)
                )
            elif op == const.opcode.SLT:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(claripy.SLT(s0, s1), BVV1, BVV0)
                )
            elif op == const.opcode.SGT:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(claripy.SGT(s0, s1), BVV1, BVV0)
                )
            elif op == const.opcode.SIGNEXTEND: # sign extend s1 from (s0+1) bytes to 32 bytes
                raise NotImplementedError
                # TODO: Use Claripy's SignExt that should do exactly that.
                [s0, s1] = state.stack_pop(2)
                # s0 is the number of bits. s1 the number we want to extend.
                s0 = state.find_one_solution(s0)
                if s0 <= 31:
                    # 分正数和复数
                    sign_bit = 1 << (s0 * 8 + 7)
                    state.stack_push(
                        claripy.If(
                            s1 & sign_bit == 0,
                            s1 & (sign_bit - 1),
                            s1 | ((1 << 256) - sign_bit),
                        )
                    )
                else:
                    assert s0 == 32
                    state.stack_push(s1)
            elif op == const.opcode.EQ:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(s0 == s1, BVV1, BVV0)
                )
            elif op == const.opcode.ISZERO:
                state.stack_push(
                    claripy.If(state.stack_pop() == BVV0, BVV1, BVV0)
                )
            elif op == const.opcode.AND:
                [s0, s1] = state.stack_pop(2)
                # fix for python10 claripy
                state.stack_push(
                    claripy.If(
                        claripy.And((s0 != BVV0), (s1 != BVV0)), 
                        BVV1, 
                        BVV0
                    )
                )
            elif op == const.opcode.OR:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    claripy.If(
                        claripy.Or((s0 != BVV0), (s1 != BVV0)), 
                        BVV1, 
                        BVV0
                    )
                )
            elif op == const.opcode.XOR:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(s0 ^ s1)
            elif op == const.opcode.NOT:
                state.stack_push(~state.stack_pop())
            elif op == const.opcode.BYTE:
                # ith byte of (u)int256 x, from the left
                # i, x
                # (x >> (248 - i * 8)) && 0xFF
                [s0, s1] = state.stack_pop(2)
                state.stack_push(
                    s1.LShR(claripy.If(s0 > 31, 32, 31 - s0) * 8) & 0xFF
                )

            elif op == const.opcode.PC:
                state.stack_push(bvv(state.pc))
            elif op == const.opcode.GAS:
                # gasRemaining
                # TODO:貌似不影响什么 随便给个值
                # raise NotImplementedError
                state.stack_push(claripy.BVV(10000000, 256))
            elif op == const.opcode.ADDRESS:
                raise NotImplementedError
                state.stack_push(state.env.address)
            elif op == const.opcode.CHAINID:
                raise NotImplementedError
                state.stack_push(state.env.chainid)
            elif op == const.opcode.SELFBALANCE:
                raise NotImplementedError
                state.stack_push(state.env.balance)
            elif op == const.opcode.BALANCE:
                # addr.balance
                raise NotImplementedError
                addr = state.find_one_solution(state.stack_pop())# WHY?
                if addr != solution(state.env.address):
                    raise utils.InterpreterError(
                        state, "Can only query balance of the current contract for now"
                    )
                state.stack_push(state.env.balance)
            elif op == const.opcode.ORIGIN:
                raise NotImplementedError
                state.stack_push(state.env.origin)
            elif op == const.opcode.CALLER:
                raise NotImplementedError
                state.stack_push(state.env.caller)
            elif op == const.opcode.CALLVALUE:
                # raise NotImplementedError
                # TODO: 没有fallback函数 如果有msg.value会导致revert
                # state.stack_push(claripy.BVS(f"CALLVALUE[{state.pc}]", 256))# TODO: use Txn or Contract
                state.stack_push(txn.value)
            elif op == const.opcode.BLOCKHASH:
                raise NotImplementedError
                block_num = state.stack_pop()
                if block_num not in state.env.block_hashes:
                    state.env.block_hashes[block_num] = claripy.BVS(
                        "blockhash[%s]" % block_num, 256
                    )
                state.stack_push(state.env.block_hashes[block_num])
            elif op == const.opcode.TIMESTAMP:
                raise NotImplementedError
                state.stack_push(state.env.block_timestamp)
            elif op == const.opcode.NUMBER:
                raise NotImplementedError
                state.stack_push(state.env.block_number)
            elif op == const.opcode.COINBASE:
                raise NotImplementedError
                state.stack_push(state.env.coinbase)
            elif op == const.opcode.DIFFICULTY:
                raise NotImplementedError
                state.stack_push(state.env.difficulty)
            elif op == const.opcode.POP:
                state.stack_pop()
            elif op == const.opcode.JUMP:
                # $pc := dst
                # TODO: check here arbitrary jump
                addr = state.stack_pop()
                
                if addr.symbolic:
                    self.observer.add_a_vuln(
                        VulnTypes.ARBITRARY_JUMP,
                        state
                    )
                    return False # TODO:
                else:
                    addr = addr.concrete_value

                    if addr > self.sb.end_addr or self.sb.instruction_at(addr).opcode != const.opcode.JUMPDEST:# TODO:
                        raise Exception("Invalid jump (0x%x) at pc 0x%x" % (addr, state.pc)) # TODO:
                    state.pc = addr
                    self.add_branch(state)
                    return False
            
            elif op == const.opcode.JUMPI:

                addr, cond = state.stack_pop(), state.stack_pop()
                # if state.pc == 0x024d:
                #     import pdb;pdb.set_trace()
                
                if addr.symbolic:
                    raise NotImplementedError("arbitrary jump")

                elif cond.symbolic:
                    
                    state_false = state.clone()
                    state_false.solver.add(cond == BVV0)# 为0的时候没法跳转
                    state_false.pc += 1
                    self.add_branch(state_false)
                    
                    state.solver.add(cond != BVV0)
                    state.pc = addr.concrete_value
                    if not self.sb.check_pc_jmp_valid(state.pc):
                        raise Exception("Invalid jump (0x%x)" % (state.pc - 1)) # TODO:

                    self.add_branch(state)

                    return True
                
                else:# addr and cond neither symbolic
                    if cond.concrete_value == 0:
                        # continue to execute to next instruction
                        pass

                    else: # EVM allow non-zero condition value
                        # subsequent state.pc += 1
                        state.pc = addr.concrete_value - 1
                        

            elif op == const.opcode.PUSH0:
                '''
                This is because solidity 0.8.20 introduces the PUSHO(Ox5f) opcode 
                which is only supported on ETH mainnet and not on anyother chains. 
                That's why other chains can't find the PUSHO(0x5f) opcode and throw this error.
                '''
                state.stack_push(BVV0)

            elif const.opcode.PUSH1 <= op <= const.opcode.PUSH32:
                '''
                PUSH1 60
                PUSH2 4070
                '''
                pushnum = op - const.opcode.PUSH1 + 1

                state.stack_push(
                    claripy.BVV(int(curinst.operand, 16), 256)
                )
                # NOTE: pc += ... must below the push which is used this pc
                state.pc += pushnum

            elif const.opcode.DUP1 <= op <= const.opcode.DUP16:
                # clone ith value on stack
                depth = op - const.opcode.DUP1 + 1
                # dup = state.stack.stack[-depth] # TODO: provide a stack index select
                state.stack_dup(depth)

            elif const.opcode.SWAP1 <= op <= const.opcode.SWAP16:
                depth = op - const.opcode.SWAP1 + 1
                state.stack_swap(depth)

            elif const.opcode.LOG0 <= op <= const.opcode.LOG4:
                '''
                永久记录一个函数签名+参数在区块链上
                '''
                raise NotImplementedError
                # TODO: 这个应该不需要模拟
                # LOG0(memory[ost:ost+len-1])
                # LOG1(memory[ost:ost+len-1], topic0, topic1)
                depth = op - const.opcode.LOG0
                dstost, mlen = (state.stack_pop(), state.stack_pop())
                topics = [state.stack_pop() for _ in range(depth)]
            elif op == const.opcode.SHA3:# TODO:
                raise NotImplementedError

                fos = state.find_one_solution

                s0 = state.stack_pop()
                s1 = state.stack_pop()

                start, length = fos(s0), fos(s1)
                memory = state.memory.read(start, length)# TODO:
                state.stack_push(Sha3(memory))# TODO:

            elif op == const.opcode.STOP:
                # halt execution
                return True

            elif op == const.opcode.RETURN:
                # return mem[ost:ost+len-1]
                return True

            elif op == const.opcode.CALLDATALOAD:
                # TODO： reconstruct
                index = state.stack_pop()

                if index.concrete:
                    
                    if index.concrete_value == 0 : # signature
                        state.stack_push(
                            txn.msg.signature
                        )

                    else:
                        v = index.concrete_value - 4
                        assert v % 32 == 0, f"v = {v}"
                        i = v // 32

                        logger.debug(f"push {txn.msg[i]}")
                        state.stack_push(
                            txn.msg[i]
                        )
                    
                    # return # TODO: why return? maybe state changed
                else:
                    raise NotImplementedError
                # TODO: check following
                    try:
                        index_sol = state.find_one_solution(index)
                    except MultipleSolutionsError:
                        state.stack_push(index)  # restore the stack
                        # TODO: maybe use Calldata class be batter?
                        CALLDATALOAD_INDEX_FUZZ = Todo()
                        # self.add_for_fuzz(state, index, CALLDATALOAD_INDEX_FUZZ)
                        self.add_for_fuzz(state, index)
                        return False
                    
                    raise NotImplementedError
                    state.stack_push(state.env.calldata.read(index_sol, 32))

            elif op == const.opcode.CALLDATASIZE:
                state.stack_push(txn.msg.len)
                
            elif op == const.opcode.CALLDATACOPY:
                # dstOst, ost, len
                # mem[dstOst:dstOst+len-1] := msg.data[ost:ost+len-1]
                old_state = state.clone()
                dstost, ost, size = (
                    state.stack_pop(),
                    state.stack_pop(),
                    state.stack_pop(),
                )
                fos: Callable = state.find_one_solution

                dstost, ost = fos(dstost), fos(ost)
                try:
                    size = fos(size)
                except MultipleSolutionsError:
                    CALLDATACOPY_SIZE_FUZZ = Todo()
                    # TODO: 
                    self.add_for_fuzzing(old_state, size, CALLDATACOPY_SIZE_FUZZ)
                    return False
                
                assert size == 32 # TODO: check 也许能把32改成循环
                assert (ost - 4) % 32 == 0

                msg_idx = (ost - 4) // 32
                msg = txn.msg[msg_idx]

                assert msg.size() == 256

                state.memory.write(
                    dstost, size, msg
                )

                # state.memory.copy_from(state.env.calldata, dstost, ost, size)
            elif op == const.opcode.CODESIZE:
                state.stack_push(bvv(len(self.sb.instructions)))
            elif op == const.opcode.EXTCODESIZE:
                raise NotImplementedError
                addr = state.stack_pop()
                # TODO:
                if (addr == state.env.address).is_true():
                    state.stack_push(bvv(len(self.code)))
                else:
                    # TODO: Improve that... It's clearly not constraining enough.
                    state.stack_push(claripy.BVS("EXTCODESIZE[%s]" % addr, 256))

            elif op == const.opcode.EXTCODECOPY:
                # addr, dstOst, ost, len
                # mem[dstOst:dstOst+len-1] := addr.code[ost:ost+len-1]
                raise NotImplementedError
                old_state = state.clone()
                addr = state.stack_pop()

                mem_start  = state.find_one_solution(state.stack_pop())
                code_start = state.find_one_solution(state.stack_pop())

                size = state.stack_pop()
                try:
                    size = state.find_one_solution(size)
                except MultipleSolutionsError:
                    # TODO: Fuzz.
                    # self.add_for_fuzzing(old_state, size, [])
                    # return False
                    raise
                state.memory.write(# TODO:
                    mem_start,
                    size,
                    claripy.BVS("EXTCODE[%s from %s]" % (addr, code_start), size * 8),
                )

            elif op == const.opcode.CODECOPY:
                raise NotImplementedError
                # dstOst, ost, len
                # mem[dstOst:dstOst+len-1] := this.code[ost:ost+len-1]
                fos: Callable = state.find_one_solution
                dst_ost, ost, size = [
                    fos(state.stack_pop()) for _ in range(3)
                ]
                # assert size % 32 == 0, logger.critical("size = %#x" % (size))
                # TODO: follow
                # 这里的size是按bit来的
                end = size // 32
                # CHECK: 
                for i in range(end):
                    if ost + i < len(self.sb.instructions):
                        state.memory.write(
                            dst_ost + i,
                            32,
                            claripy.BVV(self.sb.bytecode[ost + i:ost + i + 4], 32),
                        )
                    else:
                        raise NotImplementedError
                        state.memory.write(mem_start + i, 1, claripy.BVV(0, 8))

            elif op == const.opcode.MLOAD:
                idx = state.stack_pop()

                if idx.symbolic:
                    raise NotImplementedError
                    
                state.stack_push(
                    state.memory.read(idx.concrete_value, 32)
                )# TODO

            elif op == const.opcode.MSTORE:
                idx, value = state.stack_pop(), state.stack_pop()

                if idx.symbolic:
                    raise NotImplementedError
                    
                logger.debug(f"MSTORE : mem[{idx}] = {value}")
                state.memory.write(idx.concrete_value, 32, value)# TODO
                
            elif op == const.opcode.MSTORE8:
                raise NotImplementedError
                index, value = state.find_one_solution(state.stack_pop()), state.stack_pop()
                state.memory.write(index, 1, value[7:0])# TODO
            elif op == const.opcode.MSIZE:
                state.stack_push(bvv(state.memory.size()))# TODO

            elif op == const.opcode.SLOAD:# stack.push(storage[key])

                key = state.stack_pop()
                
                if key.concrete:
                    state.stack_push(
                        state.storage[key]
                    )
                else:
                    raise NotImplementedError

                # for w_key, w_value in state.storage_written.items():
                #     read_from_written = [w_key == key]
                #     # 能从任何一个写过的storage slot读出
                #     if state.solver.satisfiable(extra_constraints=read_from_written):
                #         new_state = state.clone()
                #         new_state.solver.add(read_from_written)# 如果可以对一个地方写两次 就创建一个新状态 让 w_key == key
                #         new_state.stack_push(w_value)
                #         self.add_branch(new_state)
                #     state.solver.add(w_key != key)# 老状态没法eval出 w_key == key
                # # 满足从一个没读过的storage slot读
                # if state.solver.satisfiable():
                #     raise Exception("impossible") # TODO:
                #     assert key not in state.storage_written # TODO:
                #     if key not in state.storage_read:
                #         state.storage_read[key] = claripy.BVS("storage[%s]" % key, 256)
                #     state.stack_push(state.storage_read[key])
                #     self.add_branch(state)
                # return

            elif op == const.opcode.SSTORE:
                # write value to storage[key]
                key = state.stack_pop()
                value = state.stack_pop()
                
                if key.concrete:
                    state.storage[key] = value
                else:
                    raise NotImplementedError("idx is symbolic 任意写？")
                # # TODO: 如果能写一个没读过的 算不算任意写呢？（好像不算 但是读才算
                # for w_key, w_value in state.storage_written.items():
                #     read_from_written = [w_key == key]
                #     if state.solver.satisfiable(extra_constraints=read_from_written):
                #         new_state = state.clone()
                #         new_state.solver.add(read_from_written)
                #         new_state.storage_written[w_key] = value
                #         self.add_branch(new_state)
                #     state.solver.add(w_key != key)
                # # 如果能写一个没写过的地方
                # if state.solver.satisfiable():
                #     assert key not in state.storage_written
                #     state.storage_written[key] = value
                #     self.add_branch(state)
                # return

            elif op == const.opcode.CALL:
                raise NotImplementedError
                # gas, addr, val, argOst, argLen,
                # mem[retOst:retOst+retLen-1] := returndata
                state.pc += 1

                # pylint:disable=unused-variable
                gas, to_, value, meminstart, meminsz, memoutstart, memoutsz = (
                    state.stack_pop() for _ in range(7)
                )

                # First possibility: the call fails
                # (always possible with a call stack big enough)
                state_fail = state.clone()
                state_fail.stack.push(BVV0) # push a success
                self.add_branch(state_fail)

                # Second possibility: success.
                state.calls.append(
                    (memoutsz, memoutstart, meminsz, meminstart, value, to_, gas)
                )

                memoutsz = state.find_one_solution(memoutsz)
                if memoutsz != 0:
                    # If we expect some output, let's constraint the call to
                    # be to a contract that we do control. Otherwise it could
                    # return anything...
                    utils = Todo()
                    state.solver.add(to_[159:0] == utils.DEFAULT_CALLER[159:0])
                    # TODO: 这里能实现一个call指定账户的操作

                    memoutstart = state.find_one_solution(memoutstart)
                    state.memory.write(
                        memoutstart,
                        memoutsz,
                        claripy.BVS("CALL_RETURN[%s]" % to_, memoutsz * 8),
                    )

                state.stack_push(BVV1)
                self.add_branch(state)
                return False

            elif op == const.opcode.DELEGATECALL:# TODO:
                '''
                When delegatecall is used, the called contract’s function is executed in the context of the calling contract, 
                calling address(this) should return the calling contract’s address.

                其实就是this是调用合约

                DELEGATECALL
                 pop : gas, addr, argOst(参数在内存中的位置), argLen(字节单位), retOst, retLen
                  op : mem[retOst:retOst+retLen-1] := returndata
                push : success
                '''
                gas, addr, argost, arglen, retost, retlen = (
                    state.stack_pop() for _ in range(6)
                )

                assert argost.concrete and arglen.concrete

                # data = state.memory.read(argost.concrete, arglen.concrete * 8)
                # NOTE: 无论data为什么 理论上都能进行攻击
                if addr.symbolic:
                    if state.solver.satisfiable(extra_constraints=[addr==ATTACK_ACCOUNT_ADDRESS]):
                        self.observer.add_a_vuln(
                            VulnTypes.DELEGATECALL,
                            state
                        )

                        state.pc += 1
                        return
                    else:
                        raise RuntimeError("symbolic but not satisfiable?")
                
                # NOTE: assume delegatecall must success but not write the memory
                state.stack_push(BVV1)

                state.calls.append(
                    (gas, addr, argost, arglen, retost, retlen)
                )

                state.pc += 1

            elif op == const.opcode.RETURNDATASIZE:# TODO:
                # ref: https://eips.ethereum.org/EIPS/eip-211
                # 就是一次call后返回的data的size
                # raise NotImplementedError
                state.stack_push(claripy.BVS("RETURNDATASIZE", 256))# TODO: 也许需要与CALLDATA保持一致？

            elif op == const.opcode.RETURNDATACOPY:
                # TODO:
                raise NotImplementedError
                old_state = state.clone()
                mem_start_position = state.find_one_solution(state.stack_pop())
                returndata_start_position = state.find_one_solution(state.stack_pop())

                size = state.stack_pop()
                try:
                    size = solution(size)
                except MultipleSolutionsError:
                    self.add_for_fuzzing(old_state, size, RETURNDATACOPY_SIZE_FUZZ)
                    return False

                state.memory.write(
                    mem_start_position, size, claripy.BVS("RETURNDATACOPY", size * 8)
                )

            elif op == const.opcode.SELFDESTRUCT:
                
                addr = state.stack_pop()
                
                if addr.symbolic:
                    constraint = [addr == ATTACK_ACCOUNT_ADDRESS]

                    if state.solver.satisfiable(extra_constraints=constraint):
                        self.observer.add_a_vuln(
                            VulnTypes.SELFDESTRUCT, state
                        )
                        state.selfdestruct_to = state.stack[-1] # TODO
                        logger.critical("selfdestruct detect successfully")

                    else:
                        raise NotImplementedError
                        
                return True

            elif op == const.opcode.REVERT:
                return False

            else:
                # TODO:
                raise Exception(state, "Unknown opcode %#x" % op)

            state.pc += 1    