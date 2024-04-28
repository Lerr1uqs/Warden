'''
    symbolic execute engine
'''
import numbers
import random
import const
import math
import pdb

from assistant    import Observer, ConstraintEvalNotifier
from version      import VersionControl, Stage
from persistence  import ConstraintPersistor
from collections  import defaultdict, deque
from disassembler import SolidityBinary, Instruction
from evm          import Transaction
from assistant    import StateWindow
from vulns        import VulnTypes
from evm          import Contract
from copy         import deepcopy
from rich.console import Console
from fuzzer       import Fuzzer
from threading    import Thread
from .state       import State # TEMP: 
from utils        import *

from evmcfg.evmcfg.cfg   import CFG

console = Console()

def calculate_bv_args_leafnode(bv: BV) -> int:
    '''
    calculate leaf node number in bv args by bfs
    '''

    if not isinstance(bv, BV):
        raise TypeError
    
    nbr = 0
    q = deque()

    # NOTE: <BV256 0x0>.args = (0, 256) so can't use len(BVV(0, 256).args) to determine whether leaf node

    if bv.op in ["BVV", "BVS"]:
        q.append(bv)
    else:
        for seed in bv.args:
            q.append(seed)

    while len(q) > 0:

        cur: BV = q.popleft()

        if cur.op in ["BVV", "BVS"]:
            nbr += 1
        else:
            for arg in cur.args:
                q.append(arg)
            
    return nbr

# __obs = None

# def init_observer_onlyone(ins: List[Instruction]) -> Observer:
#     global __obs
    
#     if __obs is None:
#         __obs = Observer(ins)

#     return __obs
        

class SymExecEngine:
    
    def __init__(self, con: Contract) -> None:
        self.branch_queue                       = deque() 
        self.sb                                 = con.sb
        self.states_hash_seen                   = set()
        # add a init state                  
        self.contract                           = con
        self.cp                                 = ConstraintPersistor()
        self.version_control                    = VersionControl(Stage.MID_TERM)
                  
        self.tracer                             = [] # for debug
        self.fuzz                               = Fuzzer(con)
        self.observer                           = Observer(SolidityBinary.instructions)
        # self.observer                           = init_observer_onlyone(SolidityBinary.instructions)

        self.txnseqs                            = self.fuzz.generate_txn_seq()
        self.init_state                         = [deepcopy(State(con)) for _ in range(len(self.txnseqs))]
        # self.add_branch(State(con)) # initial state 
        self.cfg                                = CFG(SolidityBinary.instructions, emu=True)
    
    # TEMP:
    def add_for_fuzz(self, s: State, var: BV, tries: List[Callable]=[]) -> None:
        '''
        fuzz a var and generate corresponding state for this variable
        '''
        logger.critical("add_for_fuzz")

        # TODO: sketchy fuzz strategy
        to_try = set()
        nb_random = random.randint(1, 5) # TODO:
        
        for t in tries:
            if isinstance(t, numbers.Number) and s.solver.solution(var, t):
                to_try.add(t)
            elif t is min:
                to_try.add(s.solver.min(var))
            elif t is max:
                to_try.add(s.solver.max(var))
            elif t is None:
                nb_random += 1
        if nb_random:
            to_try |= set(s.solver.eval(var, nb_random))

        for value in to_try:
            new_state = s.clone()
            new_state.solver.add(var == value)
            self.add_branch(new_state)


    def add_branch(self, s: State) -> None:
        
        s.solver.downsize()
        s.solver.simplify()

        if hash(s) in self.states_hash_seen:
            logger.debug("avoided adding visited state")
            return
        
        if self.cfg.is_dead_basicblock(s.pc):
            # 死区规避
            return
        
        logger.debug(s.solver.constraints)
        
        # NOTE: cache machenism maybe conflict with perf counter, so I add a swicth for ConstraintPersistor
        with ConstraintEvalNotifier(self.observer, s.solver.constraints) as cen:
            if (res := self.cp.find_constraint_cache(s.solver.constraints)) is not None:
                if res == False:
                    return
                
                logger.debug(f"{s.solver.constraints} hit local cache")
            else:
                logger.debug("before satisfiable")
                if not s.solver.satisfiable():
                    logger.debug("after satisfiable 1")
                    self.cp.add_constraint_cache(s.solver.constraints, False)
                    logger.debug(f"state can't satisfiable {s.solver.constraints}")
                    return
        
        logger.debug("after satisfiable 2")
        self.cp.add_constraint_cache(s.solver.constraints, True)
        self.states_hash_seen.add(hash(s))
        self.branch_queue.append((s.depth, s))
    
    def execute(self) -> Observer: # NOTE: timeout
        
        # window thread
        wt = Thread(
            target=StateWindow().show_terminal, 
            args=(self.observer,)
        )
        self.wt = wt
        wt.start()

        from see.state import STATE_COUNTER 
        
        # each txns according a data dependency subgraph function
        for i, txns in enumerate(self.txnseqs):

            self.branch_queue = deque() # clear the queue
            self.add_branch(self.init_state[i])

            for txn in txns: # Transaction execution of a set of functions with data dependencies

                logger.debug(f"execute transaction {txn}")
                self.observer.cur_executing_function_name = txn.fname

                preserved_states = []
                
                if len(self.branch_queue) == 0:
                    self.add_branch(self.init_state[i])

                # NOTE: the state not perserved if it encounter a vuln 
                # NOTE: exhaust the states for one transaction
                try:

                    while len(self.branch_queue) > 0:
                        
                        self.observer.cur_state_count = len(self.branch_queue)
                        self.observer.total_state_count = STATE_COUNTER

                        depth: int; state: State
                        depth, state = self.branch_queue.popleft()

                        state.depth += 1

                        # NOTE: maybe need avoid circular traverse?
                        state_stoped = self.exec_branch(state, txn)

                        # if state end with STOP and pending trasactions remained, save current state as seed state for subsequent transactions 
                        if state_stoped:
                            state.pc = 0 # use selector to jump where transaction specific function, so reset pc to zero
                            preserved_states.append((state.depth, state))

                except Exception:
                    
                    self.epilogue()  # take subthread back otherwise can't see the print log
                    console.print_exception(show_locals=True)
                    import sys
                    sys.exit(1)
                    
                for s in preserved_states:
                    self.branch_queue.append(s)

        # txn sequence fuzz over
        self.epilogue()
        return self.observer

    def epilogue(self) -> None:
        self.observer.notify_statewindow_shutdown = True
        self.cp.dump()
        self.wt.join() 

    def exec_branch(self, state: State, txn: Transaction) -> bool:
        """Execute forward from a state, queuing new states if needed."""
        # logger.debug("Constraints: %s" % state.solver.constraints)

        while True:

            if state.pc > self.sb.end_addr:
                return False
            
            state.exec_addrs.append(state.pc)
            # need to setup a map in pc => inst or 
            # provide a method in sb for next_inst call
            curinst = self.sb.instruction_at(state.pc)
            op      = curinst.opcode
            
            self.tracer.append("{:08x}: {}".format(state.pc, curinst))

            self.observer.hit_at(state.pc)

            # logger.debug("------- NEW STEP -------")
            # logger.debug("PC: %#x, op: %#x(%s)" % (state.pc, op, curinst.name))
            # logger.debug("\nStorage: %s\n" % state.storage)
            # logger.debug("\nStack: %s" % state.stack)


            bps = []
            for bp in bps:
                if state.pc == bp:
                    self.observer.notify_statewindow_shutdown = True
                    import pdb; pdb.set_trace()

            # Trivial operations first
            if False:
                pass
            elif op == 254:  # INVALID opcode
                # REF: https://eips.ethereum.org/EIPS/eip-141
                #  Backwards Compatibility: This instruction was never used and therefore has no effect on past contracts.
                raise NotImplementedError("INVALID")

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
                # We need to use claripy.LShR instead of a division if possible,
                # because the solver is bad dealing with divisions, better
                # with shifts. And we need shifts to handle the solidity ABI
                # for function selection.
                [s0, s1] = state.stack_pop(2) # s0 / s1
                
                if s1.concrete:
                    divisor = s1.concrete_value

                    if divisor == 0:
                        raise RuntimeError("divide by zero")

                    elif divisor == 1:
                        state.stack_push(s0)

                    elif divisor % 2 == 0:
                        exp = int(math.log(divisor, 2))
                        state.stack_push(s0.LShR(exp))

                    else:
                        raise RuntimeError("unhandled divisor")

                else:
                    # if s0.symbolic and s1.symbolic:
                        # self.observer.notify_statewindow_shutdown = True
                        # import pdb; pdb.set_trace()
                    
                    state.stack_push(s0 // s1)

                # try:
                #     s1 = state.find_one_solution(s1)  # pylint:disable=invalid-name 获得一个具体值
                # except SymbolicMultiSolutions:

                #     assert s1.symbolic
                #     # 有多个解 s1 是symbolic的
                #     state.solver.add(s1 != 0)
                #     state.stack_push(s0 // s1)
                #     # state.stack_push(claripy.If(s1 == 0, BVV0, s0 / s1))# 这里是不是可以抛出一个div zero 异常
                # else:
                #     if s1 == 0:
                #         raise NotImplementedError("divide by zero")
                #     elif s1 == 1:
                #         state.stack_push(s0)
                #     elif s1 % 2 == 0:
                #         exp = int(math.log(s1, 2))
                #         state.stack_push(s0.LShR(exp))
                #     else:
                #         raise NotImplementedError("奇数除法")
                        # state.stack_push(s0 // s1)
            elif op == const.opcode.SDIV:
                raise NotImplementedError
                [s0, s1] = state.stack_pop(2)
                
                # try:
                #     s1 = state.find_one_solution(s1)
                # except MultipleSolutionsError:
                #     state.stack_push(claripy.If(s1 == 0, BVV0, s0.SDiv(s1))) 
                # else:
                #     state.stack_push(BVV0 if s1 == 0 else s0.SDiv(s1))

            elif op == const.opcode.MOD:
                # s0 % s1
                [s0, s1] = state.stack_pop(2)
                if s1.concrete:
                    # 实验性: 如果s0的约束比较大 这里考虑化简
                    if calculate_bv_args_leafnode(s0) > 3:
                        self.add_for_fuzz(state, s0)

                    mod = s1.concrete_value
                    state.stack_push(
                        s0 % mod
                    )
                else:
                    raise NotImplementedError
                
            elif op == const.opcode.SMOD:
                raise NotImplementedError
                [s0, s1] = state.stack_pop(2)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s1 == 0, BVV0, s0.SMod(s1)))
                else:
                    state.stack_push(BVV0 if s1 == 0 else s0.SMod(s1))

            elif op == const.opcode.ADDMOD: # (a + b) % N
                raise NotImplementedError
                [s0, s1, s2] = state.stack_pop(3)
                try:
                    s1 = state.find_one_solution(s1)
                except MultipleSolutionsError:
                    state.stack_push(claripy.If(s2 == 0, BVV0, (s0 + s1) % s2))
                else:
                    state.stack_push(BVV0 if s2 == 0 else (s0 + s1) % s2)
                    
            elif op == const.opcode.MULMOD:
                raise NotImplementedError
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
                # TODO: refine here
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
                # needtodo: Use Claripy's SignExt that should do exactly that.
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
                # bitwise AND

                [s0, s1] = state.stack_pop(2)
                # TEMP: workaround for claripy bug 
                # REF: https://github.com/angr/claripy/issues/383

                # optimize condition If(c1, 1, 0) and If(c2, 1, 0)
                # bitwidth OR operation is time-consuming
                if s0.op == "If" and s1.op == "If":
                    if s0.args[1].concrete_value == 1 and s0.args[2].concrete_value == 0 and \
                       s1.args[1].concrete_value == 1 and s1.args[2].concrete_value == 0:
                                            
                        state.stack_push(
                            claripy.If(
                                claripy.And((s0 != BVV0), (s1 != BVV0)), 
                                BVV1, 
                                BVV0
                            )
                        )
                    
                else:
                    state.stack_push(s0 & s1)

            elif op == const.opcode.OR:
                [s0, s1] = state.stack_pop(2)
                state.stack_push(s0 | s1)

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
                state.stack_push(BVVify(state.pc))

            elif op == const.opcode.GAS:
                # gasRemaining
                # NOTE: imprecise GAS
                state.stack_push(
                    claripy.BVV(txn.gas, 256)
                )

            elif op == const.opcode.ADDRESS:
                raise NotImplementedError
                state.stack_push(state.env.address)

            elif op == const.opcode.CHAINID:
                raise NotImplementedError
                state.stack_push(state.env.chainid)

            elif op == const.opcode.SELFBALANCE:
                state.stack_push(
                    state.contract.balance
                )

            elif op == const.opcode.BALANCE:
                # addr.balance
                raise NotImplementedError

            elif op == const.opcode.ORIGIN:
                raise NotImplementedError
                state.stack_push(state.env.origin)

            elif op == const.opcode.CALLER:
                raise NotImplementedError
                state.stack_push(state.env.caller)

            elif op == const.opcode.CALLVALUE:
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
                addr = state.stack_pop()

                if addr.symbolic:
                    self.observer.add_a_vuln(
                        VulnTypes.ARBITRARY_JUMP,
                        state
                    )
                    return False # TODO:
                else:
                    addr = addr.concrete_value

                    if not self.sb.check_pc_jmp_valid(addr):
                        raise RuntimeError("Invalid jump (0x%x) at pc 0x%x" % (addr, state.pc))

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
                    # TODO: 这部分可以记录成优化点 放到每一个条件判断的地方
                    if cond.op == "__or__":
                        # NOTE: 在solidity中没有bitor和逻辑or的区别 但是这两个的运算在z3中就差很多了
                        # optmize here for time-comsuming up to 22s
                        a0, a1 = cond.args[0], cond.args[1]

                        if a0.op == "If" and a1.op == "If":
                            # NOTE: 不需要两个If应该也能直接优化
                            cond = claripy.Or(a0, a1)
                        else:
                            cond = claripy.Or(a0 != BVV0, a1 != BVV0)

                    logger.debug(f"fork at {hex(state.pc)}")
                    
                    state_false = state.clone()
                    state_false.solver.add(cond == BVV0) # can't jump to dest if condition is zero
                    state_false.pc += 1
                    self.add_branch(state_false)
                    
                    state.solver.add(cond != BVV0)
                    state.pc = addr.concrete_value

                    if not self.sb.check_pc_jmp_valid(state.pc):
                        raise RuntimeError("Invalid jump (0x%x)" % (state.pc))

                    self.add_branch(state)

                    return False
                
                else: # addr and cond neither symbolic
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
                state.stack_dup(depth)

            elif const.opcode.SWAP1 <= op <= const.opcode.SWAP16:
                depth = op - const.opcode.SWAP1 + 1
                state.stack_swap(depth)

            elif const.opcode.LOG0 <= op <= const.opcode.LOG4:
                '''
                log a function signature and parameters in chain permanently
                '''
                raise NotImplementedError
                # NOTE: maybe this not need to simulate

                # LOG0(memory[ost:ost+len-1])
                # LOG1(memory[ost:ost+len-1], topic0, topic1)
                depth = op - const.opcode.LOG0
                dstost, mlen = (state.stack_pop(), state.stack_pop())
                topics = [state.stack_pop() for _ in range(depth)]

            elif op == const.opcode.SHA3:
                raise NotImplementedError

                s0 = state.stack_pop()
                s1 = state.stack_pop()

                start, length = fos(s0), fos(s1)
                memory = state.memory.read(start, length)
                state.stack_push(Sha3(memory))

            elif op == const.opcode.STOP:
                # halt execution
                return True

            elif op == const.opcode.RETURN:
                # return mem[ost:ost+len-1]
                raise NotImplementedError
                return False

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
                    
                else:
                    raise NotImplementedError

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

                if dstost.symbolic or ost.symbolic or size.symbolic:
                    raise NotImplementedError
                
                dstost, ost, size = dstost.concrete_value, ost.concrete_value, size.concrete_value
                
                assert size == 32 # TODO: check 也许能把32改成循环
                assert (ost - 4) % 32 == 0, "ost must be 4 + 32n cuz 4 is signature size"

                msg_idx = (ost - 4) // 32
                msg = txn.msg[msg_idx]

                assert msg.size() == 256

                state.memory.write(
                    dstost, size, msg
                )

            elif op == const.opcode.CODESIZE:
                state.stack_push(
                    claripy.BVV(len(self.sb.instructions), 256)
                )

            elif op == const.opcode.EXTCODESIZE:
                raise NotImplementedError


            elif op == const.opcode.EXTCODECOPY:
                # addr, dstOst, ost, len
                # mem[dstOst:dstOst+len-1] := addr.code[ost:ost+len-1]
                raise NotImplementedError

            elif op == const.opcode.CODECOPY:
                raise NotImplementedError
                # dstOst, ost, len
                # mem[dstOst:dstOst+len-1] := this.code[ost:ost+len-1]

            elif op == const.opcode.MLOAD:
                addr = state.stack_pop()

                if addr.symbolic:
                    raise NotImplementedError
                    
                state.stack_push(
                    state.memory.read(
                        addr.concrete_value, 
                        32
                    )
                )

            elif op == const.opcode.MSTORE:
                addr, value = state.stack_pop(), state.stack_pop()

                if addr.symbolic:
                    raise NotImplementedError
                    
                logger.debug(f"MSTORE : mem[{addr}:{addr}+32] = {value}")
                state.memory.write(addr.concrete_value, 32, value)
                
            elif op == const.opcode.MSTORE8:
                raise NotImplementedError
                index, value = state.find_one_solution(state.stack_pop()), state.stack_pop()
                state.memory.write(index, 1, value[7:0])

            elif op == const.opcode.MSIZE:
                raise NotImplementedError
                state.stack_push(bvv(state.memory.size()))

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
                #     raise Exception("impossible") 
                #     assert key not in state.storage_written 
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
                    if state.solver.satisfiable(extra_constraints=[key == ARBITRARY_SLOT_WRITE_IDX]):
                        self.observer.add_a_vuln(
                            VulnTypes.ARBITRARY_SLOT_WRITE,
                            state
                        )

                        return False
                    else:
                        raise NotImplementedError("TODO:不满足攻击条件 随便fuzz一下就行")

            elif op == const.opcode.CALL:
                # NOTE: simple emulate
                [gas, addr, val, argOst, argLen, retOst, retLen] = state.stack.pop(7)
                state.stack_push(BVV1) # success
                
                

            elif op == const.opcode.DELEGATECALL:
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
                # NOTE: data能够符号化也可以进行攻击 所以这里有两种检测模式 但是我暂时只实现其中一种
                if addr.symbolic:
                    if state.solver.satisfiable(extra_constraints=[addr == ATTACK_ACCOUNT_ADDRESS]):
                        self.observer.add_a_vuln(
                            VulnTypes.DELEGATECALL,
                            state
                        )

                        state.pc += 1
                        return False
                    else:
                        raise RuntimeError("symbolic but not satisfiable?")
                
                # NOTE: assume delegatecall must success but not write the memory
                state.stack_push(BVV1)

                state.calls.append(
                    (gas, addr, argost, arglen, retost, retlen)
                )

                state.pc += 1

            elif op == const.opcode.RETURNDATASIZE:# TODO:
                # REF: https://eips.ethereum.org/EIPS/eip-211
                # 就是一次call后返回的data的size
                # raise NotImplementedError
                state.stack_push(claripy.BVS("RETURNDATASIZE", 256))# TODO: 也许需要与CALLDATA保持一致？

            elif op == const.opcode.RETURNDATACOPY:
                raise NotImplementedError

            elif op == const.opcode.SELFDESTRUCT:

                addr = state.stack_pop()
                
                if addr.symbolic:
                    constraint = [addr == ATTACK_ACCOUNT_ADDRESS]

                    if state.solver.satisfiable(extra_constraints=constraint):
                        self.observer.add_a_vuln(
                            VulnTypes.SELFDESTRUCT, state
                        )
                        logger.critical("selfdestruct detect successfully")

                    else:
                        # can't meet attack condition
                        # raise NotImplementedError(f"unevaluable constraints {state.solver.constraints} + {constraint}")
                        return False
                        
                return False

            elif op == const.opcode.REVERT:
                return False

            else:
                raise RuntimeError(state, "Unknown opcode %#x" % op)

            state.pc += 1    