from claripy import *
'''
[
    <Bool input-addr_1_256 == (0x0 .. input-addr_1_256[159:0])>, 
    <Bool !(input-uint256_2_256 == 0x0)>, 
    <Bool (if 0x2 * input-uint256_2_256 / input-uint256_2_256 == 0x2 then 0x1 else 0x0) == 0x0>
]

[
    <Bool (0x0 .. uint256-a_0_256[159:0]) == uint256-a_0_256>, 
    <Bool 0x2 * uint256-b_1_256 / uint256-b_1_256 == 0x2>
]
'''
a = BVS("uint256-a", 256)
b = BVS("uint256-b", 256)

BVV0 = BVV(0, 256)
BVV1 = BVV(1, 256)

solver = Solver()
# solver.add(Not(a == 0))
solver.add((a & 0xffffffffffffffffffffffffffffffffffffffff) == a)
solver.add(If(2 * b / b == 2, BVV1, BVV0) == BVV1)
solver.add(Not(b == BVV0))
solver.downsize()
solver.simplify()
print(solver.constraints)
print(solver.satisfiable())