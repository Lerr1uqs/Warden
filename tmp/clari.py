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
solver.add(a > 0)
solver.add(b > 0xff)
solver.add(BVV0 < BVV1)

print(solver.satisfiable())

print(hash(tuple(solver.constraints)) & 0xffffffffffffffff)
# solver.constraints[2] = True
# print(solver.satisfiable())