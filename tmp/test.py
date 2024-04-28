from claripy import *

a = BVS("uint256-a", 256)
b = BVS("uint256-b", 256)
c = BVS("uint256-c", 256)
d = BVS("uint256-d", 256)

f = BVV(0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff, 256)   

# constraints = [
#     <Bool msg.value_35_256 == 0x0>, 
#     <Bool msg.value_33_256 == 0x0>, 
#     <Bool msg.value_37_256 == 0x0>, 
#     <Bool msg.value_39_256 == 0x0>, 
#     <Bool msg.value_41_256 == 0x0>, 
#     <Bool !(msg.value_43_256 == 0x0)>, 
#     <Bool input-uint256_34_256 == 0x0 || 0x2 <= f / input-uint256_34_256>]
'''
[
    <Bool msg.value_35_256 == 0x0>, 
    <Bool msg.value_33_256 == 0x0>, 
    <Bool msg.value_37_256 == 0x0>, 
    <Bool msg.value_39_256 == 0x0>, 
    <Bool msg.value_41_256 == 0x0>, 
    <Bool msg.value_43_256 == 0x0>, 
    <Bool msg.value_45_256 == 0x0>, 
    <Bool input-addr_48_256 == (0x0 .. input-addr_48_256[159:0])>, 
    <Bool input-uint256_50_256[31:24] == 13>, 
    <Bool !(0x2 <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / input-uint256_49_256)>, 
    <Bool input-uint256_34_256 == 0x0 || 0x2 <= 0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff / input-uint256_34_256>, 
    <Bool !((0 .. input-uint256_44_256[11:10] .. 0 .. input-uint256_44_256[8:8] .. 0) * (0 .. input-uint256_46_256[10:8] .. 0 .. input-uint256_46_256[5:5] .. 0 .. input-uint256_46_256[0:0]) <= 0x1bf52) || !((0x0 .. input-uint256_44_256[11:10] .. 0 .. input-uint256_44_256[8:8] .. 0) * (0x0 .. input-uint256_46_256[10:8] .. 0 .. input-uint256_46_256[5:5] .. 0 .. input-uint256_46_256[0:0])[255:17] == 0x0)>]

'''

solver = Solver()
# for c in constraints:
solver.add(Or(a == 0, 0x2 <= f / b))
print(solver.constraints)

# print(solver.satisfiable())

solver.downsize()
solver.simplify()
print(solver.satisfiable())