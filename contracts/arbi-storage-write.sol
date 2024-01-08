// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract ArbiStorageWrite {
    
    uint256 array = 0xfffffffffff;
    address owner;

    constructor() {
        owner = msg.sender;
    }
    
    function a(uint256 idx, uint256 value) public {
        assembly {
            let sl := array.slot
            sstore(add(sl, idx), value)
        }
    }

}