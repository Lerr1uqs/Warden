// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract ArbiStorageWrite {
    
    uint256 array = 0xfffffffffff;
    address owner;

    constructor() {
        owner = msg.sender;
    }
    uint256 _asw_prev1;
    uint256 _asw_prev2;

    function asw_prev1(uint256 x) public {
        _asw_prev1 = x ^ 0x0d00;
    }
    
    function asw_prev2(uint256 x) public {
        _asw_prev2 = x ^ 0x0721;
    }
    
    function arbi_storage_write(uint256 idx, uint256 value) public {
        require( _asw_prev1 + _asw_prev2 == 0x2887);
        assembly {
            let sl := array.slot
            sstore(add(sl, idx), value)
        }
    }

}