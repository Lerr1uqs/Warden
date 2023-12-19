// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract SelfDestruct {
    uint256 a;
    constructor() payable  {

    }
    function vuln(address addr) public {
        selfdestruct(payable(addr));
    }
    function middle_vuln(address addr, uint256 v) public {
        a = v * 2 + 1;
        uint256 c = v + 4;
        if(c % 2 == 0) {
            if (a == 0x0d000721){
                selfdestruct(payable(addr));
            }
        }
    }
}