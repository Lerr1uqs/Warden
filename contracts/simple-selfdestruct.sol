// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;

contract SelfDestruct {
    constructor() payable  {

    }
    function vuln(address addr) public {
        selfdestruct(payable(addr));
    }
}