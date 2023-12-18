// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.8.2 <0.9.0;
// pragma solidity ^0.4.25;

contract DelegateCall {
    // address owner;

    constructor() payable {
        // require(msg.value > 0); TODO:
    }

    function vuln(address addr, bytes calldata data) public {
        addr.delegatecall(data);
        //address(Attack).delegatecall(bytes4(keccak256("Attack_code()")));  
        //代码为被攻击者的代码，其使用了delegatecall函数。
    }
}
