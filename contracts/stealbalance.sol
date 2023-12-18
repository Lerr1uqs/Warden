// SPDX-License-Identifier: GPL-3.0
pragma solidity >=0.8.2 <0.9.0;
// pragma solidity ^0.4.25;

interface Token {
    function transferFrom(address sender, address recipient, uint256 amount) external returns (bool);
    function allowance(address owner, address spender) external view returns (uint256);
}

contract TokenSale {
    uint256 start = block.timestamp;
    uint256 end = block.timestamp + 30 days;
    address wallet = address(0x0d000721); // TODO:
    Token token = Token(address(0x0d000721));

    address owner;
    bool sold;

    function Tokensale() public {
        owner = msg.sender;
    }

    function buy() public payable {
        
        require(block.timestamp < end);
        require(msg.value == 42 ether + (block.timestamp - start) / 60 / 60 / 24 * 1 ether);
        require(token.transferFrom(address(this), msg.sender, token.allowance(wallet, address(this))));
        
        sold = true;
    }

    function withdraw() public {
        
        require(msg.sender == owner);
        require(block.timestamp >= end);
        require(sold);
        
        payable(owner).transfer(address(this).balance);
    }
}
