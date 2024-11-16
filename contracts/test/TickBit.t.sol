// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {Test, console} from "forge-std/Test.sol";
import {TickBit,TickUSD} from "../src/tickbit/TickBit.sol";
import {ERC20} from "openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {SXGVerifier} from "../src/tickbit/Verifier.sol";

// Mock ERC20 token for testing
contract MockToken is ERC20 {
    constructor() ERC20("Mock", "MCK") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }
}

contract TickBitTest is Test {
    TickBit public tickbit;
    MockToken public token;
    SXGVerifier public verifier;

    address user1 = address(0x1);
    address user2 = address(0x2);
    uint256 constant TICK_SIZE = 10 ** 18;

    // Test data from SXGTest
    bytes32 constant TEST_PX =
        0x96c5e1904a90ef4c3fa99fba0767f9af8786307b2ccb069ad7f32008b3583bc7;
    bytes32 constant TEST_PY =
        0xe9f9c412e20ea07a5733dc6199ad16d723ee5392e2cfc33bc0279ddcde8e4118;

    bytes32 constant vkey =
        0x00c1c5f7a9d301b8250bd2f7593e0fcb9311a015748e7506ecc90ed30ca68ee0;

    bytes constant TEST_PROOF =
        hex"6a2906ac210350194d369c8203fcb242555b886e2fbc75bac662d6e9696b748e365e7a1a15612c918d26baf3c09dabc2d4a3f94d6413bc4504d705883fd0e68ff70a1aac1d83b80c85e0e04a2df9ef537c653adb58b3f2671ad21b4fb9999662a510e9621cf0d62ea4983c16645e96bb7c6785225c72201f08b95e1a0a74fd968198f05217bfcbd81b8d226b2a5dda266d5d6a360e5704349373a97971a464c22c482d8e037ed3027b8c21bb3a40728bcf670cb0680bc31a5ada276fcb4078f509ea74051393b38bfbe882dc00ef7840f8de7421c826fdf1149cbb02c6ad249b017496c8268b96076a969f58eabdf883be8fcbccc16733e058a1f612a34c41e5a2a67b3a";

    bytes constant TEST_BLOCK_HEADER =
        hex"00200e20913178ab42d33dfc25a3a5ebe3f78ac211bd31362d660100000000000000000033c5367fb7c213fa2ffae2ad90cff5ecbb43ef15a288fbaa36876f2e0fac231ad1cf2d67e4c402175af60cee";

    function setUp() public {
        // Deploy contracts
        token = new MockToken();
        verifier = new SXGVerifier(address(1), bytes32(0));
        tickbit = new TickBit(
            address(token),
            address(verifier),
            TEST_PX,
            TEST_PY,
            TICK_SIZE
        );

        // fund eth
        vm.deal(user1, 100 ether);
        vm.deal(user2, 100 ether);
        token.transfer(user1, 1000 * 10 ** 18);
        token.transfer(user2, 1000 * 10 ** 18);

        // Approve tokens
        vm.prank(user1);
        token.approve(address(tickbit), type(uint256).max);
        vm.prank(user2);
        token.approve(address(tickbit), type(uint256).max);
    }

    function testInitialState() public {
        assertEq(address(tickbit.token()), address(token));
        assertEq(address(tickbit.verifier()), address(verifier));
        assertEq(tickbit.Px(), TEST_PX);
        assertEq(tickbit.Py(), TEST_PY);
        assertEq(tickbit.tickSize(), TICK_SIZE);
    }

    function testBetPlacement() public {
        uint256[] memory timestamps = new uint256[](2);
        timestamps[0] = block.timestamp + 1 hours;
        timestamps[1] = block.timestamp + 2 hours;
        uint256 blockNumber = 869404;

        vm.prank(user1);
        tickbit.bet(timestamps, blockNumber);

        // Verify bet storage
        (uint256 biddedAt, address bidder) = getBetInfo(
            blockNumber,
            timestamps[0],
            0
        );
        assertEq(bidder, user1);
        assertEq(biddedAt, block.timestamp);

        // Verify pool amount
        (uint256 acruedAmount, ) = tickbit.pools(blockNumber);
        assertEq(acruedAmount, 2 * TICK_SIZE);
    }

    function testCannotBetPastTimestamp() public {
        uint256[] memory timestamps = new uint256[](1);
        timestamps[0] = block.timestamp;
        uint256 blockNumber = 869404;

        vm.prank(user1);
        vm.expectRevert("timestamp must be in the future");
        tickbit.bet(timestamps, blockNumber);
    }

    function testMultipleUsersBetting() public {
        uint256[] memory timestamps1 = new uint256[](1);
        timestamps1[0] = block.timestamp + 1 hours;
        uint256[] memory timestamps2 = new uint256[](1);
        timestamps2[0] = timestamps1[0]; // Same prediction
        uint256 blockNumber = 869404;

        vm.prank(user1);
        tickbit.bet(timestamps1, blockNumber);

        vm.prank(user2);
        tickbit.bet(timestamps2, blockNumber);

        // Verify both bets are stored
        (uint256 biddedAt1, address bidder1) = getBetInfo(
            blockNumber,
            timestamps1[0],
            0
        );
        (uint256 biddedAt2, address bidder2) = getBetInfo(
            blockNumber,
            timestamps1[0],
            1
        );

        assertEq(bidder1, user1);
        assertEq(bidder2, user2);

        // Verify pool amount
        (uint256 acruedAmount, ) = tickbit.pools(blockNumber);
        assertEq(acruedAmount, 2 * TICK_SIZE);
    }

    function testSettlement() public {
        // Setup bets
        uint256 blockNumber = 869404;
        TickBit.BlockHeader memory header = tickbit.parseBlockHeader(
            TEST_BLOCK_HEADER
        );

        uint256 futureTime = uint256(
            uint32(
                bytes4(
                    tickbit.convertToBigEndian(
                        abi.encodePacked(header.timestamp)
                    )
                )
            )
        );

        uint256[] memory timestamps1 = new uint256[](1);
        timestamps1[0] = futureTime + 1 seconds;

        uint256[] memory timestamps2 = new uint256[](1);
        timestamps2[0] = futureTime + 5 seconds;

        vm.prank(user1);
        tickbit.bet(timestamps1, blockNumber);

        vm.prank(user2);
        tickbit.bet(timestamps2, blockNumber);

        // Mock verifier response
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(SXGVerifier.verifySXGProof.selector),
            abi.encode(uint256(1))
        );

        uint256 user1Balance = token.balanceOf(user1);

        // Warp to after predicted time
        vm.warp(futureTime + 3 minutes);

        // Verify and settle
        tickbit.verifyAndSettleBlock(
            blockNumber,
            TEST_BLOCK_HEADER,
            TEST_PROOF
        );

        (, , , , bytes4 timestamp, ) = tickbit.verifiedBlocks(blockNumber);
        // Check if block is verified
        assertNotEq(timestamp, bytes4(0));

        // Check if pool is settled
        (, uint256 settledAt) = tickbit.pools(blockNumber);
        assertNotEq(settledAt, 0);

        // balance of user1 should be updated
        uint256 user1NewBalance = token.balanceOf(user1);

        assertEq(user1NewBalance, user1Balance + 2 * TICK_SIZE);
    }

    function testCannotSettleTwice() public {
        uint256 blockNumber = 869404;
        uint256[] memory timestamps = new uint256[](1);
        timestamps[0] = block.timestamp + 1 hours;

        vm.prank(user1);
        tickbit.bet(timestamps, blockNumber);

        // Mock verifier response
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(SXGVerifier.verifySXGProof.selector),
            abi.encode(uint256(1))
        );

        tickbit.verifyAndSettleBlock(
            blockNumber,
            TEST_BLOCK_HEADER,
            TEST_PROOF
        );

        vm.expectRevert("block bets already settled");
        tickbit.verifyAndSettleBlock(
            blockNumber,
            TEST_BLOCK_HEADER,
            TEST_PROOF
        );
    }

    function testInvalidProof() public {
        uint256 blockNumber = 869404;
        uint256[] memory timestamps = new uint256[](1);
        timestamps[0] = block.timestamp + 1 hours;

        vm.prank(user1);
        tickbit.bet(timestamps, blockNumber);

        // Mock verifier to return 0 (invalid proof)
        vm.mockCall(
            address(verifier),
            abi.encodeWithSelector(SXGVerifier.verifySXGProof.selector),
            abi.encode(uint256(0))
        );

        vm.expectRevert("blockHeader must be verified");
        tickbit.verifyAndSettleBlock(
            blockNumber,
            TEST_BLOCK_HEADER,
            TEST_PROOF
        );
    }

    // Helper function to get bet info
    function getBetInfo(
        uint256 blockNumber,
        uint256 timestamp,
        uint256 index
    ) internal view returns (uint256 biddedAt, address bidder) {
        (biddedAt, bidder) = tickbit.blockBets(blockNumber, timestamp, index);
        return (biddedAt, bidder);
    }

    function parseBlockHeader(
        bytes calldata blockHeader
    ) public pure returns (TickBit.BlockHeader memory parsedHeader) {
        parsedHeader.version = bytes4(blockHeader[:4]);
        parsedHeader.previousBlockHash = bytes32(blockHeader[4:36]);
        parsedHeader.merkleRootHash = bytes32(blockHeader[36:68]);
        parsedHeader.timestamp = bytes4(blockHeader[68:72]);
        parsedHeader.nBits = bytes4(blockHeader[72:76]);
        parsedHeader.nonce = bytes4(blockHeader[76:]);
    }
}
