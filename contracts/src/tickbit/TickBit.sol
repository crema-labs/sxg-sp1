// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

import {ERC20} from "../../lib/openzeppelin-contracts/contracts/token/ERC20/ERC20.sol";
import {SXGVerifier} from "./Verifier.sol";
import "forge-std/Console.sol";

contract TickBit {
    struct Bet {
        uint96 bettedAt;
        address bettor;
    }

    struct BlockHeader {
        bytes32 merkleRootHash;
        bytes4 nBits;
        bytes4 nonce;
        bytes32 previousBlockHash;
        bytes4 timestamp;
        bytes4 version;
    }

    struct Pool {
        uint256 acruedAmount;
        uint256 settledAt;
    }

    ERC20 public token;
    SXGVerifier public verifier;
    bytes32 public Px;
    bytes32 public Py;
    uint256 public tickSize;
    uint256 public latestBlock;

    mapping(uint256 => Pool) public pools;
    mapping(uint256 => mapping(uint256 => Bet[])) public blockBets;
    mapping(uint256 => uint256[]) public blockTimestamps;
    mapping(uint256 => BlockHeader) public verifiedBlocks;

    event BetPlaced(
        address indexed addr,
        uint256 indexed blockNumber,
        uint256[] timestamps,
        uint256 amount,
        uint256 placedAt
    );

    event BlockSettled(
        uint256 indexed blockNumber,
        uint256 indexed winningTimestamp,
        address[] winners,
        uint256 amount
    );

    constructor(
        address _token,
        address _verifier,
        bytes32 _Px,
        bytes32 _Py,
        uint256 _tickSize
    ) {
        token = ERC20(_token);
        verifier = SXGVerifier(_verifier);
        Px = _Px;
        Py = _Py;
        tickSize = _tickSize;
    }

    function bet(uint256[] calldata timestamps, uint256 blockNumber) public {
        require(
            timestamps.length > 0,
            "timestamps must contain at least one element"
        );
        require(
            blockNumber > latestBlock,
            "blockNumber must be greater than latestBlock"
        );

        uint256 amount = timestamps.length * tickSize;

        ERC20(token).transferFrom(msg.sender, address(this), amount);

        Pool storage pool = pools[blockNumber];
        pool.acruedAmount += amount;

        for (uint256 i = 0; i < timestamps.length; i++) {
            require(
                timestamps[i] > block.timestamp,
                "timestamp must be in the future"
            );

            if (blockBets[blockNumber][timestamps[i]].length == 0) {
                blockTimestamps[blockNumber].push(timestamps[i]);
            }

            blockBets[blockNumber][timestamps[i]].push(
                Bet(uint96(block.timestamp), msg.sender)
            );
        }

        emit BetPlaced(
            msg.sender,
            blockNumber,
            timestamps,
            amount,
            block.timestamp
        );
    }

    function verifyWithoutSettlement(
        uint256 blockNumber,
        bytes calldata blockHeader,
        bytes calldata proof
    ) internal returns (BlockHeader memory header) {
        require(
            verifiedBlocks[blockNumber].timestamp == 0,
            "block already verified"
        );

        header = parseBlockHeader(blockHeader);

        header = verifyBlock(blockNumber, blockHeader, proof);
        verifiedBlocks[blockNumber] = header;

        if (latestBlock < blockNumber) {
            latestBlock = blockNumber;
        }
    }

    function verifyAndSettleBlock(
        uint256 blockNumber,
        bytes calldata blockHeader,
        bytes calldata proof
    ) public {
        if (
            blockTimestamps[blockNumber].length == 0 &&
            pools[blockNumber].acruedAmount == 0
        ) {
            verifyWithoutSettlement(blockNumber, blockHeader, proof);
            return;
        }
        require(
            verifiedBlocks[blockNumber].timestamp == 0,
            "block bets already settled"
        );

        require(
            blockTimestamps[blockNumber].length > 0,
            "bets must be placed on this block"
        );

        Pool storage pool = pools[blockNumber];
        require(pool.acruedAmount > 0, "no bets found in the pool");

        require(pool.settledAt == 0, "block bets already settled");

        BlockHeader memory header = verifyWithoutSettlement(
            blockNumber,
            blockHeader,
            proof
        );

        settleBlock(
            pool.acruedAmount,
            blockNumber,
            uint256(
                uint32(
                    bytes4(
                        convertToBigEndian(abi.encodePacked(header.timestamp))
                    )
                )
            )
        );
    }

    function verifyBlock(
        uint256 blockNumber,
        bytes calldata blockHeader,
        bytes calldata proof
    ) public view returns (BlockHeader memory header) {
        header = parseBlockHeader(blockHeader);
        bytes32 blockHash = convertToBytes32(
            convertToBigEndian(abi.encodePacked(doubleHash(blockHeader)))
        );

        require(
            verifier.verifySXGProof(
                abi.encodePacked(uint256(1), blockNumber, blockHash, Px, Py),
                proof
            ) == uint256(1),
            "blockHeader must be verified"
        );
    }

    function settleBlock(
        uint256 poolValue,
        uint256 blockNumber,
        uint256 verifiedTimestamp
    ) internal {
        uint256[] storage timestamps = blockTimestamps[blockNumber];
        require(timestamps.length > 0, "bets must be placed on this block");

        uint256 minDiff = type(uint256).max;

        for (uint256 i = 0; i < timestamps.length; i++) {
            uint256 diff = ModDiff(timestamps[i], verifiedTimestamp);
            if (diff < minDiff) {
                minDiff = diff;
            }
        }

        (uint256 lowerIdx, uint256 higherIdx) = calculateWinners(
            blockNumber,
            verifiedTimestamp,
            minDiff
        );

        uint256 amount = poolValue / (higherIdx + lowerIdx);

        address[] memory winners = new address[](higherIdx + lowerIdx);

        if (lowerIdx > 0) {
            distributeRewards(
                blockNumber,
                verifiedTimestamp - minDiff,
                lowerIdx,
                amount
            );
        }

        if (higherIdx > 0) {
            distributeRewards(
                blockNumber,
                verifiedTimestamp + minDiff,
                higherIdx,
                amount
            );
        }
    }

    function distributeRewards(
        uint256 blockNumber,
        uint256 timestamp,
        uint256 winnerIdx,
        uint256 amount
    ) internal returns (address[] memory winners) {
        winners = new address[](winnerIdx);
        Bet[] storage bets = blockBets[blockNumber][timestamp];
        for (uint256 i = 0; i < winnerIdx; i++) {
            winners[i] = bets[i].bettor;
            ERC20(token).transfer(bets[i].bettor, amount);
        }

        emit BlockSettled(blockNumber, timestamp, winners, amount);
    }

    function calculateWinners(
        uint256 blockNumber,
        uint256 verifiedTimestamp,
        uint256 minDiff
    ) internal view returns (uint256, uint256) {
        if (minDiff == 0) {
            return (0, getWinnerIdx(blockNumber, verifiedTimestamp));
        }

        uint256 lowerIdx = 0;

        if (verifiedTimestamp > minDiff) {
            lowerIdx = getWinnerIdx(blockNumber, verifiedTimestamp - minDiff);
        }

        uint256 higherIdx = getWinnerIdx(
            blockNumber,
            verifiedTimestamp + minDiff
        );

        return (lowerIdx, higherIdx);
    }

    function getWinnerIdx(
        uint256 blockNumber,
        uint256 timestamp
    ) internal view returns (uint256) {
        Bet[] storage bets = blockBets[blockNumber][timestamp];
        if (bets.length == 0) {
            return 0;
        }

        uint256 winnerIdx = 0;
        for (uint256 i = bets.length; i > 0; i--) {
            if (bets[i - 1].bettedAt < timestamp) {
                winnerIdx = i;
                break;
            }
        }
        return winnerIdx;
    }

    function ModDiff(uint256 a, uint256 b) internal pure returns (uint256) {
        if (a > b) {
            return a - b;
        }
        return b - a;
    }

    function convertToBytes32(bytes memory data) public pure returns (bytes32) {
        require(data.length == 32, "data must be 32 bytes");
        bytes32 result;
        assembly {
            result := mload(add(data, 32))
        }
        return result;
    }

    function convertToBigEndian(
        bytes memory bytesLE
    ) public pure returns (bytes memory) {
        uint256 length = bytesLE.length;
        bytes memory bytesBE = new bytes(length);
        for (uint256 i = 0; i < length; i++) {
            bytesBE[length - i - 1] = bytesLE[i];
        }
        return bytesBE;
    }

    function parseBlockHeader(
        bytes calldata blockHeader
    ) public pure returns (BlockHeader memory parsedHeader) {
        parsedHeader.version = bytes4(blockHeader[:4]);
        parsedHeader.previousBlockHash = bytes32(blockHeader[4:36]);
        parsedHeader.merkleRootHash = bytes32(blockHeader[36:68]);
        parsedHeader.timestamp = bytes4(blockHeader[68:72]);
        parsedHeader.nBits = bytes4(blockHeader[72:76]);
        parsedHeader.nonce = bytes4(blockHeader[76:]);
    }

    function doubleHash(bytes memory data) public pure returns (bytes32) {
        return sha256(abi.encodePacked(sha256(abi.encodePacked(data))));
    }
}

contract TickUSD is ERC20 {
    constructor() ERC20("TickUSD", "TSD") {
        _mint(msg.sender, 1000000 * 10 ** 18);
    }

    function mint(address to, uint256 amount) public {
        _mint(to, amount);
    }
}
