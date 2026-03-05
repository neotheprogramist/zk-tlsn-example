// SPDX-License-Identifier: MIT
pragma solidity ^0.8.30;

import "forge-std/Test.sol";
import "../src/PrivacyPool.sol";
import "../src/MockERC20.sol";

contract MockStwoVerifier {
    bool public shouldVerify;

    constructor(bool _shouldVerify) {
        shouldVerify = _shouldVerify;
    }

    function setShouldVerify(bool value) external {
        shouldVerify = value;
    }

    function verify() external view returns (bool) {
        return shouldVerify;
    }
}

contract PrivacyPoolWithdrawTest is Test {
    PrivacyPool private pool;
    MockERC20 private token; 
    MockStwoVerifier private verifier;

    address private depositor = address(0xA11CE);
    address private recipient = address(0xB0B);
    uint256 private constant AMOUNT = 100e6;
    uint256 private constant SECRET_NULLIFIER_HASH = 12345;
    uint256 private constant NULLIFIER = 67890;
    uint256 private constant REFUND_COMMITMENT_HASH = 0;

    function setUp() external {
        pool = new PrivacyPool(address(this));
        token = new MockERC20("Mock USDC", "mUSDC", 1_000_000 * 10 ** 6);
        verifier = new MockStwoVerifier(true);

        pool.setVerifier(address(verifier));

        token.transfer(depositor, AMOUNT * 2);
        vm.prank(depositor);
        token.approve(address(pool), type(uint256).max);
    }

    function _deposit() private returns (uint256 root) {
        vm.prank(depositor);
        pool.deposit(SECRET_NULLIFIER_HASH, AMOUNT, address(token));
        return pool.getCurrentRoot();
    }

    function test_withdraw_succeeds_when_proof_is_valid() external {
        uint256 root = _deposit();
        bytes memory verifyCalldata = abi.encodeWithSelector(MockStwoVerifier.verify.selector);

        pool.withdraw(
            root,
            NULLIFIER,
            address(token),
            AMOUNT,
            recipient,
            REFUND_COMMITMENT_HASH,
            verifyCalldata
        );

        assertTrue(pool.isNullifierUsed(NULLIFIER));
        assertEq(token.balanceOf(recipient), AMOUNT);
        assertEq(token.balanceOf(address(pool)), 0);
    }

    function test_withdraw_reverts_when_proof_is_invalid() external {
        uint256 root = _deposit();
        verifier.setShouldVerify(false);
        bytes memory verifyCalldata = abi.encodeWithSelector(MockStwoVerifier.verify.selector);

        vm.expectRevert(PrivacyPool.ProofVerificationFailed.selector);
        pool.withdraw(
            root,
            NULLIFIER,
            address(token),
            AMOUNT,
            recipient,
            REFUND_COMMITMENT_HASH,
            verifyCalldata
        );
    }

    function test_withdraw_reverts_on_reused_nullifier() external {
        uint256 root = _deposit();
        bytes memory verifyCalldata = abi.encodeWithSelector(MockStwoVerifier.verify.selector);

        pool.withdraw(
            root,
            NULLIFIER,
            address(token),
            AMOUNT,
            recipient,
            REFUND_COMMITMENT_HASH,
            verifyCalldata
        );

        vm.expectRevert(PrivacyPool.NullifierAlreadyUsed.selector);
        pool.withdraw(
            root,
            NULLIFIER,
            address(token),
            AMOUNT,
            recipient,
            REFUND_COMMITMENT_HASH,
            verifyCalldata
        );
    }
}
