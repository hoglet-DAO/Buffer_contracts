#[test_only]
module hoglet_buffer::manager_tests {
    use std::signer;
    use std::vector;
    use supra_framework::account;
    use supra_framework::coin;
    use supra_framework::supra_coin::{Self, SupraCoin};
    use hoglet_buffer::manager;

    struct UnsupportedFakeCoin {}

    fun setup_env(framework: &signer, admin: &signer): (coin::BurnCapability<SupraCoin>, coin::MintCapability<SupraCoin>) {
        let (burn_cap, mint_cap) = supra_coin::initialize_for_test(framework);
        account::create_account_for_test(signer::address_of(admin));
        manager::init_for_test(admin);
        (burn_cap, mint_cap)
    }

    #[test(framework = @0x1, admin = @hoglet_buffer, next_admin = @0x200)]
    fun test_two_step_admin_transfer_and_pause(framework: &signer, admin: &signer, next_admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);
        let admin_addr = signer::address_of(admin);
        let next_addr = signer::address_of(next_admin);
        account::create_account_for_test(next_addr);

        assert!(manager::get_admin() == admin_addr, 1);
        assert!(manager::get_pending_admin() == @0x0, 2);
        assert!(!manager::is_paused(), 3);

        // Two-step transfer
        manager::nominate_admin(admin, next_addr);
        assert!(manager::get_pending_admin() == next_addr, 4);

        manager::accept_admin(next_admin);
        assert!(manager::get_admin() == next_addr, 5);
        assert!(manager::get_pending_admin() == @0x0, 6);

        // Pause and idempotent repeat
        manager::set_pause(next_admin, true);
        assert!(manager::is_paused(), 7);
        manager::set_pause(next_admin, true);
        assert!(manager::is_paused(), 8);
        manager::set_pause(next_admin, false);
        assert!(!manager::is_paused(), 9);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer, attacker = @0xbad)]
    #[expected_failure(abort_code = 327690, location = hoglet_buffer::manager)]
    fun test_accept_admin_rejects_non_pending(framework: &signer, admin: &signer, attacker: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);
        account::create_account_for_test(signer::address_of(attacker));
        manager::nominate_admin(admin, @0x200);
        manager::accept_admin(attacker);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer)]
    fun test_whitelist_add_and_swap_remove(framework: &signer, admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);

        manager::add_to_whitelist(admin, @0x111);
        manager::add_to_whitelist(admin, @0x222);
        manager::add_to_whitelist(admin, @0x333);
        assert!(manager::is_whitelisted(@0x111), 1);
        assert!(manager::is_whitelisted(@0x222), 2);
        assert!(manager::is_whitelisted(@0x333), 3);

        // Remove middle/first element via O(1) swap_remove
        manager::remove_from_whitelist(admin, @0x111);
        assert!(!manager::is_whitelisted(@0x111), 4);
        assert!(manager::is_whitelisted(@0x222), 5);
        assert!(manager::is_whitelisted(@0x333), 6);
        assert!(vector::length(&manager::get_whitelisted_protocols()) == 2, 7);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer)]
    fun test_principal_vs_yield_isolation_and_unregistered_destination(framework: &signer, admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);

        // Simulate V1 -> V2 in-place upgrade where BufferAccounting did not exist yet
        manager::drop_accounting_for_upgrade_test();
        assert!(manager::get_claimable_supra_yield() == 0, 1);
        assert!(manager::get_reserved_supra_principal() == 0, 2);
        assert!(manager::get_exchange_fee_bps() == 0, 3);

        // Set 100 bps (1%) exchange fee lazily initializing BufferAccounting
        manager::set_exchange_fee_bps(admin, 100);
        assert!(manager::get_exchange_fee_bps() == 100, 4);

        // Simulate 10,000 SUPRA swap deposit (100 fee + 9,900 reserved principal) + 500 PoEL yield
        let principal_coins = coin::mint<SupraCoin>(10_000, &mint_cap);
        let yield_coins = coin::mint<SupraCoin>(500, &mint_cap);
        manager::simulate_supra_inflow_and_yield_for_test(principal_coins, yield_coins, 100);

        assert!(manager::get_available_supra_balance() == 10_500, 5);
        assert!(manager::get_reserved_supra_principal() == 9_900, 6);
        assert!(manager::get_claimable_supra_yield() == 600, 7);

        // Withdraw 600 yield to a brand-new UNREGISTERED cold wallet (@0xc01d)
        // Verifies [M-02] fix: supra_account::deposit_coins auto-creates and registers destination
        manager::withdraw_yield(admin, 600, @0xc01d);
        assert!(coin::balance<SupraCoin>(@0xc01d) == 600, 8);
        assert!(manager::get_claimable_supra_yield() == 0, 9);
        assert!(manager::get_reserved_supra_principal() == 9_900, 10);
        assert!(manager::get_available_supra_balance() == 9_900, 11);

        // Replenish 9,900 principal to PoEL -> clears reserved principal cleanly
        manager::simulate_supra_replenish_outflow_for_test(9_900);
        assert!(manager::get_reserved_supra_principal() == 0, 12);
        assert!(manager::get_available_supra_balance() == 0, 13);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer)]
    #[expected_failure(abort_code = 196622, location = hoglet_buffer::manager)]
    fun test_withdraw_yield_blocks_draining_reserved_principal(framework: &signer, admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);

        // 10,000 SUPRA principal + 200 SUPRA yield -> attempting to withdraw 201 must abort with E_INSUFFICIENT_YIELD
        let principal_coins = coin::mint<SupraCoin>(10_000, &mint_cap);
        let yield_coins = coin::mint<SupraCoin>(200, &mint_cap);
        manager::simulate_supra_inflow_and_yield_for_test(principal_coins, yield_coins, 0);

        manager::withdraw_yield(admin, 201, @0xc01d);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer)]
    #[expected_failure(abort_code = 65542, location = hoglet_buffer::manager)]
    fun test_compound_yield_rejects_non_supra_coin_type(framework: &signer, admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);

        // Calling compound_yield<UnsupportedFakeCoin> must abort with E_COIN_NOT_SUPPORTED
        // before touching poel::withdraw_rewards
        manager::compound_yield<UnsupportedFakeCoin>(admin);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }

    #[test(framework = @0x1, admin = @hoglet_buffer)]
    fun test_emergency_withdraw_reconciles_accounting_safely(framework: &signer, admin: &signer) {
        let (burn_cap, mint_cap) = setup_env(framework, admin);

        let principal_coins = coin::mint<SupraCoin>(5_000, &mint_cap);
        let yield_coins = coin::mint<SupraCoin>(1_000, &mint_cap);
        manager::simulate_supra_inflow_and_yield_for_test(principal_coins, yield_coins, 0);

        // Emergency withdraw 1,500 SUPRA -> remaining 4,500 clamps yield to 0 and reserved principal to 4,500
        manager::emergency_withdraw_coin<SupraCoin>(admin, 1_500, @0x999);
        assert!(coin::balance<SupraCoin>(@0x999) == 1_500, 1);
        assert!(manager::get_claimable_supra_yield() == 0, 2);
        assert!(manager::get_reserved_supra_principal() == 4_500, 3);

        coin::destroy_burn_cap(burn_cap);
        coin::destroy_mint_cap(mint_cap);
    }
}
