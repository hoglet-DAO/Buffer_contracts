module hoglet_buffer::manager {
    use supra_framework::account::{Self, SignerCapability};
    use supra_framework::coin;
    use supra_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use supra_framework::object::Object;
    use supra_framework::primary_fungible_store;
    use supra_framework::supra_account;
    use supra_framework::supra_coin::SupraCoin;
    use supra_framework::event;
    use supra_framework::chain_id;
    use std::signer;
    use std::error;
    use std::vector;
    use std::option::{Self, Option};

    use dfmm_framework::asset_util;
    use dfmm_framework::poel;
    use dfmm_framework::iAsset;
    use dfmm_framework::asset_router;

    // =================================================================
    // ERROR CODES
    // =================================================================
    const E_NOT_INITIALIZED: u64 = 1;
    const E_INSUFFICIENT_BUFFER_STOCK: u64 = 2;
    const E_NOT_ADMIN: u64 = 3;
    const E_PAUSED: u64 = 4;
    const E_NOT_WHITELISTED: u64 = 5;
    const E_COIN_NOT_SUPPORTED: u64 = 6;
    const E_INVALID_COLLATERAL: u64 = 7;
    const E_INVALID_AMOUNT: u64 = 8;
    const E_INVALID_ADDRESS: u64 = 9;
    const E_NOT_PENDING_ADMIN: u64 = 10;
    const E_DECIMALS_MISMATCH: u64 = 11;
    const E_WHITELIST_FULL: u64 = 12;
    const E_FEE_TOO_HIGH: u64 = 13;
    const E_INSUFFICIENT_YIELD: u64 = 14;
    const E_NOTHING_TO_FINALIZE: u64 = 15;

    // =================================================================
    // CONSTANTS
    // =================================================================
    // Seed name for the Buffer's resource account
    const BUFFER_SEED: vector<u8> = b"HOGLET_INVENTORY_BUFFER";

    // Upper bound on whitelisted protocols to guarantee bounded gas in VIP-lane checks
    const MAX_WHITELIST_SIZE: u64 = 64;

    // Maximum configurable VIP-lane exchange fee in basis points (5.00% = 500 bps; default = 0)
    const MAX_EXCHANGE_FEE_BPS: u64 = 500;
    const BPS_DENOMINATOR: u128 = 10_000;

    // Replenishment funding source tags for enriched off-chain indexing
    const REPLENISH_SOURCE_BUFFER_IDLE: u8 = 0;
    const REPLENISH_SOURCE_ADMIN_ZAP: u8 = 1;
    const REPLENISH_SOURCE_COMPOUND: u8 = 2;

    // =================================================================
    // GLOBAL STATE STRUCTURES
    // =================================================================
    // Kept layout-identical for 100% MoveVM backward-compatible module upgrades.
    struct BufferConfig has key {
        signer_cap: SignerCapability,
        admin: address,
        pending_admin: address,
        is_paused: bool,
        whitelist: vector<address>,
    }

    // Additive accounting & fee configuration resource stored under the Buffer Resource Account.
    // Lazily initialized on upgrades so in-place module updates require zero manual migration.
    struct BufferAccounting has key {
        /// SUPRA collateral received from VIP-lane exchanges reserved to replenish PoEL inventory.
        reserved_supra_principal: u64,
        /// Net harvested PoEL SupraCoin rewards (plus any SUPRA exchange fees) available to withdraw or compound.
        claimable_supra_yield: u64,
        /// Optional exchange fee in basis points (0 = strict 1:1 exchange).
        exchange_fee_bps: u64,
    }

    // =================================================================
    // EVENTS (LOGS)
    // =================================================================
    // V1 Events preserved untouched for backwards compatibility with existing indexers.
    #[event]
    struct ExchangeEvent has drop, store {
        caller: address,
        base_amount_deposited: u64,
        iasset_metadata: Object<Metadata>,
    }

    #[event]
    struct ReplenishRequestEvent has drop, store {
        admin: address,
        base_amount: u64,
    }

    #[event]
    struct ReplenishFinalizedEvent has drop, store {
        iasset_metadata: Object<Metadata>,
        amount_received: u64,
    }

    #[event]
    struct RewardsClaimedEvent has drop, store {
        admin: address,
        amount_claimed: u64,
    }

    #[event]
    struct YieldWithdrawnEvent has drop, store {
        admin: address,
        supra_amount: u64,
        destination: address,
    }

    #[event]
    struct AdminNominatedEvent has drop, store {
        current_admin: address,
        pending_admin: address,
    }

    #[event]
    struct AdminTransferredEvent has drop, store {
        old_admin: address,
        new_admin: address,
    }

    #[event]
    struct PauseStatusChangedEvent has drop, store {
        admin: address,
        is_paused: bool,
    }

    #[event]
    struct WhitelistUpdatedEvent has drop, store {
        admin: address,
        protocol: address,
        is_whitelisted: bool,
    }

    #[event]
    struct EmergencyWithdrawCoinEvent has drop, store {
        admin: address,
        amount: u64,
        destination: address,
    }

    #[event]
    struct EmergencyWithdrawFAEvent has drop, store {
        admin: address,
        fa_metadata: Object<Metadata>,
        amount: u64,
        destination: address,
    }

    // Additive V2 Events providing full multi-asset & fee observability for off-chain indexers.
    #[event]
    struct ExchangeDetailEvent has drop, store {
        caller: address,
        deposited_metadata: Object<Metadata>,
        iasset_metadata: Object<Metadata>,
        base_amount_deposited: u64,
        iasset_amount_withdrawn: u64,
        fee_amount: u64,
    }

    #[event]
    struct ReplenishDetailEvent has drop, store {
        admin: address,
        fa_metadata: Option<Object<Metadata>>,
        base_amount: u64,
        source: u8,
    }

    #[event]
    struct EmergencyWithdrawCoinDetailEvent has drop, store {
        admin: address,
        paired_fa_metadata: Option<Object<Metadata>>,
        amount: u64,
        destination: address,
    }

    #[event]
    struct ExchangeFeeUpdatedEvent has drop, store {
        admin: address,
        old_fee_bps: u64,
        new_fee_bps: u64,
    }

    // Initializes the Buffer creating the Resource Account and setting the admin to @HOGL.
    fun init_module(deployer: &signer) {
        let (buffer_signer, signer_cap) = account::create_resource_account(deployer, BUFFER_SEED);
        let buffer_addr = signer::address_of(&buffer_signer);

        // Pre-register SupraCoin CoinStore to ensure PoEL reward withdrawals succeed
        if (!coin::is_account_registered<SupraCoin>(buffer_addr)) {
            coin::register<SupraCoin>(&buffer_signer);
        };

        move_to(&buffer_signer, BufferConfig {
            signer_cap,
            admin: @HOGL,
            pending_admin: @0x0,
            is_paused: false,
            whitelist: vector::empty<address>(),
        });

        move_to(&buffer_signer, BufferAccounting {
            reserved_supra_principal: 0,
            claimable_supra_yield: 0,
            exchange_fee_bps: 0,
        });
    }

    // =================================================================
    // 1. VIP LANE (For Launcher and Whitelisted Contracts)
    // =================================================================

    // Atomic exchange exclusive for Whitelisted contracts.
    // Version 1: Support for Legacy Coins (Coin<T>).
    public fun exchange_coin_for_launch<BaseCoin>(
        caller: &signer,
        base_coins: coin::Coin<BaseCoin>,
        iasset_metadata: Object<Metadata>
    ): FungibleAsset acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_whitelisted_and_get_signer(caller);

        let base_amount = coin::value(&base_coins);
        assert!(base_amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        // Verify that the deposited Coin has a valid paired FA and matches the requested iAsset collateral
        let opt_fa = coin::paired_metadata<BaseCoin>();
        assert!(option::is_some(&opt_fa), error::invalid_state(E_COIN_NOT_SUPPORTED));
        let deposited_metadata = option::extract(&mut opt_fa);

        let (iasset_out, fee_amount) = validate_collateral_and_compute_out(
            buffer_addr,
            deposited_metadata,
            base_amount,
            iasset_metadata
        );

        // Register the buffer account to receive this CoinType if not already registered
        if (!coin::is_account_registered<BaseCoin>(buffer_addr)) {
            coin::register<BaseCoin>(&buffer_signer);
        };

        // The Buffer receives and stores the legacy base coin
        coin::deposit(buffer_addr, base_coins);

        // Track reserved principal vs fee yield when collateral is SUPRA
        record_supra_exchange_inflow(&buffer_signer, buffer_addr, deposited_metadata, iasset_out, fee_amount);

        dispense_iasset_and_emit(
            caller,
            &buffer_signer,
            deposited_metadata,
            iasset_metadata,
            base_amount,
            iasset_out,
            fee_amount
        )
    }

    // Atomic exchange exclusive for Whitelisted contracts.
    // Version 2: Support for the Fungible Asset (FA) standard.
    public fun exchange_fa_for_launch(
        caller: &signer,
        base_fa: FungibleAsset,
        iasset_metadata: Object<Metadata>
    ): FungibleAsset acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_whitelisted_and_get_signer(caller);

        let base_amount = fungible_asset::amount(&base_fa);
        assert!(base_amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        let deposited_metadata = fungible_asset::metadata_from_asset(&base_fa);

        let (iasset_out, fee_amount) = validate_collateral_and_compute_out(
            buffer_addr,
            deposited_metadata,
            base_amount,
            iasset_metadata
        );

        // The Buffer receives and stores the Fungible Asset
        primary_fungible_store::deposit(buffer_addr, base_fa);

        // Track reserved principal vs fee yield when collateral is SUPRA (0xA paired FA)
        record_supra_exchange_inflow(&buffer_signer, buffer_addr, deposited_metadata, iasset_out, fee_amount);

        dispense_iasset_and_emit(
            caller,
            &buffer_signer,
            deposited_metadata,
            iasset_metadata,
            base_amount,
            iasset_out,
            fee_amount
        )
    }

    // =================================================================
    // 2. STOCK MAINTENANCE (Asynchronous)
    // =================================================================

    // Requests iAsset replenishment from PoEL using idle Coin<BaseCoin> held in the Buffer.
    public entry fun replenish_stock_request<BaseCoin>(
        account: &signer,
        amount: u64
    ) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, true);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        asset_router::deposit_coin<BaseCoin>(&buffer_signer, amount);

        let opt_fa = coin::paired_metadata<BaseCoin>();
        if (option::is_some(&opt_fa) && is_supra_metadata(*option::borrow(&opt_fa))) {
            sync_supra_accounting_after_outflow(buffer_addr, amount);
        };

        emit_replenish_events(signer::address_of(account), opt_fa, amount, REPLENISH_SOURCE_BUFFER_IDLE);
    }

    // Requests iAsset replenishment from PoEL using idle Fungible Asset (FA) collateral held in the Buffer.
    public entry fun replenish_stock_request_fa(
        account: &signer,
        fa_metadata: Object<Metadata>,
        amount: u64
    ) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, true);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        asset_router::deposit_fa(&buffer_signer, fa_metadata, amount);

        if (is_supra_metadata(fa_metadata)) {
            sync_supra_accounting_after_outflow(buffer_addr, amount);
        };

        emit_replenish_events(
            signer::address_of(account),
            option::some(fa_metadata),
            amount,
            REPLENISH_SOURCE_BUFFER_IDLE
        );
    }

    // ZAP: Extracts coins directly from the admin's wallet and pushes them to PoEL in 1 step.
    public entry fun replenish_stock_request_with_deposit<BaseCoin>(
        account: &signer,
        amount: u64
    ) acquires BufferConfig {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, true);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        // 1. Extract from admin and deposit to Buffer so PoEL credits the Buffer's borrow position
        let coins = coin::withdraw<BaseCoin>(account, amount);
        if (!coin::is_account_registered<BaseCoin>(buffer_addr)) {
            coin::register<BaseCoin>(&buffer_signer);
        };
        coin::deposit(buffer_addr, coins);

        // 2. Push immediately to PoEL (net change to Buffer idle reserves = 0)
        asset_router::deposit_coin<BaseCoin>(&buffer_signer, amount);

        emit_replenish_events(
            signer::address_of(account),
            coin::paired_metadata<BaseCoin>(),
            amount,
            REPLENISH_SOURCE_ADMIN_ZAP
        );
    }

    // ZAP: Extracts FA directly from the admin's wallet and pushes it to PoEL in 1 step.
    public entry fun replenish_stock_request_with_deposit_fa(
        account: &signer,
        fa_metadata: Object<Metadata>,
        amount: u64
    ) acquires BufferConfig {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, true);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));

        // 1. Extract FA from admin and deposit to Buffer
        let fa = primary_fungible_store::withdraw(account, fa_metadata, amount);
        primary_fungible_store::deposit(buffer_addr, fa);

        // 2. Push immediately to PoEL (net change to Buffer idle reserves = 0)
        asset_router::deposit_fa(&buffer_signer, fa_metadata, amount);

        emit_replenish_events(
            signer::address_of(account),
            option::some(fa_metadata),
            amount,
            REPLENISH_SOURCE_ADMIN_ZAP
        );
    }

    // Finalizes the wait period and claims the physical iAsset into the Buffer.
    // Permissionless by design so keeper bots can finalize once the PoEL cooldown elapses.
    public entry fun replenish_stock_finalize(
        iasset_metadata: Object<Metadata>
    ) acquires BufferConfig {
        let buffer_address = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_address), error::not_found(E_NOT_INITIALIZED));
        assert!(!borrow_global<BufferConfig>(buffer_address).is_paused, error::invalid_state(E_PAUSED));

        let balance_before = primary_fungible_store::balance(buffer_address, iasset_metadata);

        poel::borrow(iasset_metadata, buffer_address);

        let balance_after = primary_fungible_store::balance(buffer_address, iasset_metadata);
        let amount_received = if (balance_after > balance_before) { balance_after - balance_before } else { 0 };
        assert!(amount_received > 0, error::invalid_state(E_NOTHING_TO_FINALIZE));

        event::emit(ReplenishFinalizedEvent {
            iasset_metadata,
            amount_received,
        });
    }

    // =================================================================
    // 3. YIELD EXTRACTION (Normal Operation)
    // =================================================================

    // Claims rewards generated by the iAssets held in the Buffer's inventory.
    public entry fun claim_poel_rewards(account: &signer) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, false);
        let amount_claimed = harvest_poel_rewards_internal(&buffer_signer, buffer_addr);

        event::emit(RewardsClaimedEvent {
            admin: signer::address_of(account),
            amount_claimed,
        });
    }

    // Allows the administrator to withdraw accumulated SupraCoin yield from the Buffer.
    // Strictly bounded by claimable yield so VIP-lane principal collateral can never be drained as yield.
    public entry fun withdraw_yield(
        account: &signer,
        amount: u64,
        destination: address
    ) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, false);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));
        assert!(destination != @0x0, error::invalid_argument(E_INVALID_ADDRESS));

        let available_yield = get_effective_claimable_yield_at(buffer_addr);
        assert!(available_yield >= amount, error::invalid_state(E_INSUFFICIENT_YIELD));

        ensure_accounting_initialized(&buffer_signer, buffer_addr);
        let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
        accounting.claimable_supra_yield = accounting.claimable_supra_yield - amount;

        let reward_coins = coin::withdraw<SupraCoin>(&buffer_signer, amount);
        // Uses supra_account::deposit_coins so fresh/unregistered destination wallets never abort
        supra_account::deposit_coins(destination, reward_coins);

        event::emit(YieldWithdrawnEvent {
            admin: signer::address_of(account),
            supra_amount: amount,
            destination,
        });
    }

    // Backwards-compatible generic entry point: enforces BaseCoin == SupraCoin to prevent silent harvests
    // and delegates to the canonical SupraCoin auto-compounder.
    public entry fun compound_yield<BaseCoin>(account: &signer) acquires BufferConfig, BufferAccounting {
        let opt_fa = coin::paired_metadata<BaseCoin>();
        assert!(
            option::is_some(&opt_fa) && is_supra_metadata(*option::borrow(&opt_fa)),
            error::invalid_argument(E_COIN_NOT_SUPPORTED)
        );
        compound_supra_yield_internal(account);
    }

    // Canonical Auto-Compounder without redundant generic parameters:
    // Harvests PoEL SupraCoin rewards (emitting RewardsClaimedEvent) and re-injects all available
    // claimable yield (including any previously capped remainder) up to PoEL's current deposit limit.
    public entry fun compound_supra_yield(account: &signer) acquires BufferConfig, BufferAccounting {
        compound_supra_yield_internal(account);
    }

    // =================================================================
    // 4. ADMINISTRATION AND SECURITY
    // =================================================================

    // Direct admin transfer (kept for ABI backwards-compatibility; two-step nominate_admin + accept_admin is preferred).
    public entry fun transfer_admin(account: &signer, new_admin: address) acquires BufferConfig {
        assert!(new_admin != @0x0, error::invalid_argument(E_INVALID_ADDRESS));
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        assert!(signer::address_of(account) == config.admin, error::permission_denied(E_NOT_ADMIN));

        let old_admin = config.admin;
        config.admin = new_admin;
        config.pending_admin = @0x0;
        event::emit(AdminTransferredEvent { old_admin, new_admin });
    }

    // Two-step admin transfer: Step 1 - Nominate
    public entry fun nominate_admin(account: &signer, pending_admin: address) acquires BufferConfig {
        assert!(pending_admin != @0x0, error::invalid_argument(E_INVALID_ADDRESS));
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        assert!(signer::address_of(account) == config.admin, error::permission_denied(E_NOT_ADMIN));

        config.pending_admin = pending_admin;
        event::emit(AdminNominatedEvent { current_admin: config.admin, pending_admin });
    }

    // Two-step admin transfer: Step 2 - Accept
    public entry fun accept_admin(account: &signer) acquires BufferConfig {
        let caller = signer::address_of(account);
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        assert!(caller != @0x0 && caller == config.pending_admin, error::permission_denied(E_NOT_PENDING_ADMIN));

        let old_admin = config.admin;
        config.admin = caller;
        config.pending_admin = @0x0;
        event::emit(AdminTransferredEvent { old_admin, new_admin: caller });
    }

    // Pauses or unpauses the contract in case of emergency (no-op if state is unchanged).
    public entry fun set_pause(account: &signer, pause: bool) acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        let admin_addr = signer::address_of(account);
        assert!(admin_addr == config.admin, error::permission_denied(E_NOT_ADMIN));

        if (config.is_paused != pause) {
            config.is_paused = pause;
            event::emit(PauseStatusChangedEvent {
                admin: admin_addr,
                is_paused: pause,
            });
        };
    }

    // Updates the optional VIP-lane exchange fee in basis points (0 = strict 1:1, max = 500 bps).
    public entry fun set_exchange_fee_bps(
        account: &signer,
        new_fee_bps: u64
    ) acquires BufferConfig, BufferAccounting {
        assert!(new_fee_bps <= MAX_EXCHANGE_FEE_BPS, error::invalid_argument(E_FEE_TOO_HIGH));
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, false);
        ensure_accounting_initialized(&buffer_signer, buffer_addr);
        let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
        let old_fee_bps = accounting.exchange_fee_bps;
        if (old_fee_bps != new_fee_bps) {
            accounting.exchange_fee_bps = new_fee_bps;
            event::emit(ExchangeFeeUpdatedEvent {
                admin: signer::address_of(account),
                old_fee_bps,
                new_fee_bps,
            });
        };
    }

    // Adds a contract's signer address (Resource Account / Object Signer) to the whitelist.
    public entry fun add_to_whitelist(account: &signer, protocol: address) acquires BufferConfig {
        assert!(protocol != @0x0, error::invalid_argument(E_INVALID_ADDRESS));
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        let admin_addr = signer::address_of(account);
        assert!(admin_addr == config.admin, error::permission_denied(E_NOT_ADMIN));

        if (!vector::contains(&config.whitelist, &protocol)) {
            assert!(
                vector::length(&config.whitelist) < MAX_WHITELIST_SIZE,
                error::invalid_state(E_WHITELIST_FULL)
            );
            vector::push_back(&mut config.whitelist, protocol);
            event::emit(WhitelistUpdatedEvent {
                admin: admin_addr,
                protocol,
                is_whitelisted: true,
            });
        };
    }

    // Removes a contract from the whitelist in O(1) using swap_remove.
    public entry fun remove_from_whitelist(account: &signer, protocol: address) acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global_mut<BufferConfig>(buffer_addr);
        let admin_addr = signer::address_of(account);
        assert!(admin_addr == config.admin, error::permission_denied(E_NOT_ADMIN));

        let (found, index) = vector::index_of(&config.whitelist, &protocol);
        if (found) {
            vector::swap_remove(&mut config.whitelist, index);
            event::emit(WhitelistUpdatedEvent {
                admin: admin_addr,
                protocol,
                is_whitelisted: false,
            });
        };
    }

    // Emergency function: Withdraw any stuck Coin<T> safely (auto-registers destination if needed).
    public entry fun emergency_withdraw_coin<T>(
        account: &signer,
        amount: u64,
        destination: address
    ) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, false);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));
        assert!(destination != @0x0, error::invalid_argument(E_INVALID_ADDRESS));

        let coins = coin::withdraw<T>(&buffer_signer, amount);
        supra_account::deposit_coins(destination, coins);

        let paired_fa_metadata = coin::paired_metadata<T>();
        if (option::is_some(&paired_fa_metadata) && is_supra_metadata(*option::borrow(&paired_fa_metadata))) {
            sync_supra_accounting_after_outflow(buffer_addr, 0);
        };

        let admin_addr = signer::address_of(account);
        event::emit(EmergencyWithdrawCoinEvent {
            admin: admin_addr,
            amount,
            destination,
        });
        event::emit(EmergencyWithdrawCoinDetailEvent {
            admin: admin_addr,
            paired_fa_metadata,
            amount,
            destination,
        });
    }

    // Emergency function: Withdraw any stuck Fungible Asset.
    public entry fun emergency_withdraw_fa(
        account: &signer,
        fa_metadata: Object<Metadata>,
        amount: u64,
        destination: address
    ) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, false);
        assert!(amount > 0, error::invalid_argument(E_INVALID_AMOUNT));
        assert!(destination != @0x0, error::invalid_argument(E_INVALID_ADDRESS));

        primary_fungible_store::transfer(&buffer_signer, fa_metadata, destination, amount);

        if (is_supra_metadata(fa_metadata)) {
            sync_supra_accounting_after_outflow(buffer_addr, 0);
        };

        event::emit(EmergencyWithdrawFAEvent {
            admin: signer::address_of(account),
            fa_metadata,
            amount,
            destination,
        });
    }

    // =================================================================
    // 5. VIEW FUNCTIONS FOR FRONTEND, TREASURY AND FALLBACKS
    // =================================================================

    #[view]
    // The Launcher uses this function to know if it can use the Buffer or if it must do a Fallback.
    public fun get_available_iasset_stock(iasset_metadata: Object<Metadata>): u64 {
        primary_fungible_store::balance(get_buffer_address(), iasset_metadata)
    }

    #[view]
    // Returns the total physical SUPRA balance held by the Buffer (principal + claimable yield).
    public fun get_available_supra_balance(): u64 {
        coin::balance<SupraCoin>(get_buffer_address())
    }

    #[view]
    // Returns only the net PoEL SupraCoin yield (+ fees) safe to extract via withdraw_yield or compound.
    public fun get_claimable_supra_yield(): u64 acquires BufferAccounting {
        get_effective_claimable_yield_at(get_buffer_address())
    }

    #[view]
    // Returns the SUPRA collateral received from VIP-lane exchanges reserved for PoEL replenishment.
    public fun get_reserved_supra_principal(): u64 acquires BufferAccounting {
        let buffer_addr = get_buffer_address();
        if (exists<BufferAccounting>(buffer_addr)) {
            borrow_global<BufferAccounting>(buffer_addr).reserved_supra_principal
        } else {
            0
        }
    }

    #[view]
    // Returns the physical balance of any Fungible Asset collateral held in the Buffer.
    public fun get_available_collateral_fa_balance(fa_metadata: Object<Metadata>): u64 {
        primary_fungible_store::balance(get_buffer_address(), fa_metadata)
    }

    #[view]
    // Returns the current VIP-lane exchange fee in basis points (0 = strict 1:1).
    public fun get_exchange_fee_bps(): u64 acquires BufferAccounting {
        get_exchange_fee_bps_at(get_buffer_address())
    }

    #[view]
    // Returns remaining deposit capacity in PoEL's asset_router pool for a given FA collateral.
    public fun get_poel_available_capacity(fa_metadata: Object<Metadata>): u64 {
        let pool_details = asset_router::get_fa_pool_details(fa_metadata);
        let (pool_balance, _, _, limit) = asset_router::deconstruct_fa_pool_details(&pool_details);
        if (limit > pool_balance) { limit - pool_balance } else { 0 }
    }

    #[view]
    // Bridge (Facade) to fetch the master list of all valid iAssets directly from PoEL.
    public fun get_all_supported_iassets(): vector<Object<Metadata>> {
        iAsset::get_assets()
    }

    #[view]
    // Returns the current administrator of the Buffer.
    public fun get_admin(): address acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        borrow_global<BufferConfig>(buffer_addr).admin
    }

    #[view]
    // Returns the pending administrator of the Buffer.
    public fun get_pending_admin(): address acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        borrow_global<BufferConfig>(buffer_addr).pending_admin
    }

    #[view]
    // Returns true if the contract is paused for emergencies.
    public fun is_paused(): bool acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        borrow_global<BufferConfig>(buffer_addr).is_paused
    }

    #[view]
    // Checks if a specific protocol address is authorized to use the Buffer.
    public fun is_whitelisted(protocol: address): bool acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global<BufferConfig>(buffer_addr);
        vector::contains(&config.whitelist, &protocol)
    }

    #[view]
    // Returns the entire list of whitelisted protocol addresses.
    public fun get_whitelisted_protocols(): vector<address> acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        borrow_global<BufferConfig>(buffer_addr).whitelist
    }

    #[view]
    public fun get_buffer_address(): address {
        account::create_resource_address(&@hoglet_buffer, BUFFER_SEED)
    }

    // =================================================================
    // INTERNAL HELPERS (Single-Pass Auth, DRY Validation & Accounting)
    // =================================================================

    // Single SHA3-256 derivation + single global storage read for VIP-lane callers.
    fun authorize_whitelisted_and_get_signer(caller: &signer): (address, signer) acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global<BufferConfig>(buffer_addr);
        assert!(!config.is_paused, error::invalid_state(E_PAUSED));
        let caller_addr = signer::address_of(caller);
        assert!(vector::contains(&config.whitelist, &caller_addr), error::permission_denied(E_NOT_WHITELISTED));
        (buffer_addr, account::create_signer_with_capability(&config.signer_cap))
    }

    // Single SHA3-256 derivation + single global storage read for admin operations.
    fun authorize_admin_and_get_signer(
        account: &signer,
        require_not_paused: bool
    ): (address, signer) acquires BufferConfig {
        let buffer_addr = get_buffer_address();
        assert!(exists<BufferConfig>(buffer_addr), error::not_found(E_NOT_INITIALIZED));
        let config = borrow_global<BufferConfig>(buffer_addr);
        if (require_not_paused) {
            assert!(!config.is_paused, error::invalid_state(E_PAUSED));
        };
        assert!(signer::address_of(account) == config.admin, error::permission_denied(E_NOT_ADMIN));
        (buffer_addr, account::create_signer_with_capability(&config.signer_cap))
    }

    fun ensure_accounting_initialized(
        buffer_signer: &signer,
        buffer_addr: address
    ) {
        if (!exists<BufferAccounting>(buffer_addr)) {
            move_to(buffer_signer, BufferAccounting {
                reserved_supra_principal: 0,
                claimable_supra_yield: 0,
                exchange_fee_bps: 0,
            });
        };
    }

    fun get_exchange_fee_bps_at(buffer_addr: address): u64 acquires BufferAccounting {
        if (exists<BufferAccounting>(buffer_addr)) {
            borrow_global<BufferAccounting>(buffer_addr).exchange_fee_bps
        } else {
            0
        }
    }

    fun get_effective_claimable_yield_at(buffer_addr: address): u64 acquires BufferAccounting {
        if (!exists<BufferAccounting>(buffer_addr)) {
            return 0
        };
        let accounting = borrow_global<BufferAccounting>(buffer_addr);
        let physical_balance = coin::balance<SupraCoin>(buffer_addr);
        let unreserved = if (physical_balance > accounting.reserved_supra_principal) {
            physical_balance - accounting.reserved_supra_principal
        } else {
            0
        };
        if (accounting.claimable_supra_yield < unreserved) {
            accounting.claimable_supra_yield
        } else {
            unreserved
        }
    }

    fun is_supra_metadata(metadata: Object<Metadata>): bool {
        let opt_supra = coin::paired_metadata<SupraCoin>();
        option::is_some(&opt_supra) && option::destroy_some(opt_supra) == metadata
    }

    // Shared collateral, decimal, fee, and inventory validation for both Coin and FA VIP-lane paths.
    fun validate_collateral_and_compute_out(
        buffer_addr: address,
        deposited_metadata: Object<Metadata>,
        base_amount: u64,
        iasset_metadata: Object<Metadata>
    ): (u64, u64) acquires BufferAccounting {
        assert!(
            fungible_asset::decimals(deposited_metadata) == fungible_asset::decimals(iasset_metadata),
            error::invalid_argument(E_DECIMALS_MISMATCH)
        );

        let expected_iasset = iAsset::get_iasset_metadata(
            asset_util::get_fa_key(deposited_metadata),
            (chain_id::get() as u64)
        );
        assert!(expected_iasset == iasset_metadata, error::invalid_argument(E_INVALID_COLLATERAL));

        let fee_bps = get_exchange_fee_bps_at(buffer_addr);
        let fee_amount = ((((base_amount as u128) * (fee_bps as u128)) / BPS_DENOMINATOR) as u64);
        let iasset_out = base_amount - fee_amount;
        assert!(iasset_out > 0, error::invalid_argument(E_INVALID_AMOUNT));

        assert!(
            primary_fungible_store::balance(buffer_addr, iasset_metadata) >= iasset_out,
            error::invalid_state(E_INSUFFICIENT_BUFFER_STOCK)
        );

        (iasset_out, fee_amount)
    }

    fun dispense_iasset_and_emit(
        caller: &signer,
        buffer_signer: &signer,
        deposited_metadata: Object<Metadata>,
        iasset_metadata: Object<Metadata>,
        base_amount: u64,
        iasset_out: u64,
        fee_amount: u64
    ): FungibleAsset {
        let iasset_withdrawn = primary_fungible_store::withdraw(buffer_signer, iasset_metadata, iasset_out);
        let caller_addr = signer::address_of(caller);

        event::emit(ExchangeEvent {
            caller: caller_addr,
            base_amount_deposited: base_amount,
            iasset_metadata,
        });
        event::emit(ExchangeDetailEvent {
            caller: caller_addr,
            deposited_metadata,
            iasset_metadata,
            base_amount_deposited: base_amount,
            iasset_amount_withdrawn: iasset_out,
            fee_amount,
        });

        iasset_withdrawn
    }

    fun record_supra_exchange_inflow(
        buffer_signer: &signer,
        buffer_addr: address,
        deposited_metadata: Object<Metadata>,
        iasset_out: u64,
        fee_amount: u64
    ) acquires BufferAccounting {
        if (is_supra_metadata(deposited_metadata)) {
            ensure_accounting_initialized(buffer_signer, buffer_addr);
            let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
            accounting.reserved_supra_principal = accounting.reserved_supra_principal + iasset_out;
            accounting.claimable_supra_yield = accounting.claimable_supra_yield + fee_amount;
        };
    }

    // Maintains the invariant: reserved_supra_principal + claimable_supra_yield <= coin::balance<SupraCoin>(buffer_addr)
    fun sync_supra_accounting_after_outflow(
        buffer_addr: address,
        principal_replenished: u64
    ) acquires BufferAccounting {
        if (exists<BufferAccounting>(buffer_addr)) {
            let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
            if (principal_replenished >= accounting.reserved_supra_principal) {
                accounting.reserved_supra_principal = 0;
            } else {
                accounting.reserved_supra_principal = accounting.reserved_supra_principal - principal_replenished;
            };

            let remaining_balance = coin::balance<SupraCoin>(buffer_addr);
            if (accounting.reserved_supra_principal > remaining_balance) {
                accounting.reserved_supra_principal = remaining_balance;
                accounting.claimable_supra_yield = 0;
            } else {
                let unreserved = remaining_balance - accounting.reserved_supra_principal;
                if (accounting.claimable_supra_yield > unreserved) {
                    accounting.claimable_supra_yield = unreserved;
                };
            };
        };
    }

    fun harvest_poel_rewards_internal(
        buffer_signer: &signer,
        buffer_addr: address
    ): u64 acquires BufferAccounting {
        if (!coin::is_account_registered<SupraCoin>(buffer_addr)) {
            coin::register<SupraCoin>(buffer_signer);
        };

        let balance_before = coin::balance<SupraCoin>(buffer_addr);
        poel::withdraw_rewards(buffer_signer);
        let balance_after = coin::balance<SupraCoin>(buffer_addr);
        let amount_claimed = if (balance_after > balance_before) { balance_after - balance_before } else { 0 };

        if (amount_claimed > 0) {
            ensure_accounting_initialized(buffer_signer, buffer_addr);
            let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
            accounting.claimable_supra_yield = accounting.claimable_supra_yield + amount_claimed;
        };

        amount_claimed
    }

    fun compound_supra_yield_internal(account: &signer) acquires BufferConfig, BufferAccounting {
        let (buffer_addr, buffer_signer) = authorize_admin_and_get_signer(account, true);
        let admin_addr = signer::address_of(account);

        let opt_fa = coin::paired_metadata<SupraCoin>();
        assert!(option::is_some(&opt_fa), error::invalid_state(E_COIN_NOT_SUPPORTED));
        let supra_fa_metadata = option::extract(&mut opt_fa);

        // 1. Harvest fresh PoEL rewards and always emit RewardsClaimedEvent when > 0
        let amount_claimed = harvest_poel_rewards_internal(&buffer_signer, buffer_addr);
        if (amount_claimed > 0) {
            event::emit(RewardsClaimedEvent {
                admin: admin_addr,
                amount_claimed,
            });
        };

        // 2. Compound total available claimable yield (freshly harvested + any prior capped remainder)
        let available_yield = get_effective_claimable_yield_at(buffer_addr);
        if (available_yield > 0) {
            let space_left = get_poel_available_capacity(supra_fa_metadata);
            let safe_amount = if (available_yield > space_left) { space_left } else { available_yield };

            if (safe_amount > 0) {
                ensure_accounting_initialized(&buffer_signer, buffer_addr);
                let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
                accounting.claimable_supra_yield = accounting.claimable_supra_yield - safe_amount;

                asset_router::deposit_coin<SupraCoin>(&buffer_signer, safe_amount);

                emit_replenish_events(
                    admin_addr,
                    option::some(supra_fa_metadata),
                    safe_amount,
                    REPLENISH_SOURCE_COMPOUND
                );
            };
        };
    }

    fun emit_replenish_events(
        admin: address,
        fa_metadata: Option<Object<Metadata>>,
        base_amount: u64,
        source: u8
    ) {
        event::emit(ReplenishRequestEvent {
            admin,
            base_amount,
        });
        event::emit(ReplenishDetailEvent {
            admin,
            fa_metadata,
            base_amount,
            source,
        });
    }

    // =================================================================
    // TEST-ONLY HELPERS
    // =================================================================
    #[test_only]
    public fun init_for_test(deployer: &signer) {
        init_module(deployer);
    }

    #[test_only]
    public fun drop_accounting_for_upgrade_test() acquires BufferAccounting {
        let buffer_addr = get_buffer_address();
        if (exists<BufferAccounting>(buffer_addr)) {
            let BufferAccounting {
                reserved_supra_principal: _,
                claimable_supra_yield: _,
                exchange_fee_bps: _,
            } = move_from<BufferAccounting>(buffer_addr);
        };
    }

    #[test_only]
    public fun simulate_supra_inflow_and_yield_for_test(
        principal_coins: coin::Coin<SupraCoin>,
        yield_coins: coin::Coin<SupraCoin>,
        fee_amount: u64
    ) acquires BufferConfig, BufferAccounting {
        let buffer_addr = get_buffer_address();
        let config = borrow_global<BufferConfig>(buffer_addr);
        let buffer_signer = account::create_signer_with_capability(&config.signer_cap);

        let principal_amount = coin::value(&principal_coins);
        let yield_amount = coin::value(&yield_coins);
        let iasset_out = principal_amount - fee_amount;

        coin::deposit(buffer_addr, principal_coins);
        coin::deposit(buffer_addr, yield_coins);

        ensure_accounting_initialized(&buffer_signer, buffer_addr);
        let accounting = borrow_global_mut<BufferAccounting>(buffer_addr);
        accounting.reserved_supra_principal = accounting.reserved_supra_principal + iasset_out;
        accounting.claimable_supra_yield = accounting.claimable_supra_yield + fee_amount + yield_amount;
    }

    #[test_only]
    public fun simulate_supra_replenish_outflow_for_test(amount: u64) acquires BufferConfig, BufferAccounting {
        let buffer_addr = get_buffer_address();
        let config = borrow_global<BufferConfig>(buffer_addr);
        let buffer_signer = account::create_signer_with_capability(&config.signer_cap);
        let withdrawn = coin::withdraw<SupraCoin>(&buffer_signer, amount);
        supra_account::deposit_coins(@0xdead, withdrawn);
        sync_supra_accounting_after_outflow(buffer_addr, amount);
    }
}
