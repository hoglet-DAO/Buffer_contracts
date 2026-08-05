module hoglet_buffer::manager {
    use supra_framework::account::{Self, SignerCapability};
    use supra_framework::coin::{Self};
    use supra_framework::fungible_asset::{Self, FungibleAsset, Metadata};
    use supra_framework::object::Object;
    use supra_framework::primary_fungible_store;
    use supra_framework::supra_coin::SupraCoin;
    use aptos_std::event;
    use std::signer;
    use std::error;
    use std::vector;
    
    // Assuming PoEL is deployed at this address (Adjust per network)
    use dfmm_framework::poel;
    use dfmm_framework::iAsset;
    use dfmm_framework::asset_router;

    // =================================================================
    // ERROR CODES
    // =================================================================
    const ENOT_INITIALIZED: u64 = 1;
    const EINSUFFICIENT_BUFFER_STOCK: u64 = 2;
    const ENOT_ADMIN: u64 = 3;
    const EPAUSED: u64 = 4;
    const ENOT_WHITELISTED: u64 = 5;

    // Seed name for the Buffer's resource account
    const BUFFER_SEED: vector<u8> = b"HOGLET_INVENTORY_BUFFER";

    // =================================================================
    // GLOBAL STATE STRUCTURE
    // =================================================================
    struct BufferConfig has key {
        signer_cap: SignerCapability,
        admin: address,
        is_paused: bool,
        whitelist: vector<address>, 
    }

    // =================================================================
    // EVENTS (LOGS)
    // =================================================================
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
        // iasset_metadata is inferred by asset_router, omitted here for simplicity
    }

    #[event]
    struct YieldWithdrawnEvent has drop, store {
        admin: address,
        supra_amount: u64,
        destination: address,
    }

    // Initializes the Buffer creating the Resource Account and setting the admin.
    fun init_module(admin: &signer) {
        let (buffer_signer, signer_cap) = account::create_resource_account(admin, BUFFER_SEED);
        
        move_to(&buffer_signer, BufferConfig {
            signer_cap,
            admin: signer::address_of(admin),
            is_paused: false,
            whitelist: vector::empty<address>(), 
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
    ): FungibleAsset acquires BufferConfig {
        assert_not_paused();
        assert_whitelisted(caller);

        let buffer_address = get_buffer_address();
        let base_amount = coin::value(&base_coins);
        
        assert!(get_available_iasset_stock(iasset_metadata) >= base_amount, error::invalid_state(EINSUFFICIENT_BUFFER_STOCK));

        // The Buffer receives and stores the legacy base coin
        coin::deposit(buffer_address, base_coins);

        let buffer_signer = get_buffer_signer();
        let iasset_withdrawn = primary_fungible_store::withdraw(&buffer_signer, iasset_metadata, base_amount);
        
        event::emit(ExchangeEvent {
            caller: signer::address_of(caller),
            base_amount_deposited: base_amount,
            iasset_metadata,
        });

        iasset_withdrawn
    }

    // Atomic exchange exclusive for Whitelisted contracts.
    // Version 2: Support for the new Fungible Asset (FA) standard.
    public fun exchange_fa_for_launch(
        caller: &signer,
        base_fa: FungibleAsset,
        iasset_metadata: Object<Metadata>
    ): FungibleAsset acquires BufferConfig {
        assert_not_paused();
        assert_whitelisted(caller);

        let buffer_address = get_buffer_address();
        let base_amount = fungible_asset::amount(&base_fa);
        
        assert!(get_available_iasset_stock(iasset_metadata) >= base_amount, error::invalid_state(EINSUFFICIENT_BUFFER_STOCK));

        // The Buffer receives and stores the Fungible Asset
        primary_fungible_store::deposit(buffer_address, base_fa);

        let buffer_signer = get_buffer_signer();
        let iasset_withdrawn = primary_fungible_store::withdraw(&buffer_signer, iasset_metadata, base_amount);
        
        event::emit(ExchangeEvent {
            caller: signer::address_of(caller),
            base_amount_deposited: base_amount,
            iasset_metadata,
        });

        iasset_withdrawn
    }

    // =================================================================
    // 2. STOCK MAINTENANCE (Asynchronous)
    // =================================================================

    // Borrows iSUPRA from PoEL leaving SUPRA as collateral (Starts wait period).
    public entry fun replenish_stock_request<BaseCoin>(
        account: &signer,
        amount: u64
    ) acquires BufferConfig {
        assert_not_paused();
        assert_admin(account);
        let buffer_signer = get_buffer_signer();
        
        // We use the official asset_router to deposit coins and start the borrow process
        asset_router::deposit_coin<BaseCoin>(&buffer_signer, amount);
        
        event::emit(ReplenishRequestEvent {
            admin: signer::address_of(account),
            base_amount: amount,
        });
    }

    // Finalizes the wait period and claims the physical iSUPRA.
    public entry fun replenish_stock_finalize(
        iasset_metadata: Object<Metadata>
    ) acquires BufferConfig {
        assert_not_paused();
        let buffer_address = get_buffer_address();
        poel::borrow(iasset_metadata, buffer_address);
    }

    // =================================================================
    // 3. YIELD EXTRACTION (Normal Operation)
    // =================================================================

    // Admin withdraws accumulated base coins as yield from other contracts.
    public entry fun withdraw_yield(
        account: &signer,
        amount: u64,
        destination: address
    ) acquires BufferConfig {
        assert_admin(account);
        let buffer_signer = get_buffer_signer();
        
        let supra_to_withdraw = coin::withdraw<SupraCoin>(&buffer_signer, amount);
        coin::deposit(destination, supra_to_withdraw);
        
        event::emit(YieldWithdrawnEvent {
            admin: signer::address_of(account),
            supra_amount: amount,
            destination,
        });
    }

    // =================================================================
    // 4. ADMINISTRATION AND SECURITY
    // =================================================================

    // Transfers Buffer control to a new Administrator (e.g. Multisig).
    public entry fun transfer_admin(account: &signer, new_admin: address) acquires BufferConfig {
        assert_admin(account);
        let config = borrow_global_mut<BufferConfig>(get_buffer_address());
        config.admin = new_admin;
    }

    // Pauses or unpauses the entire contract in case of emergency.
    public entry fun set_pause(account: &signer, pause: bool) acquires BufferConfig {
        assert_admin(account);
        let config = borrow_global_mut<BufferConfig>(get_buffer_address());
        config.is_paused = pause;
    }

    // Adds a contract (e.g. Launcher) to the whitelist.
    public entry fun add_to_whitelist(account: &signer, protocol: address) acquires BufferConfig {
        assert_admin(account);
        let config = borrow_global_mut<BufferConfig>(get_buffer_address());
        if (!vector::contains(&config.whitelist, &protocol)) {
            vector::push_back(&mut config.whitelist, protocol);
        };
    }

    // Removes a contract from the whitelist.
    public entry fun remove_from_whitelist(account: &signer, protocol: address) acquires BufferConfig {
        assert_admin(account);
        let config = borrow_global_mut<BufferConfig>(get_buffer_address());
        let (found, index) = vector::index_of(&config.whitelist, &protocol);
        if (found) {
            vector::remove(&mut config.whitelist, index);
        };
    }

    // Emergency function: Withdraw any stuck coin.
    public entry fun emergency_withdraw_coin<T>(account: &signer, amount: u64, destination: address) acquires BufferConfig {
        assert_admin(account);
        let buffer_signer = get_buffer_signer();
        let coins = coin::withdraw<T>(&buffer_signer, amount);
        coin::deposit(destination, coins);
    }

    // Emergency function: Withdraw any stuck Fungible Asset.
    public entry fun emergency_withdraw_fa(account: &signer, fa_metadata: Object<Metadata>, amount: u64, destination: address) acquires BufferConfig {
        assert_admin(account);
        let buffer_signer = get_buffer_signer();
        primary_fungible_store::transfer(&buffer_signer, fa_metadata, destination, amount);
    }

    // =================================================================
    // 5. VIEW FUNCTIONS FOR FRONTEND AND FALLBACKS
    // =================================================================

    #[view]
    // The Launcher uses this function to know if it can use the Buffer or if it must do a Fallback.
    public fun get_available_iasset_stock(iasset_metadata: Object<Metadata>): u64 {
        primary_fungible_store::balance(get_buffer_address(), iasset_metadata)
    }

    #[view]
    // Returns the amount of idle SUPRA that the admin can use to generate yield or extract.
    public fun get_available_supra_balance(): u64 {
        coin::balance<SupraCoin>(get_buffer_address())
    }

    #[view]
    // Bridge (Facade) to fetch the master list of all valid iAssets directly from PoEL
    public fun get_all_supported_iassets(): vector<Object<Metadata>> {
        iAsset::get_assets()
    }

    #[view]
    // Returns the current administrator of the Buffer.
    public fun get_admin(): address acquires BufferConfig {
        borrow_global<BufferConfig>(get_buffer_address()).admin
    }

    #[view]
    // Returns true if the contract is paused for emergencies.
    public fun is_paused(): bool acquires BufferConfig {
        borrow_global<BufferConfig>(get_buffer_address()).is_paused
    }

    #[view]
    // Checks if a specific protocol address is authorized to use the Buffer.
    public fun is_whitelisted(protocol: address): bool acquires BufferConfig {
        let config = borrow_global<BufferConfig>(get_buffer_address());
        vector::contains(&config.whitelist, &protocol)
    }

    #[view]
    // Returns the entire list of whitelisted protocol addresses.
    public fun get_whitelisted_protocols(): vector<address> acquires BufferConfig {
        borrow_global<BufferConfig>(get_buffer_address()).whitelist
    }

    #[view]
    public fun get_buffer_address(): address {
        account::create_resource_address(&@hoglet_buffer, BUFFER_SEED)
    }

    // =================================================================
    // HELPER FUNCTIONS FOR VERIFICATION
    // =================================================================

    fun get_buffer_signer(): signer acquires BufferConfig {
        let buffer_address = account::create_resource_address(&@hoglet_buffer, BUFFER_SEED);
        let config = borrow_global<BufferConfig>(buffer_address);
        account::create_signer_with_capability(&config.signer_cap)
    }

    fun assert_admin(account: &signer) acquires BufferConfig {
        let config = borrow_global<BufferConfig>(get_buffer_address());
        assert!(signer::address_of(account) == config.admin, error::permission_denied(ENOT_ADMIN));
    }

    fun assert_not_paused() acquires BufferConfig {
        let config = borrow_global<BufferConfig>(get_buffer_address());
        assert!(!config.is_paused, error::invalid_state(EPAUSED));
    }

    fun assert_whitelisted(caller: &signer) acquires BufferConfig {
        let config = borrow_global<BufferConfig>(get_buffer_address());
        let caller_addr = signer::address_of(caller);
        assert!(vector::contains(&config.whitelist, &caller_addr), error::permission_denied(ENOT_WHITELISTED));
    }
}
