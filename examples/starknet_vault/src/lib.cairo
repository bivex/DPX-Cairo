#[starknet::interface]
pub trait IVault<TContractState> {
    fn deposit(ref self: TContractState, amount: u256);
    fn withdraw(ref self: TContractState, amount: u256);
    fn get_balance(self: @TContractState, user: starknet::ContractAddress) -> u256;
    fn upgrade(ref self: TContractState, new_class_hash: starknet::ClassHash);
}

#[starknet::contract]
mod StarknetVault {
    use starknet::ContractAddress;
    use starknet::ClassHash;
    use starknet::get_caller_address;
    use starknet::syscalls::replace_class_hash_syscall;

    component!(path: OwnableComponent, storage: ownable, event: OwnableEvent);
    component!(path: ReentrancyGuardComponent, storage: reentrancy_guard, event: ReentrancyGuardEvent);

    #[storage]
    struct Storage {
        balances: Map<ContractAddress, u256>,
        total_deposited: u256,
        #[substorage(v0)]
        ownable: OwnableComponent::Storage,
        #[substorage(v0)]
        reentrancy_guard: ReentrancyGuardComponent::Storage,
    }

    #[event]
    #[derive(Drop, starknet::Event)]
    enum Event {
        Deposit: DepositEvent,
        Withdraw: WithdrawEvent,
        #[flat]
        OwnableEvent: OwnableComponent::Event,
        #[flat]
        ReentrancyGuardEvent: ReentrancyGuardComponent::Event,
    }

    #[derive(Drop, starknet::Event)]
    struct DepositEvent {
        user: ContractAddress,
        amount: u256,
    }

    #[derive(Drop, starknet::Event)]
    struct WithdrawEvent {
        user: ContractAddress,
        amount: u256,
    }

    #[abi(embed_v0)]
    impl VaultImpl of super::IVault<ContractState> {
        fn deposit(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            assert(amount > 0, 'AMOUNT_ZERO');
            let current = self.balances.read(caller);
            self.balances.write(caller, current + amount);
            self.emit(Event::Deposit(DepositEvent { user: caller, amount }));
        }

        fn withdraw(ref self: ContractState, amount: u256) {
            let caller = get_caller_address();
            let current = self.balances.read(caller);
            assert(current >= amount, 'INSUFFICIENT_FUNDS');
            self.balances.write(caller, current - amount);
            self.emit(Event::Withdraw(WithdrawEvent { user: caller, amount }));
        }

        fn get_balance(self: @ContractState, user: ContractAddress) -> u256 {
            self.balances.read(user)
        }

        fn upgrade(ref self: ContractState, new_class_hash: ClassHash) {
            let caller = get_caller_address();
            assert(caller == self.ownable.owner(), 'NOT_OWNER');
            replace_class_hash_syscall(new_class_hash);
        }
    }
}
