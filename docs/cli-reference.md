# Nunchuk CLI Reference

Command-line interface for Nunchuk group wallet management.

## Installation

```bash
npm install -g nunchuk-cli
```

This installs the `nunchuk` command globally, available from any directory.

**For development:**

```bash
git clone <repo>
cd nunchuk-cli
npm install
npm run build
npm link       # links local build as global `nunchuk` command
```

## Global Options

| Flag | Description |
|------|-------------|
| `--json` | Output in JSON format (useful for scripting and AI agents) |
| `--api-key <key>` | Override stored API key for this command |
| `--network <network>` | Override network (`mainnet` or `testnet`), including the selected stored auth profile |

## Configuration

Session settings are stored in `~/.nunchuk-cli/config.json` (file mode `0600`). Secrets and per-user metadata live in encrypted per-account SQLite databases at `~/.nunchuk-cli/data/<emailHash>/<network>/storage.sqlite`.

Fields in `config.json`:
- `network` — Active network (`mainnet` or `testnet`)
- `mainnet.email` / `testnet.email` — Active user profile pointer for that network
- `mainnet.electrumServer` / `testnet.electrumServer` — Optional custom Electrum endpoint override

API key resolution order: `--api-key` flag > `NUNCHUK_API_KEY` env var > selected network profile.

Network resolution order: `--network` flag > config file > `mainnet` default.

Electrum defaults:
- `mainnet` — `ssl://mainnet.nunchuk.io:52002`
- `testnet` — `tcp://testnet.nunchuk.io:50001`

---

## Auth Commands

Manage authentication with the Nunchuk API.

### `nunchuk auth login`

Authenticate with your API secret key. Use `--api-key <key>` for non-interactive login, or omit it to enter the key in the prompt. The key is validated by calling the Nunchuk API (`/v1.1/developer/me`), and the user's email, ID, and name are saved under the selected network in config. On first login for a given network, an ephemeral Curve25519 keypair is automatically generated and saved for that network. This keypair is used for end-to-end encryption of group wallet data.

Running login again will update the selected network config but preserve that network's existing ephemeral keypair. Mainnet and testnet store separate API keys and separate ephemeral keypairs.

```bash
nunchuk auth login --api-key <api-secret-key>

# Or interactive:
nunchuk auth login
# Enter API secret key: ****
```

Output:
```
  status: authenticated
  email: user@example.com
  message: Config saved to ~/.nunchuk-cli/config.json
```

JSON output (`--json`):
```json
{
  "status": "authenticated",
  "email": "user@example.com",
  "message": "Config saved to ~/.nunchuk-cli/config.json"
}
```

### `nunchuk auth status`

Show current authentication status for the selected network, including a masked API key and that network's ephemeral public key.

```bash
nunchuk auth status
```

Output (authenticated):
```
  status: authenticated
  network: testnet
  apiKey: abc12345...6789
  ephemeralPub: <base64 public key>
```

Output (not authenticated):
```
  status: not_authenticated
  network: testnet
```

### `nunchuk auth logout`

Remove the stored API key for the selected network. Other config data (the other network config, active network, and ephemeral keypairs) is preserved.

```bash
nunchuk auth logout
```

Output:
```
  status: logged_out
  network: testnet
  message: Logged out
```

---

## Network Commands

Select between mainnet and testnet. Each network uses a different API server:
- **mainnet**: `https://api.nunchuk.io`
- **testnet**: `https://api-testnet.nunchuk.io`

### `nunchuk network set <network>`

Set the active network.

| Argument | Description |
|----------|-------------|
| `<network>` | `mainnet` or `testnet` |

```bash
nunchuk network set testnet
```

### `nunchuk network get`

Show the currently active network.

```bash
nunchuk network get
```

Output:
```
  network: testnet
```

---

## Sandbox Commands

Manage group wallet sandboxes. A sandbox is a pre-wallet state where participants assemble their signer keys before finalizing into an active multisig wallet.

### `nunchuk sandbox create`

Create a new group wallet sandbox. The sandbox state is end-to-end encrypted using the selected network's ephemeral keypair generated during login.

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--name <name>` | Yes | — | Wallet name |
| `--m <number>` | Yes | — | Required signatures (must be <= n) |
| `--n <number>` | Yes | — | Total signers (must be >= 2) |
| `--address-type <type>` | No | `NATIVE_SEGWIT` | Address type |

Valid address types: `NATIVE_SEGWIT`, `NESTED_SEGWIT`, `LEGACY`, `TAPROOT`

```bash
# Uses default NATIVE_SEGWIT
nunchuk sandbox create --name "Team Vault" --m 2 --n 3

# Explicit address type
nunchuk sandbox create --name "Team Vault" --m 2 --n 3 --address-type NESTED_SEGWIT
```

### `nunchuk sandbox list`

List all sandboxes for the authenticated account.

```bash
nunchuk sandbox list
```

### `nunchuk sandbox get <sandbox-id>`

Get details of a specific sandbox.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox get abc123
```

### `nunchuk sandbox join <sandbox-id-or-url>`

Join an existing sandbox as a participant.

| Argument | Description |
|----------|-------------|
| `<sandbox-id-or-url>` | Sandbox ID or join URL |

```bash
nunchuk sandbox join abc123
nunchuk sandbox join https://nunchuk.io/join/abc123
```

### `nunchuk sandbox add-key <sandbox-id>`

Add a signer key to a specific slot in the sandbox.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<sandbox-id>` | Yes | Sandbox ID |
| `--slot <number>` | Yes | Slot index (0-based) |
| `--fingerprint <xfp>` | Conditionally | Master fingerprint (8 hex chars). Alone = look up stored key and auto-derive descriptor. With `--xpub` + `--path` = manual descriptor |
| `--descriptor <descriptor>` | Conditionally | Full signer descriptor in `[xfp/path]xpub` format (`h` and `'` both supported) |
| `--xpub <xpub>` | Conditionally | Extended public key (requires `--fingerprint` and `--path`) |
| `--path <path>` | Conditionally | BIP derivation path, e.g. `m/48h/0h/0h/2h` (requires `--fingerprint` and `--xpub`) |

Three modes: `--fingerprint` alone (stored key), `--descriptor`, or `--fingerprint` + `--xpub` + `--path`.

```bash
# Use a stored key (simplest)
nunchuk sandbox add-key abc123 --slot 0 --fingerprint 73c5da0a

# Or provide a full descriptor
nunchuk sandbox add-key abc123 \
  --slot 1 \
  --descriptor "[1a2b3c4d/48h/0h/0h/2h]xpub6..."

# Or provide individual parts
nunchuk sandbox add-key abc123 \
  --slot 0 \
  --fingerprint "1a2b3c4d" \
  --xpub "xpub6..." \
  --path "m/48h/0h/0h/2h"
```

### `nunchuk sandbox finalize <sandbox-id>`

Finalize a sandbox into an active wallet. All signer slots must be filled before finalizing.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox finalize abc123
```

### `nunchuk sandbox delete <sandbox-id>`

Delete a sandbox permanently.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox delete abc123
```

### `nunchuk sandbox platform-key enable <sandbox-id>`

Enable platform key on a sandbox. Reserves the last signer slot (index `n-1`) for the Nunchuk-held platform key and adds the backend's public key to the encrypted group state.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox platform-key enable abc123
```

### `nunchuk sandbox platform-key disable <sandbox-id>`

Disable platform key on a sandbox. Removes the backend's public key from the group state and frees the last signer slot.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox platform-key disable abc123
```

### `nunchuk sandbox platform-key set-policy <sandbox-id>`

Set platform key policies. Platform key must be enabled first. Policies control when the platform key auto-signs: spending limits, signing delays, and auto-broadcast.

Three input modes:

**1. CLI flags** (one policy at a time):

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `--signer <xfp>` | string | _(none — global)_ | Target signer fingerprint (per-signer policy) |
| `--auto-broadcast` | boolean | `false` | Auto-broadcast after signing |
| `--signing-delay <duration>` | string | `0` | Delay before signing as seconds or `30s`, `15m`, `24h`, `7d` |
| `--limit-amount <amount>` | string | _(none)_ | Spending limit amount |
| `--limit-currency <currency>` | string | _(none)_ | Spending limit currency (USD, BTC, sat) |
| `--limit-interval <interval>` | string | _(none)_ | DAILY, WEEKLY, MONTHLY, YEARLY |

```bash
# Global policy
nunchuk sandbox platform-key set-policy abc123 \
  --auto-broadcast --signing-delay 1h

# Global policy with spending limit
nunchuk sandbox platform-key set-policy abc123 \
  --auto-broadcast --limit-amount 1000 --limit-currency USD --limit-interval DAILY

# Per-signer policy (smart merge: updates this signer, keeps others)
nunchuk sandbox platform-key set-policy abc123 \
  --signer 534a4a82 --auto-broadcast --signing-delay 0
```

**2. `--policy-json <json>`** (inline JSON — full replacement):

```bash
nunchuk sandbox platform-key set-policy abc123 --policy-json '{
  "signers": [
    {
      "masterFingerprint": "534a4a82",
      "autoBroadcastTransaction": true,
      "signingDelaySeconds": 0,
      "spendingLimit": { "interval": "DAILY", "amount": "1000", "currency": "USD" }
    },
    {
      "masterFingerprint": "a1b2c3d4",
      "autoBroadcastTransaction": false,
      "signingDelaySeconds": 3600,
      "spendingLimit": null
    }
  ]
}'
```

**3. `--policy-file <path>`** (JSON file — full replacement):

```bash
nunchuk sandbox platform-key set-policy abc123 --policy-file policy.json
```

Global and per-signer policies are mutually exclusive. When using `--signer` with existing per-signer policies, the CLI performs a smart merge (updates the targeted signer, keeps others). Switching between global and per-signer replaces entirely.

### `nunchuk sandbox platform-key get <sandbox-id>`

Show platform key status and policies for a sandbox.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |

```bash
nunchuk sandbox platform-key get abc123
```

Output when enabled:
```
Platform Key:    Enabled
Policy Type:     Global
Auto Broadcast:  true
Signing Delay:   0s
Spending Limit:  1000 USD / DAILY
```

Output when disabled:
```
Platform Key:    Disabled
```

---

## Invitation Commands

Manage wallet invitations.

### `nunchuk invitation send <sandbox-id> <emails...>`

Invite one or more people to a sandbox by email.

| Argument | Description |
|----------|-------------|
| `<sandbox-id>` | Sandbox ID |
| `<emails...>` | One or more recipient emails |

The command accepts either space-separated emails or comma-separated batches.

```bash
nunchuk invitation send abc123 alice@example.com bob@example.com

nunchuk invitation send abc123 alice@example.com,bob@example.com
```

### `nunchuk invitation list [sandbox-id]`

List pending invitations. Without an argument, this lists invitations for the current user. With a sandbox ID, it lists pending invitations sent for that sandbox.

```bash
nunchuk invitation list

nunchuk invitation list abc123
```

### `nunchuk invitation accept <invitation-id>`

Accept an invitation and join its sandbox.

```bash
nunchuk invitation accept 9d53f7aa-1234-4567-89ab-0123456789ab
```

### `nunchuk invitation deny <invitation-id>`

Deny an invitation.

```bash
nunchuk invitation deny 9d53f7aa-1234-4567-89ab-0123456789ab
```

---

## Wallet Commands

Manage finalized group wallets.

### `nunchuk wallet list`

List all wallets stored locally.

| Option | Description |
|--------|-------------|
| `--no-balance` | Skip Electrum balance lookup and return local wallet metadata only |

```bash
nunchuk wallet list

nunchuk wallet list --no-balance
```

### `nunchuk wallet get <wallet-id>`

Get locally stored wallet details.

| Argument / Option | Description |
|-------------------|-------------|
| `<wallet-id>` | Wallet ID |
| `--no-balance` | Skip Electrum balance lookup and return local wallet metadata only |

```bash
nunchuk wallet get wallet_abc123

nunchuk wallet get wallet_abc123 --no-balance
```

### `nunchuk wallet address get <wallet-id>`

Get a fresh receive address for a wallet. The CLI scans receive-chain history with Electrum, finds the highest used receive index, and returns the next receive address to avoid reuse.

| Argument | Description |
|----------|-------------|
| `<wallet-id>` | Wallet ID |

```bash
nunchuk wallet address get wallet_abc123
```

### `nunchuk wallet export <wallet-id>`

Export wallet descriptor or BSMS record for backup and recovery. Output is raw content suitable for piping to a file.

| Option | Default | Description |
|--------|---------|-------------|
| `--type <type>` | `descriptor` | Export type: `descriptor` or `bsms` |
| `--format <format>` | `internal` | Descriptor format: `internal` (BIP-389 `/<0;1>/*`) or `all` (`/0/*`). Only valid with `--type descriptor` |

```bash
# Export descriptor (default)
nunchuk wallet export wallet_abc123

# Export descriptor with external format
nunchuk wallet export wallet_abc123 --format all

# Export BSMS record
nunchuk wallet export wallet_abc123 --type bsms

# Save to file for recovery
nunchuk wallet export wallet_abc123 > wallet-backup.txt
nunchuk wallet export wallet_abc123 --type bsms > wallet-backup.bsms
```

### `nunchuk wallet rename <wallet-id>`

Rename a wallet locally. This only changes the local name; it does not update the server.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<wallet-id>` | Yes | Wallet ID |
| `--name <name>` | Yes | New wallet name |

```bash
nunchuk wallet rename wallet_abc123 --name "Savings Vault"
```

### `nunchuk wallet delete <wallet-id>`

Delete a wallet from the server and remove local data.

| Argument | Description |
|----------|-------------|
| `<wallet-id>` | Wallet ID |

```bash
nunchuk wallet delete wallet_abc123
```

### `nunchuk wallet recover`

Recover a group wallet from a descriptor or BSMS 1.0 backup file. The command parses the file, derives the wallet's group ID, verifies the wallet exists on the server, calls the recover API, and saves the wallet locally.

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--file <path>` | Yes | — | Path to BSMS or descriptor backup file |
| `--name <name>` | No | `Group wallet` | Wallet name |

```bash
# Recover from a BSMS backup
nunchuk wallet recover --file wallet-backup.bsms

# Recover from a descriptor file with a custom name
nunchuk wallet recover --file descriptor.txt --name "Recovered Vault"
```

If the wallet already exists locally, the command returns without overwriting:
```json
{ "status": "already_exists", "wallet": { ... } }
```

### `nunchuk wallet platform-key get <wallet-id>`

Get current platform key policies for a finalized wallet.

| Argument | Description |
|----------|-------------|
| `<wallet-id>` | Wallet ID |

```bash
nunchuk wallet platform-key get w123
```

Output:
```
Policy Type:     Global
Auto Broadcast:  true
Signing Delay:   0s
Spending Limit:  500 USD / DAILY
```

### `nunchuk wallet platform-key update <wallet-id>`

Request a wallet platform key policy update. The request may apply immediately or may create a dummy transaction that needs approval signatures.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<wallet-id>` | Yes | Wallet ID |
| `--signer <xfp>` | No | Target signer fingerprint (per-key policy) |
| `--auto-broadcast` | No | Auto-broadcast after signing |
| `--signing-delay <duration>` | No | Delay before signing (`30s`, `15m`, `24h`, `7d`, or raw seconds) |
| `--limit-amount <amount>` | No | Spending limit amount |
| `--limit-currency <currency>` | No | Spending limit currency (`USD`, `BTC`, `sat`) |
| `--limit-interval <interval>` | No | Spending limit interval (`DAILY`, `WEEKLY`, `MONTHLY`, `YEARLY`) |
| `--policy-json <json>` | No | Full policy as JSON string |
| `--policy-file <path>` | No | Path to policy JSON file |

Use exactly one input mode:
- flags
- `--policy-json`
- `--policy-file`

Examples:

```bash
nunchuk wallet platform-key update w123 \
  --auto-broadcast --signing-delay 24h
```

```bash
nunchuk wallet platform-key update w123 \
  --signer 534a4a82 --limit-amount 100 --limit-currency USD --limit-interval DAILY
```

```bash
nunchuk wallet platform-key update w123 --policy-file policy.json
```

### `nunchuk wallet dummy-tx list <wallet-id>`

List pending dummy transactions. Dummy transactions are created by the server when a platform key policy change requires multi-sig approval.

| Argument | Description |
|----------|-------------|
| `<wallet-id>` | Wallet ID |

```bash
nunchuk wallet dummy-tx list w123
```

### `nunchuk wallet dummy-tx get <wallet-id>`

Get details of a specific dummy transaction, including old/new policies and signature status.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<wallet-id>` | Yes | Wallet ID |
| `--dummy-tx-id <id>` | Yes | Dummy transaction ID |

```bash
nunchuk wallet dummy-tx get w123 --dummy-tx-id 694364702230188032
```

Output:
```
ID:              694364702230188032
Type:            UPDATE_PLATFORM_KEY_POLICIES
Status:          PENDING_SIGNATURES
Signatures:      1/2

Old Policies:
  Policy Type:     Global
  Auto Broadcast:  true
  Signing Delay:   0s
  Spending Limit:  200 USD / DAILY

New Policies:
  Policy Type:     Global
  Auto Broadcast:  true
  Signing Delay:   0s
  Spending Limit:  500 USD / DAILY
```

### `nunchuk wallet dummy-tx sign <wallet-id>`

Sign a dummy transaction. Creates a dummy PSBT from the transaction's request body, signs it, and submits the signature to the server. If no key option is provided, auto-detects stored keys that match the wallet's signers and signs with all of them. Signers that have already signed are skipped.

If enough signatures are collected, the server applies the policy change and deletes the dummy transaction. The command will then display the updated policy.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<wallet-id>` | Yes | Wallet ID |
| `--dummy-tx-id <id>` | Yes | Dummy transaction ID |
| `--fingerprint <xfp>` | No | Fingerprint of a stored key |
| `--xprv <xprv>` | No | Extended private key for signing |

```bash
# Auto-sign with all matching stored keys
nunchuk wallet dummy-tx sign w123 \
  --dummy-tx-id 694364702230188032

# Sign with a specific stored key
nunchuk wallet dummy-tx sign w123 \
  --dummy-tx-id 694364702230188032 --fingerprint 73c5da0a

# Or provide xprv directly
nunchuk wallet dummy-tx sign w123 \
  --dummy-tx-id 694364702230188032 --xprv "tprv..."
```

### `nunchuk wallet dummy-tx cancel <wallet-id>`

Cancel a pending dummy transaction.

| Argument / Option | Required | Description |
|-------------------|----------|-------------|
| `<wallet-id>` | Yes | Wallet ID |
| `--dummy-tx-id <id>` | Yes | Dummy transaction ID |

```bash
nunchuk wallet dummy-tx cancel w123 --dummy-tx-id 694364702230188032
```

---

## Transaction Commands

Create, sign, and broadcast transactions.

### `nunchuk tx create`

Create a new transaction. Builds a PSBT locally and uploads to the group server for signer coordination.

| Option | Required | Description |
|--------|----------|-------------|
| `--wallet <wallet-id>` | Yes | Wallet ID |
| `--to <address>` | Yes | Recipient Bitcoin address |
| `--amount <value>` | Yes | Amount to send (default unit: sat) |
| `--currency <code>` | No | Currency for amount. Supports BTC, USD, and fiat codes |

Fee rate is automatically estimated from the Nunchuk API (with Electrum fallback).

```bash
nunchuk tx create --wallet w123 --to bc1q... --amount 100000
nunchuk tx create --wallet w123 --to bc1q... --amount 0.001 --currency BTC
nunchuk tx create --wallet w123 --to bc1q... --amount 50 --currency USD
```

### `nunchuk tx sign`

Sign a transaction. By default, this fetches the PSBT from the group server, signs matching inputs locally, and re-uploads the merged result. You can also pass `--psbt <base64>` to merge an externally signed PSBT into the current pending transaction. Upload only happens when the merge adds new data.

| Option | Required | Description |
|--------|----------|-------------|
| `--wallet <wallet-id>` | Yes | Wallet ID |
| `--tx-id <tx-id>` | Yes | Transaction ID |
| `--psbt <psbt>` | No | Signed PSBT to merge into the current pending transaction |
| `--fingerprint <xfp>` | No | Fingerprint of a stored key |
| `--xprv <xprv>` | No | Extended private key for signing |

```bash
# Auto-sign with all matching stored keys
nunchuk tx sign --wallet w123 --tx-id tx456

# Sign with a specific stored key
nunchuk tx sign --wallet w123 --tx-id tx456 --fingerprint 73c5da0a

# Or provide xprv directly
nunchuk tx sign --wallet w123 --tx-id tx456 --xprv "xprv..."

# Or merge an externally signed PSBT
nunchuk tx sign --wallet w123 --tx-id tx456 --psbt "cHNidP8B..."
```

### `nunchuk tx broadcast`

Broadcast a fully signed transaction to the network.

| Option | Required | Description |
|--------|----------|-------------|
| `--wallet <wallet-id>` | Yes | Wallet ID |
| `--tx-id <tx-id>` | Yes | Transaction ID |

```bash
nunchuk tx broadcast --wallet w123 --tx-id tx456
```

### `nunchuk tx list`

List transactions for a wallet.

| Option | Required | Description |
|--------|----------|-------------|
| `--wallet <wallet-id>` | Yes | Wallet ID |

```bash
nunchuk tx list --wallet w123
```

### `nunchuk tx get`

Get transaction details.

| Option | Required | Description |
|--------|----------|-------------|
| `--wallet <wallet-id>` | Yes | Wallet ID |
| `--tx-id <tx-id>` | Yes | Transaction ID |

```bash
nunchuk tx get --wallet w123 --tx-id tx456
```

---

## Key Commands

Generate and manage software signing keys (BIP39 mnemonics).

### `nunchuk key generate`

Generate a new BIP39 mnemonic and save to local storage. The mnemonic is displayed once — back it up securely.

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--name <name>` | No | `My key #N` | Name for the key |
| `--words <count>` | No | `24` | Number of words (12 or 24) |

```bash
nunchuk key generate
nunchuk key generate --name "Alice" --words 12
```

Output:
```
MNEMONIC (back up these words securely!):
  abandon abandon abandon ... about

Name:          Alice
Fingerprint:   73c5da0a

Key saved to local storage.
```

### `nunchuk key info`

Derive signer info (fingerprint, path, xpub, descriptor) from a stored key, mnemonic, or master xprv. Derivation is done on demand — the stored mnemonic can produce info for any address type.

| Option | Required | Default | Description |
|--------|----------|---------|-------------|
| `--fingerprint <xfp>` | Conditionally | — | Fingerprint of a stored key |
| `--mnemonic <words>` | Conditionally | — | BIP39 mnemonic (wrap in quotes) |
| `--xprv <xprv>` | Conditionally | — | BIP32 master extended private key |
| `--passphrase <passphrase>` | No | — | BIP39 passphrase (only with --mnemonic) |
| `--address-type <type>` | No | `NATIVE_SEGWIT` | Address type for derivation |
| `--path <path>` | No | — | Custom derivation path (overrides --address-type) |

Provide exactly one of `--fingerprint`, `--mnemonic`, or `--xprv`.

```bash
# Derive from a stored key
nunchuk key info --fingerprint 73c5da0a

# Derive with a different address type
nunchuk key info --fingerprint 73c5da0a --address-type TAPROOT

# Derive from a provided mnemonic
nunchuk key info --mnemonic "abandon abandon abandon ... about"

# Derive from a mnemonic with passphrase
nunchuk key info --mnemonic "abandon ..." --passphrase "secret"

# Derive at a custom path
nunchuk key info --fingerprint 73c5da0a --path "m/48'/0'/1'/2'"
```

Output:
```
Fingerprint:   73c5da0a
Network:       testnet
Address Type:  NATIVE_SEGWIT
Path:          m/48'/1'/0'/2'
Xpub:          tpub...
Descriptor:    [73c5da0a/48'/1'/0'/2']tpub...
```

### `nunchuk key list`

List locally stored keys for the current user and network.

```bash
nunchuk key list
```

Output:
```
name           fingerprint   createdAt
Alice          73c5da0a      2026-04-03T01:00:00.000Z
Bob            a1b2c3d4      2026-04-03T02:00:00.000Z
```

---

## Config Commands

Inspect stored session settings and manage the Electrum endpoint used for balance lookup, address gap scanning, transaction history, UTXO discovery, and broadcast.

### `nunchuk config show`

Show the active network config, including the masked API key, email pointer, ephemeral key status, and active Electrum server.

```bash
nunchuk config show
```

### `nunchuk config electrum get`

Show the Electrum server currently used for the selected network, whether it comes from a custom override or the built-in default, and the default endpoint for that network.

```bash
nunchuk config electrum get
```

### `nunchuk config electrum set <server>`

Persist a custom Electrum server for the selected network.

| Argument | Description |
|----------|-------------|
| `<server>` | Electrum endpoint in `host:port`, `tcp://host:port`, or `ssl://host:port` format |

If the protocol is omitted, the CLI probes `ssl://` first and then `tcp://`. The server is only saved if the Electrum connection and `server.version` handshake succeed.

```bash
nunchuk config electrum set ssl://mainnet.nunchuk.io:52002
nunchuk config electrum set mainnet.nunchuk.io:52002
nunchuk --network testnet config electrum set tcp://electrum.example.com:50001
```

### `nunchuk config electrum reset`

Remove the custom Electrum override for the selected network and fall back to the built-in default.

```bash
nunchuk config electrum reset
```

---

## Currency Commands

Currency conversion helpers using Nunchuk market rates.

### `nunchuk currency convert <amount> <from> <to>`

Convert between `BTC`, `sat`, `USD`, and fiat currencies using Nunchuk market rates.

| Argument | Description |
|----------|-------------|
| `<amount>` | Non-negative amount to convert |
| `<from>` | Source currency |
| `<to>` | Target currency |

Notes:
- `BTC`, `USD`, and fiat currencies are case-insensitive.
- `sat`, `sats`, `satoshi`, and `satoshis` are all accepted.
- Conversions use `https://api.nunchuk.io/v1.1/prices` and `https://api.nunchuk.io/v1.1/forex/rates`.

```bash
nunchuk currency convert 100 USD BTC
nunchuk currency convert 0.01 BTC VND
nunchuk currency convert 100000 sat USD
```

---

## Quick Start

```bash
# 1. Authenticate
nunchuk auth login

# 2. (Optional) Switch to testnet
nunchuk network set testnet

# 3. Generate a software signing key
nunchuk key generate --name "Alice"

# 4. Create a 2-of-3 multisig sandbox
nunchuk sandbox create --name "Team Vault" --m 2 --n 3

# 5. Share the sandbox ID with participants
# They run: nunchuk sandbox join <sandbox-id>

# 6. Add stored key to sandbox (auto-derives descriptor)
nunchuk sandbox add-key <sandbox-id> --slot 0 --fingerprint <xfp>

# 7. Finalize into an active wallet
nunchuk sandbox finalize <sandbox-id>

# 8. Create, sign, and broadcast a transaction
nunchuk tx create --wallet <wallet-id> --to bc1q... --amount 100000
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id>
nunchuk tx broadcast --wallet <wallet-id> --tx-id <tx-id>

# 9. View transaction history
nunchuk tx list --wallet <wallet-id>
```

---

## Output Formats

By default, the CLI outputs human-readable text. Use `--json` for machine-readable JSON output.

```bash
# Human-readable
nunchuk auth status
#   status: authenticated
#   apiKey: abc12345...6789

# JSON
nunchuk --json auth status
# {"status":"authenticated","apiKey":"abc12345...6789","ephemeralPub":"..."}
```

Errors are written to stderr and exit with code 1:

```bash
nunchuk --json sandbox create --name "" --m 3 --n 2
# stderr: {"error":"INVALID_PARAM","message":"m must be <= n"}
```
