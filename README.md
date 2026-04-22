# Nunchuk CLI

A command-line tool that lets AI agents use Bitcoin safely. Agents operate within group wallets and miniscript wallets where user keys retain ultimate control — transactions above policy limits require explicit user approval.

Built for integration with AI agent frameworks. See [agent-skills](https://github.com/nunchuk-io/agent-skills) for ready-made skills.

- ✅ Group Wallet (m-of-n multisig)
- ✅ Miniscript Wallet (native segwit; Taproot next phase)

## Prerequisites

- Node.js >= 18
- Nunchuk API key — generate one at the [Developer Portal](https://developer.nunchuk.io)

## Installation

```bash
npm install -g nunchuk-cli
```

### Development

```bash
git clone git@github.com:nunchuk-io/nunchuk-cli.git
cd nunchuk-cli
npm install
npm run build
npm link  # makes `nunchuk` available globally
```

## Quick Start

```bash
# Authenticate
nunchuk auth login

# Set network (mainnet or testnet)
nunchuk network set testnet

# Generate a software signing key
nunchuk key generate --name "Alice"

# Derive signer info for a stored key
nunchuk key info --fingerprint <xfp>

# List stored keys
nunchuk key list

# Authenticate separately on another network when needed
nunchuk --network mainnet auth login
nunchuk --network testnet auth login

# Create a 2-of-3 sandbox (defaults to NATIVE_SEGWIT)
nunchuk sandbox create --name "My Wallet" --m 2 --n 3

# Or create a native-segwit miniscript sandbox from a signer-name template
nunchuk sandbox create --name "Mini Wallet" \
  --miniscript-template "or_d(multi(2,key_0_0,key_1_0,key_2_0),and_v(v:pk(key_3_0),after(1785542400)))"

# Invite participants by email
nunchuk invitation send <sandbox-id> alice@example.com bob@example.com

# List your pending invitations
nunchuk invitation list

# Accept or deny an invitation
nunchuk invitation accept <invitation-id>
nunchuk invitation deny <invitation-id>

# Add stored key to sandbox (auto-derives descriptor)
nunchuk sandbox add-key <sandbox-id> --slot 0 --fingerprint <xfp>

# For miniscript sandboxes, use the signer names from the template as slots
nunchuk sandbox add-key <sandbox-id> --slot key_0_0 --fingerprint <xfp>

# Or provide the full signer descriptor directly
nunchuk sandbox add-key <sandbox-id> --slot 1 \
  --descriptor "[aabbccdd/48h/1h/0h/2h]tpubXXX"

# Or provide xpub + path manually
nunchuk sandbox add-key <sandbox-id> --slot 2 \
  --fingerprint aabbccdd \
  --xpub tpubXXX \
  --path "m/48h/1h/0h/2h"

# Finalize into an active wallet
nunchuk sandbox finalize <sandbox-id>

# View wallets
nunchuk wallet list

# View wallets without Electrum balance lookup
nunchuk wallet list --no-balance

# Get a fresh receive address
nunchuk wallet address get <wallet-id>

# Inspect or validate miniscript spending paths
nunchuk miniscript inspect --wallet <wallet-id>
nunchuk miniscript validate --wallet <wallet-id>

# Export wallet descriptor and BSMS for backup/recovery
nunchuk wallet export <wallet-id>

# Rename a wallet
nunchuk wallet rename <wallet-id> --name "New Name"

# Recover a wallet from backup
nunchuk wallet recover --file wallet-backup.txt

# Send bitcoin
nunchuk tx create --wallet <wallet-id> --to <address> --amount 100000
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id>
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id> --psbt <signed-psbt>
nunchuk tx broadcast --wallet <wallet-id> --tx-id <tx-id>

# For miniscript, optionally choose a path and attach required hash preimages
nunchuk tx create --wallet <wallet-id> --to <address> --amount 100000 --miniscript-path 0
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id> --preimage <32-byte-hex>

# View transaction history
nunchuk tx list --wallet <wallet-id>

# Enable platform key (auto-signing by Nunchuk backend)
nunchuk sandbox platform-key enable <sandbox-id>

# For miniscript, enable platform key for one or more named signer slots
nunchuk sandbox platform-key enable <sandbox-id> --slot key_3_0

# Set global policy with spending limit
nunchuk sandbox platform-key set-policy <sandbox-id> \
  --auto-broadcast --limit-amount 1000 --limit-currency USD --limit-interval DAILY

# Set per-signer policy
nunchuk sandbox platform-key set-policy <sandbox-id> \
  --signer <xfp> --auto-broadcast --signing-delay 1h

# Set policy via JSON (supports spendingLimit per signer)
nunchuk sandbox platform-key set-policy <sandbox-id> --policy-json '{
  "signers": [
    {
      "masterFingerprint": "534a4a82",
      "autoBroadcastTransaction": true,
      "signingDelaySeconds": 0,
      "spendingLimit": { "interval": "DAILY", "amount": "1000", "currency": "USD" }
    }
  ]
}'

# View platform key status
nunchuk sandbox platform-key get <sandbox-id>

# After finalization: view wallet platform key policies
nunchuk wallet platform-key get <wallet-id>

# Request a wallet platform key policy update
nunchuk wallet platform-key update <wallet-id> \
  --auto-broadcast --signing-delay 24h

# List pending dummy transactions (created when policy changes need approval)
nunchuk wallet dummy-tx list <wallet-id>

# Sign a dummy transaction to approve a policy change
nunchuk wallet dummy-tx sign <wallet-id> \
  --dummy-tx-id <id> --xprv <tprv...>
```

## Commands

For full command documentation, see [docs/cli-reference.md](docs/cli-reference.md).

### `auth`

| Command       | Description                                                           |
| ------------- | --------------------------------------------------------------------- |
| `auth login`  | Authenticate with API key (use `--api-key` for non-interactive login) |
| `auth status` | Show authentication status for the selected network                   |
| `auth logout` | Remove the stored API key for the selected network                    |

### `network`

| Command                 | Description                          |
| ----------------------- | ------------------------------------ |
| `network set <network>` | Set network (`mainnet` or `testnet`) |
| `network get`           | Show current network                 |

### `key`

| Command        | Description                                             |
| -------------- | ------------------------------------------------------- |
| `key generate` | Generate a new BIP39 mnemonic and save locally          |
| `key info`     | Derive signer info from a stored key, mnemonic, or xprv |
| `key list`     | List locally stored keys                                |

### `sandbox`

| Command                                | Description                                               |
| -------------------------------------- | --------------------------------------------------------- |
| `sandbox create`                       | Create a new multisig or native-segwit miniscript sandbox |
| `sandbox list`                         | List sandbox IDs                                          |
| `sandbox get <id>`                     | Get sandbox details from server                           |
| `sandbox join <id-or-url>`             | Join an existing sandbox by ID or URL                     |
| `sandbox add-key <id>`                 | Add a signer key to a slot                                |
| `sandbox finalize <id>`                | Finalize sandbox into an active wallet                    |
| `sandbox delete <id>`                  | Delete a sandbox                                          |
| `sandbox platform-key enable <id>`     | Enable platform key on a sandbox                          |
| `sandbox platform-key disable <id>`    | Disable platform key on a sandbox                         |
| `sandbox platform-key set-policy <id>` | Set platform key policies                                 |
| `sandbox platform-key get <id>`        | Get platform key status and policies                      |

### `invitation`

| Command                                    | Description                                        |
| ------------------------------------------ | -------------------------------------------------- |
| `invitation send <sandbox-id> <emails...>` | Invite participants by email                       |
| `invitation list [sandbox-id]`             | List invitations for the current user or a sandbox |
| `invitation accept <id>`                   | Accept an invitation and join its sandbox          |
| `invitation deny <id>`                     | Deny an invitation                                 |

### `wallet`

| Command                           | Description                                            |
| --------------------------------- | ------------------------------------------------------ |
| `wallet list`                     | List wallets                                           |
| `wallet get <id>`                 | Get wallet details                                     |
| `wallet address get <id>`         | Get a new receive address                              |
| `wallet export <id>`              | Export wallet descriptor and/or BSMS record            |
| `wallet delete <id>`              | Delete a wallet                                        |
| `wallet rename <id>`              | Rename a wallet locally                                |
| `wallet recover`                  | Recover a wallet from a descriptor or BSMS backup file |
| `wallet platform-key get <id>`    | Get platform key policies for a wallet                 |
| `wallet platform-key update <id>` | Request a platform key policy update                   |
| `wallet dummy-tx list <id>`       | List pending dummy transactions                        |
| `wallet dummy-tx get <id>`        | Get dummy transaction details                          |
| `wallet dummy-tx sign <id>`       | Sign a dummy transaction                               |
| `wallet dummy-tx cancel <id>`     | Cancel a dummy transaction                             |

### `miniscript`

| Command               | Description                                             |
| --------------------- | ------------------------------------------------------- |
| `miniscript inspect`  | Inspect miniscript spending paths                       |
| `miniscript validate` | Validate a miniscript wallet, descriptor, or expression |

### `tx`

| Command        | Description                                                                                   |
| -------------- | --------------------------------------------------------------------------------------------- |
| `tx create`    | Create a new transaction, optionally selecting miniscript path/preimages                      |
| `tx sign`      | Sign a transaction locally, attach miniscript preimages, or merge a signed PSBT with `--psbt` |
| `tx broadcast` | Broadcast a fully signed transaction                                                          |
| `tx list`      | List transactions for a wallet                                                                |
| `tx get`       | Get transaction details                                                                       |

#### `tx create`

```bash
nunchuk tx create --wallet <id> --to <address> --amount <sats>
nunchuk tx create --wallet <id> --to <address> --amount <sats> --miniscript-path 0
```

Fee rate is automatically estimated from the Nunchuk API.

#### `tx sign`

```bash
nunchuk tx sign --wallet <id> --tx-id <txid>                             # auto-detect
nunchuk tx sign --wallet <id> --tx-id <txid> --fingerprint <xfp>         # specific key
nunchuk tx sign --wallet <id> --tx-id <txid> --xprv <extended-private-key>
nunchuk tx sign --wallet <id> --tx-id <txid> --preimage <32-byte-hex>    # miniscript hash preimage
nunchuk tx sign --wallet <id> --tx-id <txid> --psbt <signed-psbt-base64> # merge signed PSBT
```

#### `tx broadcast`

```bash
nunchuk tx broadcast --wallet <id> --tx-id <txid>
```

### `config`

| Command                        | Description                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `config show`                  | Display current configuration                                                           |
| `config electrum get`          | Show the active Electrum server for the selected network                                |
| `config electrum set <server>` | Persist a custom Electrum server (`host:port`, `tcp://host:port`, or `ssl://host:port`) |
| `config electrum reset`        | Reset the Electrum server to the selected network default                               |

Mainnet now defaults to `ssl://mainnet.nunchuk.io:52002`.
When the protocol is omitted, the CLI tries `ssl://` first, then `tcp://`, and only saves the server if the Electrum connection succeeds.

### `currency`

| Command                                 | Description                                        |
| --------------------------------------- | -------------------------------------------------- |
| `currency convert <amount> <from> <to>` | Convert between BTC, sat, USD, and fiat currencies |

## Global Options

| Option                | Description                       |
| --------------------- | --------------------------------- |
| `--json`              | Output in JSON format             |
| `--api-key <key>`     | Override stored API key           |
| `--network <network>` | Override network for this command |

## Webhooks

Receive real-time HTTP notifications when events happen on your account. Configure webhook endpoints via the [Developer Portal](https://developer.nunchuk.io).

See [docs/portal-webhook-guide.md](docs/portal-webhook-guide.md) for setup instructions, destination types, and event payload reference.

## Project Structure

```
src/
  commands/         # CLI command definitions
    auth.ts         # Authentication commands
    config.ts       # Config and Electrum endpoint commands
    currency.ts     # Currency conversion commands
    invitation.ts   # Group invitation commands
    key.ts          # Key generation and derivation
    miniscript.ts   # Miniscript inspection and validation commands
    network.ts      # Network selection
    sandbox.ts      # Sandbox lifecycle (create, add-key, finalize, etc.)
    tx.ts           # Transaction commands (create, sign, broadcast, list, get)
    wallet.ts       # Wallet management and export
  core/             # Business logic (importable as library)
    address-type.ts # Address type constants and labels
    address.ts      # Bitcoin address derivation (multisig and miniscript)
    api-client.ts   # HTTP client for Nunchuk API
    bip39.ts        # BIP39 mnemonic utilities
    config.ts       # Config file management (~/.nunchuk-cli/config.json)
    crypto.ts       # NaCl encryption (Publicbox, Secretbox)
    currency.ts     # Fiat/BTC/sat conversion helpers
    descriptor.ts   # Bitcoin output descriptor parsing/building + checksum
    electrum.ts     # Electrum protocol client
    fees.ts         # Fee estimation helpers
    format.ts       # Formatting utilities (BTC, sats, dates)
    keygen.ts       # BIP39 mnemonic generation and BIP32 key derivation
    miniscript.ts   # Miniscript parser, compiler, and descriptor helpers
    miniscript-finalize.ts # Miniscript witness finalization
    miniscript-preimage.ts # Miniscript hash-preimage requirements
    miniscript-spend.ts    # Miniscript spending path analysis
    multisig-config.ts # Multisig config export/recovery helpers
    paths.ts        # BIP32 derivation path helpers
    platform-key.ts # Platform key types, validation, policy builders
    psbt-sign.ts    # Local PSBT signing helpers
    sandbox.ts      # Sandbox event builders (create, add-key, finalize, platform-key)
    signer-key.ts   # Signer key parsing and matching
    storage.ts      # Local encrypted per-account SQLite storage (sandboxes, wallets, keys)
    transaction.ts  # Transaction operations (create, upload, fetch, broadcast)
    wallet-keys.ts  # BIP32/BIP85 key derivation (Secretbox key, GID, signing)
    wallet.ts       # Wallet metadata helpers
  index.ts          # CLI entry point
  output.ts         # Output formatting (human-readable / JSON)
```

## Development

```bash
# Run in dev mode (no build needed)
npm run dev -- auth status

# Type check
npm run typecheck

# Lint
npm run lint

# Format
npm run format

# Build
npm run build
```

## License

[MIT](LICENSE) — Copyright Nunchuk.
