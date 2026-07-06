# Nunchuk CLI

A command-line tool that lets AI agents use Bitcoin safely. Agents operate within group wallets and miniscript wallets where user keys retain ultimate control — transactions above policy limits require explicit user approval.

Built for integration with AI agent frameworks. See [agent-skills](https://github.com/nunchuk-io/agent-skills) for ready-made skills.

- ✅ Group Wallet (m-of-n multisig — native segwit, nested segwit, legacy, taproot)
- ✅ Miniscript Wallet (native segwit and taproot/tapscript)

## Prerequisites

- Node.js >= 20
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

# Show the current chain tip height and block time
nunchuk network tip

# Generate a software signing key
nunchuk key generate --name "Alice"

# Import an existing BIP39 mnemonic
nunchuk key import --name "Alice Backup" <bip39 words>

# Derive signer info for a stored key
nunchuk key info --fingerprint <xfp>

# List stored keys
nunchuk key list

# Authenticate separately on another network when needed
nunchuk --network mainnet auth login
nunchuk --network testnet auth login

# Create a 2-of-3 sandbox (defaults to NATIVE_SEGWIT)
nunchuk sandbox create --name "My Wallet" --m 2 --n 3

# Taproot multisig
nunchuk sandbox create --name "TR Wallet" --m 2 --n 3 --address-type TAPROOT

# Or create a native-segwit miniscript sandbox from a signer-name template
nunchuk sandbox create --name "Mini Wallet" \
  --miniscript-template "or_d(multi(2,key_0_0,key_1_0,key_2_0),and_v(v:pk(key_3_0),after(1785542400)))"

# Taproot miniscript (tapscript tree using multi_a)
nunchuk sandbox create --name "TR Mini Wallet" --address-type TAPROOT \
  --miniscript-template "{multi_a(2,key_0_0,key_1_0,key_2_0),and_v(v:multi_a(1,key_0_1,key_1_1,key_2_1),after(1785542400))}"

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

# Taproot multisig: enable a MuSig2 key path over exactly m signers
# (omit --value-key-set for a script-path-only taproot wallet)
nunchuk sandbox finalize <sandbox-id> --value-key-set 0,1

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

# Taproot: force a script-path spend (key path is the default)
nunchuk tx create --wallet <wallet-id> --to <address> --amount 100000 --taproot-script-path
# Taproot multisig (MuSig2) needs two signing rounds — run tx sign twice
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id>   # publishes nonces
nunchuk tx sign --wallet <wallet-id> --tx-id <tx-id>   # adds partial signatures

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
| `network tip`           | Show current chain tip height/time   |

### `key`

| Command        | Description                                             |
| -------------- | ------------------------------------------------------- |
| `key generate` | Generate a new BIP39 mnemonic and save locally          |
| `key import`   | Import an existing BIP39 mnemonic and save locally      |
| `key info`     | Derive signer info from a stored key, mnemonic, or xprv |
| `key list`     | List locally stored keys                                |

### `sandbox`

| Command                                | Description                                               |
| -------------------------------------- | --------------------------------------------------------- |
| `sandbox create`                       | Create a new multisig or miniscript sandbox (native segwit or taproot) |
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
| `wallet replace create <id>`      | Create a replacement sandbox for a wallet              |
| `wallet replace list <id>`        | List replacement sandboxes for a wallet                |
| `wallet replace accept <id> <gid>`  | Accept and join a replacement sandbox                  |
| `wallet replace decline <id> <gid>` | Decline a replacement sandbox locally                  |
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
| `tx draft`     | Preview a transaction (fee, total, change, input coins) without creating it                    |
| `tx sign`      | Sign a transaction locally, attach miniscript preimages, or merge a signed PSBT with `--psbt` |
| `tx broadcast` | Broadcast a fully signed transaction                                                          |
| `tx list`      | List transactions for a wallet                                                                |
| `tx get`       | Get transaction details                                                                       |
| `tx fees`      | Show current recommended fee rates (priority / standard / economy)                            |

#### `tx create`

```bash
nunchuk tx create --wallet <id> --to <address> --amount <sats>
nunchuk tx create --wallet <id> --to <address> --amount <sats> --miniscript-path 0
nunchuk tx create --wallet <id> --to <address> --amount <sats> --taproot-script-path  # taproot script-path spend
nunchuk tx create --wallet <id> --to <address> --amount <sats> --fee-rate 1.5          # manual fee rate (sat/vB, fractional ok)
nunchuk tx create --wallet <id> --to <address> --amount <sats> --fee-level priority    # auto-estimate at a fee level
nunchuk tx create --wallet <id> --to <address> --amount <sats> --anti-fee-sniping      # pin nLockTime to the chain tip
nunchuk tx create --wallet <id> --to <address> --amount <sats> --subtract-fee          # recipient pays the fee
nunchuk tx create --wallet <id> --to <address> --send-all                              # sweep the entire balance
nunchuk tx create --wallet <id> --to <address> --amount <sats> --coin <txid:vout> --coin <txid:vout>  # manual coin selection
nunchuk tx create --wallet <id> --to <address> --amount <sats> --from-tag kyc          # auto-select only from tagged coins
nunchuk tx create --wallet <id> --to <address> --amount <sats> --change-tags none      # don't tag the change coin
```

Fee rate is automatically estimated from the Nunchuk API, or set manually with `--fee-rate <sat/vB>`. When auto-estimating, the **level** is `--fee-level <economy|standard|priority>` (one-shot), else the account's saved default (`config fee-rate set`), else `economy`; `--fee-rate` overrides the level. Run [`tx fees`](#tx-fees) to see the current rates for each level. For taproot wallets the key path (MuSig2 aggregate) is used by default; `--taproot-script-path` forces a tapscript spend.

`--anti-fee-sniping` pins the transaction's `nLockTime` to the current block height so the transaction has no fee-sniping advantage over a competitor at the same height. A spending path's own absolute locktime (an `after` / OP_CHECKLOCKTIMEVERIFY condition) always takes precedence; the flag only fills a locktime that would otherwise be 0.

`--subtract-fee` takes the network fee out of the send amount instead of adding it on top, so the recipient receives `amount - fee` and the wallet's total spend stays at `amount`. The output shows the reduced `Recipient receives` value. The send fails if the amount cannot cover the fee or the recipient would drop below the dust threshold.

`--send-all` sweeps the entire wallet balance to the recipient — it spends every coin, forces `--subtract-fee` on (recipient receives `balance - fee`), and leaves no change. Use it instead of `--amount` (exactly one is required); if both are given, `--amount` is ignored with a warning.

`--coin <txid:vout>` (repeatable) selects coins manually: the transaction spends **exactly** the chosen coins — no subset optimization, no automatic top-up (a shortfall fails with insufficient funds). Explicitly chosen coins are spent even when locked. Combined with `--send-all`, only the chosen coins are swept. Cannot be combined with `--from-tag`.

`--from-tag <name>` restricts automatic coin selection to coins carrying that tag (case-sensitive). Locked coins stay excluded within the filtered pool.

`--change-tags <tags>` decides which tags the change coin inherits. By default the change coin inherits **all** tags carried by the input coins; pass `none` to inherit nothing, or a comma-separated subset of the input coins' tags (e.g. `--change-tags kyc,cold`). The choice is stored locally and applied when the change coin appears in a later scan or broadcast — see [`coin tag`](#coin) for how tags work.

#### `tx fees`

```bash
nunchuk tx fees
```

Shows the current recommended fee rates (priority / standard / economy) from the Nunchuk API, in sat/vB, marking the account's default level. Same source as the auto-estimate; no wallet required.

#### `tx draft`

```bash
nunchuk tx draft --wallet <id> --to <address> --amount <sats>
nunchuk tx draft --wallet <id> --to <address> --amount <sats> --fiat USD
```

Previews a transaction the way `tx create` would build it — recipient, estimated fee, total amount, change, and the input coins (value + block date) — **without** creating or uploading anything. Takes the same options as `tx create`, plus `--fiat <code>` to show fiat values alongside BTC. It calls the same builder as `tx create`, so the numbers match; when no `--fee-rate` is given the fee is auto-estimated and may change before you run `tx create` (pass `--fee-rate` to lock it).

#### `tx sign`

```bash
nunchuk tx sign --wallet <id> --tx-id <txid>                             # auto-detect
nunchuk tx sign --wallet <id> --tx-id <txid> --fingerprint <xfp>         # specific key
nunchuk tx sign --wallet <id> --tx-id <txid> --xprv <extended-private-key>
nunchuk tx sign --wallet <id> --tx-id <txid> --preimage <32-byte-hex>    # miniscript hash preimage
nunchuk tx sign --wallet <id> --tx-id <txid> --psbt <signed-psbt-base64> # merge signed PSBT
```

Taproot multisig spends use **MuSig2** and need two signing rounds: the first `tx sign` publishes the signer's nonce (`PENDING_NONCE` → `PENDING_SIGNATURES`), the second produces its partial signature (`READY_TO_BROADCAST`). Taproot miniscript (`multi_a`) and non-taproot wallets sign in one pass.

#### `tx broadcast`

```bash
nunchuk tx broadcast --wallet <id> --tx-id <txid>
```

### `coin`

| Command                  | Description                                                          |
| ------------------------ | -------------------------------------------------------------------- |
| `coin list`              | List a wallet's UTXOs (coins) with status, lock, tags, collections   |
| `coin lock` / `unlock`   | Exclude a coin from (or return it to) automatic coin selection       |
| `coin tag …`             | Manage tags: `create`, `list`, `get`, `rename`, `delete`, `add`, `remove`   |
| `coin collection …`      | Manage collections: `create`, `update`, `list`, `get`, `delete`, `add`, `remove` |

#### `coin list`

```bash
nunchuk coin list --wallet <id>
nunchuk coin list --wallet <id> --status CONFIRMED
nunchuk coin list --wallet <id> --tag kyc            # only coins carrying #kyc
nunchuk coin list --wallet <id> --untagged           # only coins with no tags
nunchuk coin list --wallet <id> --collection "Exchange A"
nunchuk --json coin list --wallet <id>
```

Lists the wallet's unspent outputs from Electrum with a derived status (`CONFIRMED`, `INCOMING_PENDING_CONFIRMATION`, `OUTGOING_PENDING_SIGNATURES`, `OUTGOING_PENDING_BROADCAST`) — outgoing statuses come from pending PSBTs on the group server. Each coin shows its outpoint, address, amount, status, confirmations, the received date-time (local time, from its confirmation block), a change flag, a `[locked]` marker, and its tags and collections.

#### `coin lock` / `coin unlock`

```bash
nunchuk coin lock --wallet <id> --coin <txid:vout>
nunchuk coin unlock --wallet <id> --coin <txid:vout>
```

A locked coin is never used by automatic coin selection (including `--send-all`). Selecting it explicitly with `tx create --coin` still spends it — the lock guards against accidental use, not deliberate use. `--coin` is repeatable here (and on `coin tag add/remove`, `coin collection add/remove`) to act on several coins at once.

#### `coin tag`

```bash
nunchuk coin tag create kyc --wallet <id>
nunchuk coin tag list --wallet <id>
nunchuk coin tag get kyc --wallet <id>              # member coins + spendable total
nunchuk coin tag rename kyc --wallet <id> --name kyc-verified
nunchuk coin tag delete kyc --wallet <id>
nunchuk coin tag add kyc --wallet <id> --coin <txid:vout>
nunchuk coin tag remove kyc --wallet <id> --coin <txid:vout>
```

Tags are reusable labels for classifying coins (for example by source: `kyc`, `exchange-a`, `payroll`), matching the mobile app's coin tags. Names are **case-sensitive** (`KYC` and `kyc` are different tags), contain no whitespace, and a leading `#` on input is accepted and stripped. Use them to scope spending (`tx create --from-tag`), filter listings (`coin list --tag`), and drive collection rules. `--coin` is repeatable to tag several coins in one command; list a tag's coins with `coin list --tag <name>`. Deleting a tag removes it from every coin.

#### `coin collection`

```bash
nunchuk coin collection create "Exchange A" --wallet <id>
nunchuk coin collection create quarantine --wallet <id> --add-untagged --auto-lock
nunchuk coin collection create verified --wallet <id> --add-tag kyc --apply-to-existing
nunchuk coin collection update quarantine --wallet <id> --no-auto-lock
nunchuk coin collection list --wallet <id>
nunchuk coin collection get quarantine --wallet <id>   # rules + member coins + spendable total
nunchuk coin collection delete quarantine --wallet <id>
nunchuk coin collection add "Exchange A" --wallet <id> --coin <txid:vout>
nunchuk coin collection remove "Exchange A" --wallet <id> --coin <txid:vout>
```

Collections are named groups of coins with optional membership rules, matching the mobile app's collection settings. Names are case-sensitive and may contain spaces. Rules:

- `--add-untagged` — new coins that arrive without tags join the collection automatically.
- `--add-tag <tag>` (repeatable) — coins join when they receive one of these tags.
- `--auto-lock` — coins are locked the moment they join (a quarantine posture: combined with `--add-untagged`, every unclassified inbound coin is locked until reviewed).
- `--apply-to-existing` — one-shot: run the rules over currently known coins now.

Rule semantics follow the app: membership applies on arrival and is never re-evaluated or auto-removed — removing a tag keeps the coin in the collection, deleting a collection keeps its locks. Rules are evaluated when the CLI next sees the wallet's coins (`coin list`, `tx create`, `tx draft`, `tx broadcast`); there is no background daemon.

#### Change-coin tag inheritance

When `tx create` produces change from tagged inputs, the change coin inherits the inputs' tags by default (`--change-tags` selects a subset or `none`). The choice is stored locally keyed by the change address and applied automatically when the change coin is next seen — regardless of whether the transaction was broadcast by the CLI, the app, or the backend. An inherited-tag change coin joins tag-rule collections but never `--add-untagged` collections.

### `config`

| Command                        | Description                                                                             |
| ------------------------------ | --------------------------------------------------------------------------------------- |
| `config show`                  | Display current configuration                                                           |
| `config electrum get`          | Show the active Electrum server for the selected network                                |
| `config electrum set <server>` | Persist a custom Electrum server (`host:port`, `tcp://host:port`, or `ssl://host:port`) |
| `config electrum reset`        | Reset the Electrum server to the selected network default                               |
| `config fee-rate get`          | Show the active account's default fee level (`economy`/`standard`/`priority`)           |
| `config fee-rate set <level>`  | Save the default fee level for the active account (per account, network-independent)    |
| `config fee-rate reset`        | Remove the saved default fee level (falls back to `economy`)                            |

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
