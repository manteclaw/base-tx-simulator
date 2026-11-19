# base-tx-simulator

Simulate a Base transaction via `eth_call` / `eth_estimateGas` **before**
you sign it — a pre-flight check, not a scam detector.

## Who it's for

Anyone signing Base transactions who wants a quick read-only check before
they approve: is the destination a contract or an EOA, does the call
revert, and does the gas estimate look sane?

## Install

```bash
git clone https://github.com/manteclaw/base-tx-simulator.git
cd base-tx-simulator
python3 -m pip install -r requirements.txt
```

Requires Python 3.8+. Only dependency is `requests`.

## Setup

No API key needed — it defaults to the public Base RPC
(`https://mainnet.base.org`). To use your own endpoint instead:

```bash
export BASE_RPC_URL=https://your-node-or-provider
# or, to use Alchemy:
export ALCHEMY_API_KEY=your-key
```

## Usage

Simulate a plain ETH transfer:

```bash
python3 simulate-tx.py simple --from 0xYourAddress --to 0xDestination --value 0.01
```

Simulate a contract call:

```bash
python3 simulate-tx.py contract --from 0xYourAddress --to 0xContract --data 0xa9059cbb... --value 0
```

Example output for a clean transfer:

```text
Simulating ETH transfer:
   From: 0xYourAddress
   To:   0xDestination
   Value: 0.01 ETH (10000000000000000 wei)
   Destination is an EOA (no contract code)
   Gas estimate: 21,000 (1.0x standard transfer)
   Simulation result: 0x

SIMULATION PASSED — transaction appears safe (see limits below)
```

Exit code is `0` when the simulation passes, `1` when it fails, reverts,
or trips a heuristic.

## What it checks

- **Destination type** — EOA vs contract (`eth_getCode`).
- **Bytecode heuristics** — very short code, `SELFDESTRUCT` opcode, heavy
  `DELEGATECALL` usage. These run on decoded bytes, not hex substrings.
- **Gas estimate** — flags estimates far above a standard transfer.
- **Simulation** — `eth_call` to catch reverts before you sign.

## Honest limits

- **This is not a scam detector.** The heuristics are thin: there is no
  scam-label source behind them, no honeypot simulation, and no
  token-approval analysis. A clean result means "the call did not revert
  and nothing in these cheap checks tripped" — nothing more.
- A malicious contract can pass every check here and still drain an
  approval. Always verify a contract through independent sources (block
  explorer, project docs, audit reports) before approving a transaction.
- `eth_call` simulates against the latest block; state can change between
  simulation and signing.
- The public RPC default is rate-limited and shared; run your own node or
  a provider key for heavy use.

## License

MIT — see `LICENSE`.
