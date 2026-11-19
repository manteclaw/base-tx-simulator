#!/usr/bin/env python3
"""
Transaction Simulator — simulate a Base transaction before signing.

Pre-flight check: runs eth_call / eth_estimateGas against a Base RPC node
and flags a few cheap bytecode heuristics on the destination contract.
It does NOT detect scams. A clean result means "the call did not revert
and nothing in these thin checks tripped" — nothing more. Always verify
a contract through independent sources before approving a transaction.

Usage:
    python3 simulate-tx.py simple --from <addr> --to <addr> --value <eth>
    python3 simulate-tx.py contract --from <addr> --to <addr> --data <hex> [--value <eth>]

RPC endpoint (first set wins):
    BASE_RPC_URL env var, else an Alchemy key via ALCHEMY_API_KEY,
    else the public Base RPC (https://mainnet.base.org).
"""
import os
import sys

import requests

# Public Base RPC is the default. Set BASE_RPC_URL to point at your own
# node / provider, or ALCHEMY_API_KEY to use Alchemy.
BASE_RPC = os.getenv("BASE_RPC_URL", "")
if not BASE_RPC:
    alchemy_key = os.getenv("ALCHEMY_API_KEY", "")
    BASE_RPC = (
        f"https://base-mainnet.g.alchemy.com/v2/{alchemy_key}"
        if alchemy_key
        else "https://mainnet.base.org"
    )


def _rpc(method: str, params: list, timeout: int = 15) -> dict:
    """One JSON-RPC call. Returns the decoded response, or {"error": ...}."""
    payload = {"jsonrpc": "2.0", "method": method, "params": params, "id": 1}
    try:
        r = requests.post(BASE_RPC, json=payload, timeout=timeout)
        return r.json()
    except Exception as e:  # noqa: BLE001 - surface as a plain error string
        return {"error": str(e)}


def get_contract_code(address: str) -> str:
    """Deployed bytecode at address ("0x" for an EOA)."""
    result = _rpc("eth_getCode", [address, "latest"], timeout=10)
    if "error" in result:
        print(f"RPC error fetching code: {result['error']}")
        return "0x"
    return result.get("result", "0x")


def simulate_eth_call(tx: dict) -> dict:
    """eth_call simulation (read-only, no state change)."""
    return _rpc("eth_call", [tx, "latest"])


def estimate_gas(tx: dict) -> dict:
    """eth_estimateGas for the transaction."""
    return _rpc("eth_estimateGas", [tx])


def check_honeypot_heuristics(bytecode: str) -> list:
    """Cheap bytecode heuristics. Thin by design — see module docstring.

    Checks run on decoded bytes, not hex substrings, so a byte value
    appearing as part of another value does not trip them.
    """
    alerts = []
    if bytecode == "0x":
        return alerts  # EOA, not a contract
    try:
        code = bytes.fromhex(bytecode[2:])
    except ValueError:
        return ["Contract code is not valid hex — cannot inspect it"]

    if len(code) < 50:
        alerts.append("Contract code unusually short — possible proxy/minimal contract")
    if b"\xff" in code:
        alerts.append("Contract contains SELFDESTRUCT opcode — it can vanish")
    delegatecall_count = code.count(b"\xf4")
    if delegatecall_count > 5:
        alerts.append(
            f"Heavy DELEGATECALL usage ({delegatecall_count}x) — possible drainer pattern"
        )
    return alerts


def simulate_simple_transfer(from_addr: str, to_addr: str, value_eth: float) -> int:
    """Simulate a simple ETH transfer."""
    value_wei = int(value_eth * 1e18)
    tx = {
        "from": from_addr,
        "to": to_addr,
        "value": hex(value_wei),
        "data": "0x",
    }

    print("\nSimulating ETH transfer:")
    print(f"   From: {from_addr}")
    print(f"   To:   {to_addr}")
    print(f"   Value: {value_eth} ETH ({value_wei} wei)")

    code = get_contract_code(to_addr)
    if code != "0x":
        print("   Destination is a CONTRACT (not an EOA)")
        heuristics = check_honeypot_heuristics(code)
        for h in heuristics:
            print(f"      ! {h}")
        if heuristics:
            print("\n   TRANSFER BLOCKED: destination contract has suspicious characteristics")
            return 1
    else:
        print("   Destination is an EOA (no contract code)")

    gas_est = estimate_gas(tx)
    if "error" in gas_est:
        print(f"   Gas estimation failed: {gas_est['error']}")
        return 1
    gas = int(gas_est.get("result", "0x0"), 16)
    print(f"   Gas estimate: {gas:,} ({gas / 21000:.1f}x standard transfer)")
    if gas > 50000:
        print("   Gas unusually high for a simple transfer — possible hidden contract interaction")

    sim = simulate_eth_call(tx)
    if "error" in sim:
        print(f"   Simulation failed: {sim['error']}")
        return 1

    print(f"   Simulation result: {sim.get('result', '0x')}")
    print("\nSIMULATION PASSED — transaction appears safe (see limits in README)")
    return 0


def simulate_contract_call(from_addr: str, to_addr: str, data: str, value_eth: float = 0) -> int:
    """Simulate a contract call."""
    value_wei = int(value_eth * 1e18)
    tx = {
        "from": from_addr,
        "to": to_addr,
        "value": hex(value_wei),
        "data": data,
    }

    print("\nSimulating contract interaction:")
    print(f"   From: {from_addr}")
    print(f"   To:   {to_addr}")
    print(f"   Data: {data[:66]}...")
    print(f"   Value: {value_eth} ETH")

    code = get_contract_code(to_addr)
    if code == "0x":
        print("   Target has NO contract code — this call will revert")
        return 1

    for h in check_honeypot_heuristics(code):
        print(f"   ! {h}")

    gas_est = estimate_gas(tx)
    if "error" in gas_est:
        print(f"   Gas estimation failed: {gas_est['error']}")
        return 1
    gas = int(gas_est.get("result", "0x0"), 16)
    print(f"   Gas estimate: {gas:,}")

    sim = simulate_eth_call(tx)
    if "error" in sim:
        print(f"   Simulation REVERTED: {sim['error']}")
        return 1

    print(f"   Simulation result: {sim.get('result', '0x')}")
    print("\nSIMULATION PASSED (see limits in README)")
    return 0


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage:")
        print("  python3 simulate-tx.py simple --from <addr> --to <addr> --value <eth>")
        print("  python3 simulate-tx.py contract --from <addr> --to <addr> --data <hex> [--value <eth>]")
        return 1

    cmd = sys.argv[1]
    args = {}
    i = 2
    while i < len(sys.argv):
        if sys.argv[i].startswith("--"):
            key = sys.argv[i][2:]
            val = sys.argv[i + 1] if i + 1 < len(sys.argv) else ""
            args[key] = val
            i += 2
        else:
            i += 1

    from_addr = args.get("from", "")
    to_addr = args.get("to", "")
    if not from_addr or not to_addr:
        print("--from and --to are required")
        return 1

    if cmd == "simple":
        return simulate_simple_transfer(from_addr, to_addr, float(args.get("value", "0")))
    if cmd == "contract":
        return simulate_contract_call(
            from_addr, to_addr, args.get("data", "0x"), float(args.get("value", "0"))
        )
    print(f"Unknown command: {cmd}")
    return 1


if __name__ == "__main__":
    sys.exit(main())
