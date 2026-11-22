"""Compare confirmed transactions involving user-supplied wallet addresses."""
import asyncio
from bisect import bisect_left
from collections import defaultdict

from app.services.wallet_monitoring import WalletSourceError, _history, normalize_address

MAX_TRACE_PATHS = 1000


class WalletTraceLimitError(Exception):
    pass


def _tron_transfer(record: dict, *, require_timestamp: bool = False) -> dict:
    value = record.get("value")
    if (not isinstance(value, str) or not value.isascii() or not value.isdecimal()
            or record["token_info"].get("decimals") != 6):
        raise WalletSourceError("TronGrid returned an invalid USDT transfer amount")
    timestamp = record.get("block_timestamp")
    if require_timestamp and (type(timestamp) is not int or timestamp < 0):
        raise WalletSourceError("TronGrid returned an invalid transfer timestamp")
    txid = record["transaction_id"]
    return {
        "transaction_id": txid, "from": record["from"], "to": record["to"],
        "amount_base_units": value, "decimals": 6, "block_timestamp_ms": timestamp,
        "source_url": f"https://tronscan.org/#/transaction/{txid}",
    }


def _transfer_key(item: dict) -> tuple:
    return item["transaction_id"], item["from"], item["to"], item["amount_base_units"]


async def compare_wallets(chain: str, addresses: list[str]) -> dict:
    async def collect():
        histories = []
        for address in addresses:
            histories.extend(await _history(chain, address))
        return histories

    try:
        histories = await asyncio.wait_for(collect(), timeout=600)
    except TimeoutError as exc:
        raise WalletSourceError("Wallet comparison timed out") from exc
    selected = set(addresses)
    if chain == "btc":
        transactions = {}
        for record in histories:
            txid = record["txid"]
            if txid in transactions and transactions[txid] != record:
                raise WalletSourceError("Blockstream returned inconsistent transaction records")
            transactions[txid] = record
        matches = []
        for txid, transaction in transactions.items():
            inputs = _bitcoin_addresses(transaction.get("vin"), selected, inputs=True)
            outputs = _bitcoin_addresses(transaction.get("vout"), selected, inputs=False)
            if not any(sender != receiver for sender in inputs for receiver in outputs):
                continue
            matches.append({
                "transaction_id": txid,
                "inputs": [{"address": address, "satoshis": amount} for address, amount in sorted(inputs.items())],
                "outputs": [{"address": address, "satoshis": amount} for address, amount in sorted(outputs.items())],
                "block_time": transaction["status"].get("block_time"),
                "source_url": f"https://blockstream.info/tx/{txid}",
            })
        matches.sort(key=lambda item: item["transaction_id"])
        return {
            "chain": chain, "addresses": addresses, "matches": matches,
            "notice": (
                "Bitcoin matches show selected inputs and outputs in the same confirmed transaction, "
                "not proof that any specific input funded any specific output or that addresses share an owner. "
                "Fees, change, shared transactions and unrelated participants can make attribution ambiguous. "
                "No match does not prove that no connection exists."
            ),
        }

    matches = {}
    for record in histories:
        sender, receiver = record["from"], record["to"]
        if sender == receiver or sender not in selected or receiver not in selected:
            continue
        item = _tron_transfer(record)
        key = _transfer_key(item)
        if key in matches and matches[key] != item:
            raise WalletSourceError("TronGrid returned inconsistent transfer records")
        matches[key] = item
    return {
        "chain": chain, "addresses": addresses, "matches": [matches[key] for key in sorted(matches)],
        "notice": (
            "Matches are confirmed USDT transfer records between the supplied addresses, not proof of ownership. "
            "Identical transfer records in one transaction are collapsed because the provider does not supply "
            "an event index; do not use them to calculate totals. No match does not prove no connection exists."
        ),
    }


async def trace_usdt_paths(source: str, destination: str) -> dict:
    async def collect():
        return (
            await _history("usdt_trc20", source),
            await _history("usdt_trc20", destination),
        )

    try:
        source_history, destination_history = await asyncio.wait_for(collect(), timeout=600)
    except TimeoutError as exc:
        raise WalletSourceError("Wallet trace timed out") from exc

    outgoing: dict[tuple, dict] = {}
    incoming: dict[tuple, dict] = {}
    for history, expected, direction, result in (
        (source_history, source, "from", outgoing),
        (destination_history, destination, "to", incoming),
    ):
        for record in history:
            if record.get(direction) != expected:
                continue
            other = record.get("to" if direction == "from" else "from")
            try:
                if not isinstance(other, str) or normalize_address("usdt_trc20", other) != other:
                    raise ValueError("Invalid address")
            except ValueError as exc:
                raise WalletSourceError("TronGrid returned an invalid transfer address") from exc
            item = _tron_transfer(record, require_timestamp=True)
            key = _transfer_key(item)
            if key in result and result[key] != item:
                raise WalletSourceError("TronGrid returned inconsistent transfer records")
            result[key] = item

    paths = []
    direct_outgoing = {key: item for key, item in outgoing.items() if item["to"] == destination}
    direct_incoming = {key: item for key, item in incoming.items() if item["from"] == source}
    if direct_outgoing != direct_incoming:
        raise WalletSourceError("TronGrid returned inconsistent histories for the supplied addresses")

    def add_path(legs: list[dict]) -> None:
        if len(paths) >= MAX_TRACE_PATHS:
            raise WalletTraceLimitError(f"More than {MAX_TRACE_PATHS} paths match; no partial result was returned")
        paths.append({
            "transfers": legs,
            "same_timestamp_order_unknown": (
                len(legs) == 2 and legs[0]["block_timestamp_ms"] == legs[1]["block_timestamp_ms"]
            ),
        })

    for item in direct_outgoing.values():
        add_path([item])

    onward = defaultdict(list)
    for item in incoming.values():
        if item["from"] not in {source, destination}:
            onward[item["from"]].append(item)
    for items in onward.values():
        items.sort(key=lambda item: (item["block_timestamp_ms"], _transfer_key(item)))
    onward_times = {address: [item["block_timestamp_ms"] for item in items]
                    for address, items in onward.items()}

    for first in outgoing.values():
        intermediary = first["to"]
        if intermediary in {source, destination} or intermediary not in onward:
            continue
        items = onward[intermediary]
        start = bisect_left(onward_times[intermediary], first["block_timestamp_ms"])
        for second in items[start:]:
            add_path([first, second])
    paths.sort(key=lambda path: tuple(
        (leg["block_timestamp_ms"], _transfer_key(leg)) for leg in path["transfers"]
    ))
    return {
        "source_address": source, "destination_address": destination, "paths": paths,
        "notice": (
            "Paths show confirmed transfer records, not proof the same funds flowed through an intermediary "
            "or that addresses share an owner. Transfers with identical timestamps have unknown order. "
            "Identical events within one transaction are collapsed because no event index is available; "
            "do not calculate totals from these paths. Missing paths do not prove no connection exists."
        ),
    }


def _bitcoin_addresses(items: object, selected: set[str], *, inputs: bool) -> dict[str, int]:
    if not isinstance(items, list):
        raise WalletSourceError("Blockstream returned incomplete transaction inputs or outputs")
    amounts: dict[str, int] = {}
    for item in items:
        if not isinstance(item, dict):
            raise WalletSourceError("Blockstream returned an invalid transaction input or output")
        if inputs:
            output = item.get("prevout")
            if output is None and item.get("is_coinbase") is True:
                continue
        else:
            output = item
        if not isinstance(output, dict):
            raise WalletSourceError("Blockstream returned an incomplete previous output")
        address = output.get("scriptpubkey_address")
        if address is not None and not isinstance(address, str):
            raise WalletSourceError("Blockstream returned an invalid output address")
        if isinstance(address, str) and address.lower().startswith("bc1"):
            address = address.lower()
        if address in selected:
            value = output.get("value")
            if type(value) is not int or value < 0:
                raise WalletSourceError("Blockstream returned an invalid output value")
            amounts[address] = amounts.get(address, 0) + value
    return amounts
