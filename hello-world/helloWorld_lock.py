from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
)
from pycardano.hash import (
    TransactionId,
    ScriptHash,
)
import json

def read_validator() -> dict:
    with open("plutus.json", "r") as f:
        validator = json.load(f)
    script_bytes = PlutusV3Script(
        bytes.fromhex(validator["validators"][0]["compiledCode"])
    )
    script_hash = ScriptHash(bytes.fromhex(validator["validators"][0]["hash"]))
    return {
        "type": "PlutusV3",
        "script_bytes": script_bytes,
        "script_hash": script_hash,
    }

def lock(
    amount: int,
    into: ScriptHash,
    datum: PlutusData,
    context: BlockFrostChainContext,
) -> TransactionId:

    sk = PaymentSigningKey.load("./me.sk")
    vk = PaymentVerificationKey.from_signing_key(sk)
    network = Network.TESTNET
    input_address = Address(payment_part=vk.hash(), network=network)
    contract_address = Address(
        payment_part=into,
        network=Network.TESTNET,
    )

    builder = TransactionBuilder(context=context)
    builder.add_input_address(input_address)
    builder.add_output(
        TransactionOutput(
            address=contract_address,
            amount=amount,
            datum=datum,
        )
    )
    signed_tx = builder.build_and_sign(
        signing_keys=[sk],
        change_address=input_address,
    )

    return context.submit_tx(signed_tx)

@dataclass
class Datum(PlutusData):
    CONSTR_ID = 0
    owner: bytes
    content: bytes

context = BlockFrostChainContext(
    project_id="previewc3NRhWomtSTZ3p0MBCawyMxcbuOt4I5X",
    base_url="https://cardano-preview.blockfrost.io/api/",
)

validator = read_validator()

sk = PaymentSigningKey.load("./me.sk")
vk = PaymentVerificationKey.from_signing_key(sk)
owner = PaymentVerificationKey.from_signing_key(sk).hash()

datum = Datum(
    owner=owner.to_primitive(),
    content=b"init"
)

tx_hash = lock(
    amount=2_000_000,
    into=validator["script_hash"],
    datum=datum,
    context=context,
)

print(
    f"2 tADA locked into the contract\n\tTx ID: {tx_hash}\n\tDatum: {datum.to_cbor_hex()}"
)
