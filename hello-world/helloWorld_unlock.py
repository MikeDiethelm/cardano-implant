from dataclasses import dataclass
from pycardano import (
    Address,
    BlockFrostChainContext,
    Network,
    PaymentSigningKey,
    PaymentVerificationKey,
    PlutusData,
    PlutusV3Script,
    Redeemer,
    ScriptHash,
    TransactionBuilder,
    TransactionOutput,
    UTxO,
)
from pycardano.hash import VerificationKeyHash, TransactionId, ScriptHash
import json
import sys
import os
import glob

def read_validator() -> dict:
    with open("plutus.json", "r") as f:
        v = json.load(f)
    return {
        "type": "PlutusV3",
        "script_bytes": PlutusV3Script(bytes.fromhex(v["validators"][0]["compiledCode"])),
        "script_hash": ScriptHash(bytes.fromhex(v["validators"][0]["hash"])),
    }

@dataclass
class ContractDatum(PlutusData):
    CONSTR_ID = 0
    owner: bytes
    content: bytes

@dataclass
class UpdateDatumRedeemer(PlutusData):
    CONSTR_ID = 0
    new_content: bytes

@dataclass
class ChangeOwnerRedeemer(PlutusData):
    CONSTR_ID = 1
    new_owner: bytes

def get_utxo_from_str(tx_id: str, contract_address: Address) -> UTxO:
    for utxo in context.utxos(str(contract_address)):
        if str(utxo.input.transaction_id) == tx_id:
            return utxo
    raise Exception(f"UTxO {tx_id} not found at contract address")

def lock(amount: int, into: ScriptHash, datum: PlutusData) -> TransactionId:
    sk = PaymentSigningKey.load("./me.sk")
    vk = PaymentVerificationKey.from_signing_key(sk)
    addr = Address(payment_part=vk.hash(), network=Network.TESTNET)
    builder = TransactionBuilder(context)
    builder.add_input_address(addr)
    builder.add_output(TransactionOutput(
        address=Address(payment_part=into, network=Network.TESTNET),
        amount=amount,
        datum=datum,
    ))
    signed = builder.build_and_sign([sk], change_address=addr)
    return context.submit_tx(signed)

def update_datum(utxo: UTxO, new_content: bytes) -> TransactionId:
    # 1) Redeemer und neues Datum
    redeemer = Redeemer(data=UpdateDatumRedeemer(new_content=new_content))
    raw = utxo.output.datum
    old = ContractDatum.from_cbor(raw.cbor)
    new_datum = ContractDatum(owner=old.owner, content=new_content)

    # 2) Echten VerificationKeyHash für old.owner erzeugen
    old_owner_vkh = VerificationKeyHash(old.owner)

    # 3) Builder aufsetzen
    sk = PaymentSigningKey.load("./me.sk")
    vk = PaymentVerificationKey.from_signing_key(sk)
    addr = Address(payment_part=vk.hash(), network=Network.TESTNET)

    builder = TransactionBuilder(context)
    builder.add_input_address(addr)
    builder.add_script_input(utxo, validator["script_bytes"], redeemer=redeemer)
    builder.add_output(TransactionOutput(
        address=utxo.output.address,
        amount=utxo.output.amount,
        datum=new_datum,
    ))
    builder.required_signers = [old_owner_vkh]

    signed = builder.build_and_sign([sk], change_address=addr)
    tx_hash = context.submit_tx(signed)

    print(
        f"Datum aktualisiert\n"
        f"\tTx ID:    {tx_hash}\n"
        f"\tRedeemer: {redeemer.data.to_cbor_hex()}"
    )
    return tx_hash

def change_owner(utxo: UTxO) -> TransactionId:
    # 1) Alte Dateien löschen
    for pattern in ("new_owner*.sk", "new_owner*.vkey", "new_owner*.addr"):
        for f in glob.glob(pattern):
            os.remove(f)

    # 2) Neues Schlüssel-Paar erzeugen und speichern
    new_sk = PaymentSigningKey.generate()
    new_vk = PaymentVerificationKey.from_signing_key(new_sk)
    new_sk.save("new_owner.sk")
    new_vk.save("new_owner.vkey")
    addr = Address(payment_part=new_vk.hash(), network=Network.TESTNET)
    with open("new_owner.addr", "w") as f:
        f.write(str(addr))

    # 3) Bytes und VKH extrahieren
    new_owner_bytes = new_vk.hash().to_primitive()
    new_owner_vkh   = new_vk.hash()

    # 4) Redeemer + neues Datum
    redeemer = Redeemer(data=ChangeOwnerRedeemer(new_owner=new_owner_bytes))
    raw = utxo.output.datum
    old = ContractDatum.from_cbor(raw.cbor)
    new_datum = ContractDatum(owner=new_owner_bytes, content=old.content)

    # 5) Alten Owner-Hash in VerificationKeyHash konvertieren
    old_owner_vkh = VerificationKeyHash(old.owner)

    # 6) Transaktion aufbauen
    sk = PaymentSigningKey.load("./me.sk")
    vk = PaymentVerificationKey.from_signing_key(sk)
    change_addr = Address(payment_part=vk.hash(), network=Network.TESTNET)

    builder = TransactionBuilder(context)
    builder.add_input_address(change_addr)
    builder.add_script_input(utxo, validator["script_bytes"], redeemer=redeemer)
    builder.add_output(TransactionOutput(
        address=utxo.output.address,
        amount=utxo.output.amount,
        datum=new_datum,
    ))
    # Echte VKH-Objekte verwenden
    builder.required_signers = [old_owner_vkh, new_owner_vkh]

    signed = builder.build_and_sign([sk, new_sk], change_address=change_addr)
    tx_hash = context.submit_tx(signed)

    print(
        f"Owner gewechselt\n"
        f"\tTx ID:    {tx_hash}\n"
        f"\tRedeemer: {redeemer.data.to_cbor_hex()}\n"
        f"\tNeue Keys in: new_owner.sk, new_owner.vkey, new_owner.addr"
    )
    return tx_hash

# --- main ---
if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python helloWorld_unlock.py <update|change_owner> <tx_id> [param]")
        sys.exit(1)

    # Context & Validator laden
    context = BlockFrostChainContext(
        project_id="previewc3NRhWomtSTZ3p0MBCawyMxcbuOt4I5X",
        base_url="https://cardano-preview.blockfrost.io/api/",
    )
    validator = read_validator()

    mode  = sys.argv[1]
    tx_id = sys.argv[2]
    param = sys.argv[3] if len(sys.argv) > 3 else None

    contract_address = Address(payment_part=validator["script_hash"], network=Network.TESTNET)
    utxo = get_utxo_from_str(tx_id, contract_address)

    if mode == "update":
        if param is None:
            raise ValueError("Für 'update' bitte einen neuen Inhalt angeben.")
        update_datum(utxo, param.encode())
    elif mode == "change_owner":
        change_owner(utxo)
    else:
        raise ValueError("Usage: python helloWorld_unlock.py <update|change_owner> <tx_id> [param]")

    # Ergebnis prüfen
    for u in context.utxos(str(contract_address)):
        if str(u.input.transaction_id) == tx_id:
            cd = ContractDatum.from_cbor(u.output.datum.cbor)
            print("Owner:  ", cd.owner.hex())
            print("Content:", cd.content.decode())
            break
