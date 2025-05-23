from dataclasses import dataclass
from pycardano import PlutusData

@dataclass
class ContractDatum(PlutusData):
    CONSTR_ID = 0   # State
    owner: bytes
    content: bytes

@dataclass
class UpdateDatumRedeemer(PlutusData):
    CONSTR_ID = 0   # UpdateDatum
    new_content: bytes

@dataclass
class ChangeOwnerRedeemer(PlutusData):
    CONSTR_ID = 1   # ChangeOwner
    new_owner: bytes
