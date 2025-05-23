use aiken/collection/list
use aiken/crypto.{VerificationKeyHash}
use cardano/transaction.{InlineDatum, OutputReference, Transaction}

pub type Datum {
  Datum { owner: VerificationKeyHash, content: ByteArray }
}

pub type Redeemer {
  UpdateDatum { new_content: ByteArray }
  ChangeOwner { new_owner: VerificationKeyHash }
}

validator hello_world {
  spend(
    datum: Option<Datum>,
    redeemer: Redeemer,
    own_ref: OutputReference,
    self: Transaction,
  ) {
    expect Some(Datum { owner, content }) = datum

    expect Some(input) =
      self.inputs
        |> transaction.find_input(own_ref)

    let script_addr = input.output.address

    let outs_back_self =
      self.outputs
        |> list.filter(fn(o) { o.address == script_addr })

    expect [out] = outs_back_self

    expect InlineDatum(d) = out.datum
    expect Datum { owner: out_owner, content: out_content } = d

    when redeemer is {
      UpdateDatum { new_content } ->
        list.has(self.extra_signatories, owner) && out_owner == owner && out_content == new_content
      ChangeOwner { new_owner } ->
        list.has(self.extra_signatories, owner) && list.has(
          self.extra_signatories,
          new_owner,
        ) && out_owner == new_owner && out_content == content
    }
  }

  else(_) {
    fail
  }
}
