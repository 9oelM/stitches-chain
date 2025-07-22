pub struct BlockBody {
  pub randao_reveal: [u8; 96], // BLS signature
  // These can be added later:
  // pub graffiti: [u8; 32],
  // pub proposer_slashings: Vec<ProposerSlashing>,
  // pub attester_slashings: Vec<AttesterSlashing>,
  // pub attestations: Vec<Attestation>,
  // pub deposits: Vec<Deposit>,
  // pub voluntary_exits: Vec<SignedVoluntaryExit>,
  // pub execution_payload: Option<ExecutionPayload>, // post-Merge
}
