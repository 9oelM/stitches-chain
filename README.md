# stitches-chain

PoS chain for dummies to break stuff & learn.

> [!NOTE]
> **_This project is not intended for smart people!_**
>
> And I really mean it. Because this is for the average-ish people who still want to break into L1 development.

The goal is:

1. **PoS Consensus Layer**. Implement minimal PoS chain at a consensus layer. Execution layer is not dealt with for now.
1. **Ethereum relevance**. Sufficiently replicate certain features/ERCs/EIPs of Ethereum Beacon chain in a rather inefficient but educative manner
1. **Obsessive documentation**. Overly annotate the code in such a way that developers coming from other domains (web2/smart contract development/fullstack) would understand what is going on in the code.

The project is divided up into modular crates:

| crate        | description                                                                                                             |
| ------------ | ----------------------------------------------------------------------------------------------------------------------- |
| consensus    | Consensus client that mimics certain features of Ethereum consensus client                                              |
| validator    | Validator client that manages keys, signs blocks, communicates with consensus client, etc                               |
| bls-keystore | [EIP-2335](https://eips.ethereum.org/EIPS/eip-2335)-compliant KeyStore implementation. Used for storing a validator key |
| cli          | CLI entrypoint for other crates                                                                                         |

## Useful resources

- ['Upgrading Ethereum' book](https://eth2book.info/capella/contents/)
- [Ethereum Foundation's annotated spec](https://github.com/ethereum/annotated-spec)
- [Ethereum Foundation's consensus spec](https://github.com/ethereum/consensus-specs)
