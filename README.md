# Atomic Swap using Schnorr Adaptor Signature



This repo demonstrates how to implement a **Scriptless Script Atomic Swap Protocol** using **Schnorr Adaptor Signatures**. With this protocol, a cross-chain atomic swap can happen between two people (e.g. Alice and Bob) in a trustless manner without the need for special smart contracts on either blockchain (so long as both parties are using a blockchain that can verify Schnorr signatures).


## Overview:


Atomic Swaps allow parties to trade on separate blockchains (i.e. trading assets between Bitcoin and a sidechain or trading on two disparate blockchains), without requiring third-party trust. If one of the parties does not fulfill their obligation, the non-defaulting party has complete ownership of the assets they would have profited from through the trade.


This implementation addresses the **cryptographic primitives** that support this form of swap and focuses specifically on **Adaptor Signature**.


### What is an Adaptor Signature? An adpator signature serves as a type of "pre-signature" for an asset and is obscured by a secret key value (the witness). 
- An adaptor signature alone is not a valid signed statement.
- The legitimate signature can be extracted from an adaptor signature if the witness is available to the signator.
- A valid signature will produce an adaptor signature when the witness is extracted from the two signatures.


## Features


- **Schnorr Signatures**: General signature validation.
- **Adaptor Primitives**:
  - `pre_sign`: To pre-sign a particular statement with an adaptor signature.
  - `pre_verify`: To pre-verify an adaptor signature with a public key and statement.
  - `adapt`: To change an adaptor signature into a properly formatted full signature using an attestation.
  - `extract`: To retrieve the witness from the `adaptor` signature and the full signature.
- **Atomic Swap Protocol (ASP)**: A single structure called `AtomicSwap` which manages the multi-step ASP procedure between two parties.

## How it Works

The atomic swap protocol consists of **6 Phases**:

1.  **Phase 1: Setup (Party A)**
    - Party A creates random **witness** and its public statement. 
    - Party A also gives Party B the public **statement**.

2.  **Phase 2: Partial Signature (Party B)**
    - Party B makes a transaction that sends its funds to Party A.
    - Instead of giving the transaction a normal signature, Party B instead will give it a Partial Signature (adaptor signature) that locks into the statement given to it by Party A. This partial signature is then sent to Party A.

3.  **Phase 3: Verification (Party A)**
    - Party A checks that the partial signature given by Party B is valid and that it locks to the statement given by Party A.
    - Assuming that the Partial Signature is valid, Party A knows that if it publishes its transaction revealing the witness, it would then be able to claim Party B's funds.

4.  **Phase 4: Publish Transaction (Party A)**
    - Party A signs and publishes its own transaction that is sending funds to Party B. When Party A signs its transaction using the witness, this creates a Full Signature of the transaction and is then published onto Blockchain A
    - It is this published Full Signature of the transaction that reveals the witness to anyone who has an Adaptor Signature (specifically, Party B).

    - **Crucial Step**: Publishing this signature on the public blockchain reveals the witness to anyone who has the adaptor signature (specifically Party B).

5.  **Phase 5: Extract Witness (Party B)**
    - During this phase, Party B observes the transaction made by Party A on Blockchain A.
    - PParty B uses their own Partial Signature that they created in Phase 2 and the Full Signature created by Party A to use the `extract` function to create their own witness.

6.  **Phase 6: Complete Transaction (Party B)**
    - In this phase, Party B uses the witness that they created from Party A's Full Signature to `adapt` Party B's own partial signature into a valid Full Signature for their transaction on Blockchain B.
    - Finally, Party B publishes the completed transaction on Blockchain B in order to claim the funds.


## Security Note
This implementation uses the `secp256k1` elliptic curve. Ensure that the curve integration matches the target blockchains (e.g., Bitcoin uses secp256k1).


