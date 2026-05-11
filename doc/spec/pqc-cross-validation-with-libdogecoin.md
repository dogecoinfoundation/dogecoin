# Cross-Validating Dogecoin Core PQC Transactions with libdogecoin CLI

This document describes how to use the libdogecoin `such` CLI tool to
independently validate PQC commitment transactions created by Dogecoin Core.
Both implementations share the same BIP spec, carrier format, commitment
algorithm, and TX_BASE reconstruction logic, enabling bit-exact cross-repo
validation.

## Prerequisites

Build libdogecoin with PQC support:

```bash
cd libdogecoin
./autogen.sh
./configure --enable-liboqs       # Falcon-512 + Dilithium2
# or: ./configure --enable-raccoon-g  # adds Raccoon-G-44 (in-tree port under src/raccoon_g/)
make
```

## Shared Invariants

The following primitives produce identical output in both Dogecoin Core
(C++ `pqc_commitment.cpp`) and libdogecoin (C `pqc_carrier.c` + `spv.c`):

| Primitive | Dogecoin Core | libdogecoin CLI |
|-----------|--------------|-----------------|
| Carrier redeemScript | `PQCBuildCarrierRedeemScript()` → `757575757551` | `./such -c pqc_carrier_redeemscript` → `757575757551` |
| Carrier P2SH scriptPubKey | `PQCBuildCarrierScriptPubKey()` → `a9149b402803555511d15d81207d3e2cb3e6bc365e0e87` | `./such -c pqc_carrier_scriptpubkey` → `a9149b402803555511d15d81207d3e2cb3e6bc365e0e87` |
| Commitment | `SHA256(pk \|\| sig)` via `PQCComputeCommitment()` | `./such -c falcon_commit -k <pk> -s <sig>` |
| OP_RETURN script | `6a24` + TAG4 + commitment32 | `./such -c falcon_commit` output includes the script |
| TX_BASE | Strip OP_RETURN + P2SH carriers, restore carrier cost to vout[0] | SPV `spv.c` does identical reconstruction |
| Sighash32 | `SignatureHash(spk, TX_BASE, 0, SIGHASH_ALL)` | `./such -c tx_sighash32 -x <tx_base_hex> -s <spk> -i 0 -h 1` |
| Carrier scriptSig | `PQCBuildCarrierPartScriptSig()` | `./such -c pqc_carrier_mkpart -k <tag4> -p <pk> -s <sig> -i 0` |

### Algorithm Parameters

| Algorithm | Tag4 | Tag8 | pk_len | sig_len | full_len | parts |
|-----------|------|------|--------|---------|----------|-------|
| Falcon-512 | `FLC1` | `FLC1FULL` | 897 | ~652–690 | ~1549–1587 | 1 |
| Dilithium2 | `DIL2` | `DIL2FULL` | 1312 | 2420 | 3732 | 3 |
| Raccoon-G-44 | `RCG4` | `RCG4FULL` | 16144 | 20768 | 36912 | 24 |

## Workflow Overview

Dogecoin Core creates PQC transactions in a two-step process:

1. **TX_C (Commitment):** Sends payment + OP_RETURN commitment + P2SH carrier outputs.
2. **TX_R (Reveal):** Spends carrier outputs, revealing full PQ public key + signature.

The details popup in Core already performs full validation:
- Recomputes `TX_BASE` from `TX_C` (strips OP_RETURN + carrier outputs, restores carrier cost to vout[0])
- Computes `sighash32 = SignatureHash(scriptPubKey, TX_BASE, 0, SIGHASH_ALL)`
- Verifies `OQS_SIG_verify(pk, sighash32, sig)`
- Shows **PASSED** (green) or **FAILED** (red) with specific failure reasons

Old transactions (created before the TX_BASE sighash fix) will show **FAILED —
OQS_SIG_verify() failed** because they signed a different message. New
transactions from Core or libdogecoin will show **PASSED**.

## Step-by-Step Cross-Validation Using libdogecoin CLI

### Step 1: Verify canonical carrier primitives match

Before validating any transaction, confirm both implementations produce
the same carrier infrastructure:

```bash
# Canonical carrier redeemScript (must be 757575757551)
./such -c pqc_carrier_redeemscript

# Canonical carrier P2SH scriptPubKey (must be a9149b402803555511d15d81207d3e2cb3e6bc365e0e87)
./such -c pqc_carrier_scriptpubkey
```

Both values are deterministic and must match exactly between
Dogecoin Core and libdogecoin.

### Step 2: Extract TX_C raw hex from Core

```bash
dogecoin-cli getrawtransaction <TX_C_txid>
```

### Step 3: Reconstruct TX_BASE and compute sighash32

TX_BASE is TX_C with OP_RETURN and P2SH carrier outputs removed, and
carrier cost restored to vout[0]. Both repos use exact canonical carrier
scriptPubKey matching (not a generic P2SH length check) to identify
carrier outputs.

```bash
# Derive the sighash32 for input 0 of the base transaction
./such -c tx_sighash32 \
  -x <tx_base_hex> \
  -s <scriptPubKey_of_input0_hex> \
  -i 0 \
  -h 1
```

Note: The raw tx passed to `tx_sighash32` should be the TX_BASE (before
OP_RETURN and carrier outputs were appended). You can reconstruct TX_BASE
by stripping the OP_RETURN output and any P2SH carrier outputs from TX_C,
then adding the carrier cost back to vout[0].

### Step 4: Verify the PQC signature

Using the public key and signature extracted from TX_R carrier scriptSig:

```bash
# Falcon-512
./such -c falcon_verify -k <pubkey_hex> -x <sighash32_hex> -s <signature_hex>

# Dilithium2
./such -c dilithium2_verify -k <pubkey_hex> -x <sighash32_hex> -s <signature_hex>

# Raccoon-G-44
./such -c raccoong_verify -k <pubkey_hex> -x <sighash32_hex> -s <signature_hex>
```

### Step 5: Verify the commitment

```bash
# Falcon-512
./such -c falcon_commit -k <pubkey_hex> -s <signature_hex>
# Output: commitment32 hex — compare against OP_RETURN payload in TX_C

# Dilithium2
./such -c dilithium2_commit -k <pubkey_hex> -s <signature_hex>

# Raccoon-G-44
./such -c raccoong_commit -k <pubkey_hex> -s <signature_hex>
```

The output should match the 32-byte commitment in the OP_RETURN output of TX_C.

### Step 6: Parse carrier scriptSig

```bash
./such -c pqc_carrier_parsepart -x <TX_R_scriptSig_hex>
```

This extracts the TAG8, HDR8 (with part_index/part_total/pk_len/full_len),
and payload chunks from the carrier scriptSig.

### Step 7: Build carrier scriptSig (for new transactions)

```bash
# Build a carrier part scriptSig from algorithm tag, public key, and signature
./such -c pqc_carrier_mkpart -k <tag4_hex> -p <pk_hex> -s <sig_hex> -i <part_index>
```

### Step 8: Build TX_C with commitment and carrier in one step

```bash
# Falcon-512
./such -c falcon_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pk_hex> -s <sig_hex>

# Dilithium2
./such -c dilithium2_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pk_hex> -s <sig_hex>

# Raccoon-G-44
./such -c raccoong_add_commit_and_carrier_tx -x <raw_tx_hex> -m <commitment_hex> -k <pk_hex> -s <sig_hex>
```

These commands output the modified TX_C raw hex plus `carrier_part_scriptsig[N]`
values needed to build the TX_R.

## Complete TX_R Reveal Flow

### Single-Part (Falcon-512)

```bash
# 1. Generate keypair
./such -c falcon_keygen

# 2. Compute sighash32 of the unsigned base transaction
./such -c tx_sighash32 -x <unsigned_tx_hex> -s <scriptPubKey_hex> -i 0 -h 1

# 3. Sign the sighash32
./such -c falcon_sign -p <secret_key_hex> -x <sighash32_hex>

# 4. Generate commitment
./such -c falcon_commit -k <pubkey_hex> -s <signature_hex>

# 5. Build TX_C with commitment + carrier
./such -c falcon_add_commit_and_carrier_tx -x <unsigned_tx_hex> -m <commitment_hex> -k <pubkey_hex> -s <signature_hex>

# 6. Sign TX_C with secp256k1 (standard P2PKH signing)
./such -c sign_tx ...

# 7. Build TX_R spending carrier outputs using carrier_part_scriptsig from step 5
# 8. Broadcast TX_C, then TX_R
```

### Multi-Part (Dilithium2 — 3 parts)

```bash
# Steps 1-5 identical, using dilithium2_* commands
# Step 5 output includes carrier_part_scriptsig[0], [1], [2]
# TX_R has 3 inputs, each spending one carrier P2SH output from TX_C
# Each input's scriptSig is set to the corresponding carrier_part_scriptsig
```

### Multi-Part (Raccoon-G-44 — 24 parts)

```bash
# Steps 1-5 identical, using raccoong_* commands
# Step 5 output includes carrier_part_scriptsig[0] through [23]
# TX_R has 24 inputs, each spending one carrier P2SH output from TX_C
```

## Multi-Part Carrier Reassembly

For algorithms requiring multiple carrier parts, reassembly follows:

1. Parse each carrier vin's scriptSig with `pqc_carrier_parsepart`
2. Verify all parts share the same TAG8, pk_len, full_len, and part_total
3. Concatenate payload chunks in `part_index` order (0 to part_total-1)
4. Truncate concatenated payload to `full_len` bytes
5. Split into `pk[0..pk_len)` and `sig[pk_len..full_len)`
6. Verify `SHA256(pk || sig)` matches the OP_RETURN commitment from TX_C

## Expected Results

| Transaction Age | Sighash | OQS_SIG_verify | Overall |
|----------------|---------|----------------|---------|
| Old (pre-fix)  | Signed wrong message | **FAILED** (red) | **FAILED — OQS_SIG_verify() failed** |
| New (Core)     | Signed TX_BASE sighash32 | **PASSED** (green) | **PASSED — commitment and cryptographic verification both verified** |
| New (libdogecoin) | Signed TX_BASE sighash32 | **PASSED** (green) | **PASSED — commitment and cryptographic verification both verified** |

## SPV Cross-Validation

The libdogecoin SPV scanner (`spvnode`) performs real-time cross-validation
during block scan:

```
[falcon-commit] Valid at height=6156750 txpos=12
  commit=3a83c1c63136e118... carrier_vin=0
  source=carrier_scriptsig pk_len=897 sig_len=657
  pk_prefix=091f7e11e2bbcb23... sig_prefix=3938a41d3ffc68a5...

[falcon-commit] PQC signature verification PASSED at height=6156750
  txpos=12 sighash=<sighash32_hex>
```

The SPV scanner:
1. Buffers OP_RETURN commitments from TX_C outputs per block
2. Scans TX_R carrier scriptSigs for matching commitments
3. Reconstructs TX_BASE (strips OP_RETURN + exact canonical carrier outputs)
4. Derives scriptPubKey from the P2PKH scriptSig (extracts pubkey, computes HASH160)
5. Computes `sighash32(TX_BASE, scriptPubKey, 0, SIGHASH_ALL)`
6. Verifies the PQC signature over the sighash32

## Automated Cross-Validation

### Unit tests (Dogecoin Core)

The `pqc_commitment_tests` test suite validates all carrier primitives:
- `pqc_carrier_redeemscript_is_6_bytes` — canonical redeemScript
- `pqc_carrier_scriptpubkey_is_p2sh` — canonical P2SH scriptPubKey
- `pqc_carrier_build_parse_falcon_roundtrip` — single-part roundtrip
- `pqc_carrier_multipart_dilithium2` — 3-part Dilithium2 roundtrip
- `pqc_cross_validate_carrier_primitives` — shared test vectors matching libdogecoin CLI output
- Confirmed mainnet TX_R decode tests for all three algorithms

### RPC test (Dogecoin Core)

```bash
python3 qa/rpc-tests/pqc_testnet_checkpoint_scan.py \
  --srcdir /path/to/dogecoin/src \
  --txid <txid> \
  --height <height> \
  --commitment-type FLC1 \
  --pubkey-hex <pubkey_hex> \
  --signature-hex <signature_hex>
```

See `doc/spec/pqc-validation-log-template.md` for the full log format and
`doc/tools.md` in the libdogecoin repo for the complete CLI reference.
