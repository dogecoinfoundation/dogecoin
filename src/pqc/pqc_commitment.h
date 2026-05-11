// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef DOGECOIN_PQC_COMMITMENT_H
#define DOGECOIN_PQC_COMMITMENT_H

#include "config/bitcoin-config.h"
#include "support/experimental.h"
#include "script/script.h"
#include "primitives/transaction.h"
#include "uint256.h"

#include <stdint.h>
#include <string>
#include <vector>

#if ENABLE_LIBOQS
EXPERIMENTAL_FEATURE
#endif

/** Supported post-quantum signature algorithms. */
enum class PQCCommitmentType {
    FALCON512,   ///< Falcon-512 (NIST round 4 alternate)
    DILITHIUM2,  ///< ML-DSA-44 / Dilithium2 (NIST standard)
#ifdef ENABLE_LIBOQS_RACCOON
    RACCOONG44,  ///< Raccoon-G-44 (experimental)
#endif
};

/** Commitment size in bytes (SHA256 output length). */
static const unsigned int PQC_COMMITMENT_BYTES = 32;

/** SHA256(public_key || signature). */
bool PQCComputeCommitment(const std::vector<unsigned char>& public_key,
                          const std::vector<unsigned char>& signature,
                          uint256& commitment_out);

/** Build canonical OP_RETURN commitment script:
 * OP_RETURN, 0x24, TAG4, COMMIT32.
 */
bool PQCBuildCommitmentScript(PQCCommitmentType type,
                              const uint256& commitment,
                              CScript& script_out);

/** Parse canonical OP_RETURN commitment script:
 * OP_RETURN, 0x24, TAG4, COMMIT32.
 */
bool PQCExtractCommitment(const CScript& script,
                          PQCCommitmentType& type_out,
                          uint256& commitment_out);

/** Return a human-readable string for a PQCCommitmentType (e.g. "FALCON512/FLC1"). */
const char* PQCCommitmentTypeToString(PQCCommitmentType type);

/** Parse a user-supplied algorithm name or tag into a PQCCommitmentType.
 *  Accepts case-insensitive full names (falcon512, dilithium2, raccoong44)
 *  and 4-byte tags (FLC1, DIL2, RCG4).  Returns false on unknown input.
 */
bool ParsePQCCommitmentType(const std::string& type, PQCCommitmentType& type_out);

/** Scan tx.vout for the first OP_RETURN commitment output.
 *  On success, sets type_out, commitment_out, and output_index_out.
 */
bool PQCExtractCommitmentFromTx(const CTransaction& tx,
                                PQCCommitmentType& type_out,
                                uint256& commitment_out,
                                uint32_t& output_index_out);

// P2SH Data-Carrier (Carrier Mode)

/** Maximum bytes per individual scriptSig push element (Bitcoin P2SH limit). */
static const unsigned int PQC_CARRIER_MAX_CHUNK_BYTES = 520;

/** Number of data-chunk pushes per carrier input (TAG8, HDR8, CHUNK0, CHUNK1, CHUNK2). */
static const unsigned int PQC_CARRIER_CHUNKS_PER_PART = 3;

/** Usable payload per carrier input: 3 x 520 bytes. */
static const unsigned int PQC_CARRIER_PAYLOAD_PER_PART = PQC_CARRIER_CHUNKS_PER_PART * PQC_CARRIER_MAX_CHUNK_BYTES;

/** 8-byte full-material carrier tags. */
static const unsigned char PQC_CARRIER_TAG_FALCON[8]    = {'F','L','C','1','F','U','L','L'};
static const unsigned char PQC_CARRIER_TAG_DILITHIUM[8]  = {'D','I','L','2','F','U','L','L'};
#ifdef ENABLE_LIBOQS_RACCOON
static const unsigned char PQC_CARRIER_TAG_RACCOON[8]    = {'R','C','G','4','F','U','L','L'};
#endif

/** Carrier output value: 1 DOGE per carrier part (to avoid dust threshold). */
static const CAmount PQC_CARRIER_OUTPUT_VALUE = 100000000; // 1 DOGE in koinu

/** TX_R fee rate: 1000 koinu per byte (standard Dogecoin relay fee rate). */
static const CAmount PQC_CARRIER_FEE_RATE = 1000;

/** TX_R minimum fee: 0.001 DOGE. */
static const CAmount PQC_CARRIER_MIN_FEE = 100000;

/** Carrier redeemScript: OP_DROP x5 OP_TRUE (6 bytes). */
bool PQCBuildCarrierRedeemScript(CScript& script_out);

/** P2SH scriptPubKey for the canonical carrier redeemScript. */
bool PQCBuildCarrierScriptPubKey(CScript& script_out);

/** Carrier HDR8 header structure. */
struct PQCCarrierHeader {
    uint8_t version;       // always 0x01
    uint8_t part_index;    // 0..part_total-1
    uint8_t part_total;    // number of carrier parts
    uint8_t reserved;      // 0x00
    uint16_t pk_len;       // public key length (big-endian)
    uint16_t full_len;     // total payload length (big-endian)
};

/** Compute number of carrier parts needed for a given payload size. */
uint8_t PQCCarrierPartsNeeded(size_t payload_size);

/** Build one carrier reveal part scriptSig.
 *  payload = pubkey_bytes || signature_bytes (concatenated).
 *  part_index selects which chunk of the payload this part carries.
 */
bool PQCBuildCarrierPartScriptSig(PQCCommitmentType type,
                                   const std::vector<unsigned char>& pubkey,
                                   const std::vector<unsigned char>& signature,
                                   uint8_t part_index,
                                   CScript& script_sig_out);

/** Parse carrier scriptSig tag and determine if it's a carrier reveal input.
 *  Returns true if the scriptSig contains a valid 8-byte carrier tag.
 */
bool PQCDetectCarrierScriptSig(const CScript& scriptSig,
                                PQCCommitmentType& type_out);

/** Parse a carrier part scriptSig and extract the header and payload chunk.
 *  Returns the raw payload bytes for this part (up to PQC_CARRIER_PAYLOAD_PER_PART).
 */
bool PQCParseCarrierPartScriptSig(const CScript& scriptSig,
                                   PQCCommitmentType& type_out,
                                   PQCCarrierHeader& header_out,
                                   std::vector<unsigned char>& payload_out);

/** Validate a commitment by extracting PQC public key and signature from
 *  carrier scriptSig data in the transaction inputs, reconstructing the
 *  full payload, and comparing SHA256(pk || sig) against the commitment.
 */
bool PQCValidateCommitmentFromCarrier(const CTransaction& tx,
                                       const uint256& commitment,
                                       PQCCommitmentType& type_out,
                                       uint32_t& carrier_input_index_out,
                                       uint16_t& pk_len_out,
                                       uint16_t& sig_len_out);

/** Extract the raw PQC public key and signature bytes from carrier
 *  scriptSig data in the transaction inputs. Reconstructs the full
 *  payload from multi-part carrier inputs and splits by pk_len.
 *  Returns true if extraction succeeded (does NOT validate commitment).
 */
bool PQCExtractKeyMaterialFromCarrier(const CTransaction& tx,
                                       PQCCommitmentType& type_out,
                                       std::vector<unsigned char>& pubkey_out,
                                       std::vector<unsigned char>& signature_out);

/** Full PQC signature verification from carrier data:
 *  1. Extract pk + sig from carrier scriptSig inputs
 *  2. Validate SHA256(pk || sig) == commitment
 *  3. Verify the PQC signature over the provided message using liboqs OQS_SIG_verify
 *  Returns true only if all three steps pass.
 */
bool PQCVerifySignatureFromCarrier(const CTransaction& tx,
                                    const uint256& commitment,
                                    const unsigned char* message, size_t message_len,
                                    PQCCommitmentType& type_out,
                                    uint32_t& carrier_input_index_out,
                                    uint16_t& pk_len_out,
                                    uint16_t& sig_len_out);

// TX_BASE Reconstruction

/** Reconstruct TX_BASE from TX_C by stripping OP_RETURN and P2SH carrier
 *  outputs, restoring carrier cost to vout[0].
 *
 *  Per the BIP spec, TX_BASE is the deterministic base transaction template
 *  used for sighash computation.  Both signer and verifier must use the same
 *  canonical reconstruction so that sighash32 values agree.
 *
 *  @param txc              The commitment transaction (TX_C)
 *  @param txBase_out       Receives the reconstructed unsigned TX_BASE
 *  @param carrierCost_out  Receives the total carrier cost that was restored
 *  @return true on success (at least one non-carrier, non-OP_RETURN output)
 */
bool PQCReconstructTxBase(const CTransaction& txc,
                          CMutableTransaction& txBase_out,
                          CAmount& carrierCost_out);

/** Return the maximum signature length (in bytes) for a given PQC algorithm.
 *  Uses liboqs OQS_SIG metadata.  Returns 0 on failure.
 */
size_t PQCMaxSignatureLength(PQCCommitmentType type);

// liboqs PQC Cryptographic Operations

/** Get the liboqs OQS_SIG algorithm identifier string for a PQC type.
 *  Returns nullptr if the type is unknown or not supported. */
const char* PQCGetOQSAlgorithmName(PQCCommitmentType type);

/** Generate a real PQC keypair using liboqs.
 *  public_key_out will be e.g. 897 bytes for Falcon-512.
 *  secret_key_out will be e.g. 1281 bytes for Falcon-512.
 */
bool PQCGenerateKeypair(PQCCommitmentType type,
                         std::vector<unsigned char>& public_key_out,
                         std::vector<unsigned char>& secret_key_out);

/** Sign a message with a PQC secret key using liboqs.
 *  signature_out will be variable-length (e.g. ~660 bytes for Falcon-512).
 */
bool PQCSign(PQCCommitmentType type,
             const std::vector<unsigned char>& secret_key,
             const unsigned char* message, size_t message_len,
             std::vector<unsigned char>& signature_out);

/** Get a human-readable name of the verifier function actually used for a
 *  given PQC algorithm. Returns "raccoong_verify()" for the in-tree
 *  Raccoon-G-44 port (when ENABLE_LIBOQS_RACCOON is defined) and
 *  "OQS_SIG_verify()" for Falcon/Dilithium variants verified via liboqs.
 *  Returns "PQCVerify()" if no specific backend applies. The returned
 *  pointer references static storage. */
const char* PQCGetVerifierName(PQCCommitmentType type);

/** Verify a PQC signature using liboqs.
 *  Returns true if the signature is valid.
 */
bool PQCVerify(PQCCommitmentType type,
               const std::vector<unsigned char>& public_key,
               const unsigned char* message, size_t message_len,
               const std::vector<unsigned char>& signature);

#endif // DOGECOIN_PQC_COMMITMENT_H
