// Copyright (c) 2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "pqc/pqc_commitment.h"

#include "crypto/sha256.h"
#include "hash.h"
#include "pubkey.h"
#include "script/script.h"
#include "script/standard.h"
#include "support/cleanse.h"
#include "support/experimental.h"

#include <string.h>
#include <algorithm>
#include <mutex>

#if ENABLE_LIBOQS
EXPERIMENTAL_FEATURE
#include <oqs/oqs.h>
#endif

#ifdef ENABLE_LIBOQS_RACCOON
// In-tree Raccoon-G-44 C port (vendored from edtubbs/libdogecoin@0.1.5-dev-pqc-carrier).
// The ENABLE_LIBOQS_RACCOON macro name is preserved across the codebase as the
// Raccoon-G-44 visibility gate; the implementation lives natively under
// src/raccoon_g/.
#include "raccoon_g/raccoong.h"
#include "raccoon_g/thrc.h"
#include "raccoon_g/dogecoin/random.h"

namespace {
// The Raccoon-G-44 keygen/sign/verify primitives in src/raccoon_g/thrc.c
// use file-scope `static polyr` scratch (documented at src/raccoon_g/thrc.h
// ~lines 112-130). The upstream port requires callers to externally
// serialize all keygen / sign / verify / HD-derive calls. This mutex
// provides that serialization for every Raccoon-G-44 entry point exposed
// through PQCGenerateKeypair / PQCSign / PQCVerify so concurrent Qt + RPC
// callers (or two Qt clicks in flight) cannot race on the shared scratch.
std::mutex& RaccoonGMutex()
{
    static std::mutex m;
    return m;
}
} // namespace
#endif

static const unsigned char PQC_COMMITMENT_OP_RETURN = OP_RETURN;
static const unsigned char PQC_COMMITMENT_PUSH_LEN = 36;
static const unsigned char PQC_TAG_FALCON[4] = {'F', 'L', 'C', '1'};
static const unsigned char PQC_TAG_DILITHIUM[4] = {'D', 'I', 'L', '2'};
#ifdef ENABLE_LIBOQS_RACCOON
static const unsigned char PQC_TAG_RACCOON[4] = {'R', 'C', 'G', '4'};
#endif
static const unsigned int PQC_TAG_BYTES = 4;
static const unsigned int PQC_SCRIPT_BYTES = 2 + PQC_TAG_BYTES + PQC_COMMITMENT_BYTES;

/** Map PQCCommitmentType to its 4-byte OP_RETURN script tag. Returns nullptr for unknown types. */
static const unsigned char* GetTagForType(PQCCommitmentType type)
{
    switch (type) {
    case PQCCommitmentType::FALCON512:
        return PQC_TAG_FALCON;
    case PQCCommitmentType::DILITHIUM2:
        return PQC_TAG_DILITHIUM;
#ifdef ENABLE_LIBOQS_RACCOON
    case PQCCommitmentType::RACCOONG44:
        return PQC_TAG_RACCOON;
#endif
    default:
        return nullptr;
    }
}

/** Compute commitment = SHA256(public_key || signature). */
bool PQCComputeCommitment(const std::vector<unsigned char>& public_key,
                          const std::vector<unsigned char>& signature,
                          uint256& commitment_out)
{
    if (public_key.empty() || signature.empty()) {
        return false;
    }

    CSHA256()
        .Write(public_key.data(), public_key.size())
        .Write(signature.data(), signature.size())
        .Finalize(commitment_out.begin());
    return true;
}

/** Build canonical OP_RETURN commitment script: OP_RETURN 0x24 TAG4 COMMIT32. */
bool PQCBuildCommitmentScript(PQCCommitmentType type,
                              const uint256& commitment,
                              CScript& script_out)
{
    const unsigned char* tag = GetTagForType(type);
    if (tag == nullptr) {
        return false;
    }

    std::vector<unsigned char> raw(PQC_SCRIPT_BYTES);
    raw[0] = PQC_COMMITMENT_OP_RETURN;
    raw[1] = PQC_COMMITMENT_PUSH_LEN;
    memcpy(&raw[2], tag, PQC_TAG_BYTES);
    memcpy(&raw[2 + PQC_TAG_BYTES], commitment.begin(), PQC_COMMITMENT_BYTES);
    script_out = CScript(raw.begin(), raw.end());
    return true;
}

/** Parse canonical OP_RETURN commitment script and extract tag and 32-byte commitment. */
bool PQCExtractCommitment(const CScript& script,
                          PQCCommitmentType& type_out,
                          uint256& commitment_out)
{
    if (script.size() != PQC_SCRIPT_BYTES) {
        return false;
    }

    if (script[0] != PQC_COMMITMENT_OP_RETURN || script[1] != PQC_COMMITMENT_PUSH_LEN) {
        return false;
    }

    const unsigned char* data = &script[2];
    if (memcmp(data, PQC_TAG_FALCON, PQC_TAG_BYTES) == 0) {
        type_out = PQCCommitmentType::FALCON512;
    } else if (memcmp(data, PQC_TAG_DILITHIUM, PQC_TAG_BYTES) == 0) {
        type_out = PQCCommitmentType::DILITHIUM2;
#ifdef ENABLE_LIBOQS_RACCOON
    } else if (memcmp(data, PQC_TAG_RACCOON, PQC_TAG_BYTES) == 0) {
        type_out = PQCCommitmentType::RACCOONG44;
#endif
    } else {
        return false;
    }

    std::vector<unsigned char> commitment_bytes(PQC_COMMITMENT_BYTES);
    memcpy(commitment_bytes.data(), data + PQC_TAG_BYTES, PQC_COMMITMENT_BYTES);
    commitment_out = uint256(commitment_bytes);
    return true;
}

/** Return a human-readable string for a PQCCommitmentType (e.g. "FALCON512/FLC1"). */
const char* PQCCommitmentTypeToString(PQCCommitmentType type)
{
    switch (type) {
    case PQCCommitmentType::FALCON512:
        return "FALCON512/FLC1";
    case PQCCommitmentType::DILITHIUM2:
        return "DILITHIUM2/DIL2";
#ifdef ENABLE_LIBOQS_RACCOON
    case PQCCommitmentType::RACCOONG44:
        return "RACCOONG44/RCG4";
#endif
    default:
        return "UNKNOWN";
    }
}

/** Parse a user-supplied algorithm name or 4-byte tag into a PQCCommitmentType. */
bool ParsePQCCommitmentType(const std::string& type, PQCCommitmentType& type_out)
{
    if (type == "falcon512" || type == "FALCON512" || type == "flc1" || type == "FLC1") {
        type_out = PQCCommitmentType::FALCON512;
        return true;
    }
    if (type == "dilithium2" || type == "DILITHIUM2" || type == "dil2" || type == "DIL2") {
        type_out = PQCCommitmentType::DILITHIUM2;
        return true;
    }
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == "raccoong44" || type == "RACCOONG44" || type == "raccoong" || type == "RACCOONG" || type == "rcg4" || type == "RCG4") {
        type_out = PQCCommitmentType::RACCOONG44;
        return true;
    }
#endif
    return false;
}

/** Scan tx.vout for the first OP_RETURN commitment output. */
bool PQCExtractCommitmentFromTx(const CTransaction& tx,
                                PQCCommitmentType& type_out,
                                uint256& commitment_out,
                                uint32_t& output_index_out)
{
    for (uint32_t i = 0; i < tx.vout.size(); ++i) {
        if (PQCExtractCommitment(tx.vout[i].scriptPubKey, type_out, commitment_out)) {
            output_index_out = i;
            return true;
        }
    }
    return false;
}

// P2SH Data-Carrier (Carrier Mode)

/** Carrier redeemScript: OP_DROP OP_DROP OP_DROP OP_DROP OP_DROP OP_TRUE (6 bytes).
 *  Cleans TAG8, HDR8, CHUNK0, CHUNK1, CHUNK2 from stack and pushes true.
 */
bool PQCBuildCarrierRedeemScript(CScript& script_out)
{
    script_out = CScript();
    script_out << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_DROP << OP_TRUE;
    return true;
}

/** P2SH scriptPubKey wrapping the canonical carrier redeemScript. */
bool PQCBuildCarrierScriptPubKey(CScript& script_out)
{
    CScript redeemScript;
    if (!PQCBuildCarrierRedeemScript(redeemScript)) {
        return false;
    }
    script_out = GetScriptForDestination(CScriptID(redeemScript));
    return true;
}

/** Return the number of carrier parts required for a payload of payload_size bytes. */
uint8_t PQCCarrierPartsNeeded(size_t payload_size)
{
    if (payload_size == 0) return 0;
    return static_cast<uint8_t>((payload_size + PQC_CARRIER_PAYLOAD_PER_PART - 1) / PQC_CARRIER_PAYLOAD_PER_PART);
}

/** Map PQCCommitmentType to its 8-byte carrier TAG8. Returns nullptr for unknown types. */
static const unsigned char* GetCarrierTagForType(PQCCommitmentType type)
{
    switch (type) {
    case PQCCommitmentType::FALCON512:
        return PQC_CARRIER_TAG_FALCON;
    case PQCCommitmentType::DILITHIUM2:
        return PQC_CARRIER_TAG_DILITHIUM;
#ifdef ENABLE_LIBOQS_RACCOON
    case PQCCommitmentType::RACCOONG44:
        return PQC_CARRIER_TAG_RACCOON;
#endif
    default:
        return nullptr;
    }
}

/** Serialise a PQCCarrierHeader into the 8-byte big-endian wire format. */
static void EncodeCarrierHeader(const PQCCarrierHeader& hdr, unsigned char out[8])
{
    out[0] = hdr.version;
    out[1] = hdr.part_index;
    out[2] = hdr.part_total;
    out[3] = hdr.reserved;
    out[4] = static_cast<unsigned char>((hdr.pk_len >> 8) & 0xFF);
    out[5] = static_cast<unsigned char>(hdr.pk_len & 0xFF);
    out[6] = static_cast<unsigned char>((hdr.full_len >> 8) & 0xFF);
    out[7] = static_cast<unsigned char>(hdr.full_len & 0xFF);
}

/** Deserialise 8 bytes into a PQCCarrierHeader. Returns false if version != 0x01
 *  or part_index >= part_total.
 */
static bool DecodeCarrierHeader(const unsigned char data[8], PQCCarrierHeader& hdr)
{
    hdr.version = data[0];
    if (hdr.version != 0x01) return false;
    hdr.part_index = data[1];
    hdr.part_total = data[2];
    hdr.reserved = data[3];
    hdr.pk_len = (static_cast<uint16_t>(data[4]) << 8) | data[5];
    hdr.full_len = (static_cast<uint16_t>(data[6]) << 8) | data[7];
    if (hdr.part_total == 0 || hdr.part_index >= hdr.part_total) return false;
    return true;
}

/** Build carrier scriptSig with TAG8, HDR8, and up to 3 chunk pushes for the given part_index. */
bool PQCBuildCarrierPartScriptSig(PQCCommitmentType type,
                                   const std::vector<unsigned char>& pubkey,
                                   const std::vector<unsigned char>& signature,
                                   uint8_t part_index,
                                   CScript& script_sig_out)
{
    const unsigned char* carrier_tag = GetCarrierTagForType(type);
    if (carrier_tag == nullptr) return false;
    if (pubkey.empty() || signature.empty()) return false;

    // Build full payload: pubkey || signature
    std::vector<unsigned char> full_payload;
    full_payload.reserve(pubkey.size() + signature.size());
    full_payload.insert(full_payload.end(), pubkey.begin(), pubkey.end());
    full_payload.insert(full_payload.end(), signature.begin(), signature.end());

    uint8_t parts_needed = PQCCarrierPartsNeeded(full_payload.size());
    if (parts_needed == 0 || part_index >= parts_needed) return false;
    if (full_payload.size() > 0xFFFF || pubkey.size() > 0xFFFF) return false;

    // Build HDR8
    PQCCarrierHeader hdr;
    hdr.version = 0x01;
    hdr.part_index = part_index;
    hdr.part_total = parts_needed;
    hdr.reserved = 0x00;
    hdr.pk_len = static_cast<uint16_t>(pubkey.size());
    hdr.full_len = static_cast<uint16_t>(full_payload.size());

    unsigned char hdr_bytes[8];
    EncodeCarrierHeader(hdr, hdr_bytes);

    // Extract this part's payload slice
    size_t part_offset = static_cast<size_t>(part_index) * PQC_CARRIER_PAYLOAD_PER_PART;
    size_t part_remaining = (part_offset < full_payload.size()) ? (full_payload.size() - part_offset) : 0;
    size_t part_len = std::min(part_remaining, static_cast<size_t>(PQC_CARRIER_PAYLOAD_PER_PART));

    // Split into up to 3 chunks of max 520 bytes each
    std::vector<unsigned char> chunks[PQC_CARRIER_CHUNKS_PER_PART];
    size_t consumed = 0;
    for (unsigned int c = 0; c < PQC_CARRIER_CHUNKS_PER_PART; ++c) {
        if (consumed < part_len) {
            size_t chunk_len = std::min(part_len - consumed, static_cast<size_t>(PQC_CARRIER_MAX_CHUNK_BYTES));
            chunks[c].assign(full_payload.begin() + part_offset + consumed,
                             full_payload.begin() + part_offset + consumed + chunk_len);
            consumed += chunk_len;
        }
        // Empty chunks left as empty vectors
    }

    // Build scriptSig: TAG8 HDR8 CHUNK0 CHUNK1 CHUNK2 redeemScript
    CScript redeemScript;
    if (!PQCBuildCarrierRedeemScript(redeemScript)) return false;

    std::vector<unsigned char> tag_vec(carrier_tag, carrier_tag + 8);
    std::vector<unsigned char> hdr_vec(hdr_bytes, hdr_bytes + 8);

    script_sig_out = CScript();
    script_sig_out << tag_vec << hdr_vec;
    for (unsigned int c = 0; c < PQC_CARRIER_CHUNKS_PER_PART; ++c) {
        if (chunks[c].empty()) {
            script_sig_out << OP_0;
        } else {
            script_sig_out << chunks[c];
        }
    }
    // Push the redeemScript as the final element
    std::vector<unsigned char> rsBytes(redeemScript.begin(), redeemScript.end());
    script_sig_out << rsBytes;
    return true;
}

/** Return true if the first push in scriptSig is a known 8-byte PQC carrier tag; set type_out. */
bool PQCDetectCarrierScriptSig(const CScript& scriptSig, PQCCommitmentType& type_out)
{
    // Decode the scriptSig to get push elements
    std::vector<std::vector<unsigned char> > stack;
    CScript::const_iterator it = scriptSig.begin();
    while (it != scriptSig.end()) {
        std::vector<unsigned char> data;
        opcodetype opcode;
        if (!scriptSig.GetOp(it, opcode, data)) break;
        stack.push_back(data);
    }
    // Need at least 6 pushes: TAG8 HDR8 CHUNK0 CHUNK1 CHUNK2 redeemScript
    if (stack.size() < 6) return false;

    // First push must be an 8-byte carrier tag
    if (stack[0].size() != 8) return false;

    if (memcmp(stack[0].data(), PQC_CARRIER_TAG_FALCON, 8) == 0) {
        type_out = PQCCommitmentType::FALCON512;
        return true;
    }
    if (memcmp(stack[0].data(), PQC_CARRIER_TAG_DILITHIUM, 8) == 0) {
        type_out = PQCCommitmentType::DILITHIUM2;
        return true;
    }
#ifdef ENABLE_LIBOQS_RACCOON
    if (memcmp(stack[0].data(), PQC_CARRIER_TAG_RACCOON, 8) == 0) {
        type_out = PQCCommitmentType::RACCOONG44;
        return true;
    }
#endif
    return false;
}

/** Decode one carrier part scriptSig into type, header fields, and raw payload bytes. */
bool PQCParseCarrierPartScriptSig(const CScript& scriptSig,
                                   PQCCommitmentType& type_out,
                                   PQCCarrierHeader& header_out,
                                   std::vector<unsigned char>& payload_out)
{
    // Decode pushes
    std::vector<std::vector<unsigned char> > stack;
    CScript::const_iterator it = scriptSig.begin();
    while (it != scriptSig.end()) {
        std::vector<unsigned char> data;
        opcodetype opcode;
        if (!scriptSig.GetOp(it, opcode, data)) break;
        stack.push_back(data);
    }
    if (stack.size() < 6) return false;

    // TAG8 (8 bytes)
    if (stack[0].size() != 8) return false;
    if (!PQCDetectCarrierScriptSig(scriptSig, type_out)) return false;

    // HDR8 (8 bytes)
    if (stack[1].size() != 8) return false;
    if (!DecodeCarrierHeader(stack[1].data(), header_out)) return false;

    // Concatenate CHUNK0 + CHUNK1 + CHUNK2 (indices 2, 3, 4)
    payload_out.clear();
    for (int c = 2; c < 5 && c < (int)stack.size(); ++c) {
        payload_out.insert(payload_out.end(), stack[c].begin(), stack[c].end());
    }
    return true;
}

/** Gather all carrier parts from tx.vin, verify they are contiguous and from the
 *  same algorithm, reassemble the full payload, and split it into pubkey + signature
 *  using pk_len from the HDR8 header.  Returns false if any part is missing or
 *  inconsistent.
 */
static bool ReconstructCarrierPayload(const CTransaction& tx,
                                       PQCCommitmentType& type_out,
                                       std::vector<unsigned char>& pubkey_out,
                                       std::vector<unsigned char>& sig_out,
                                       uint32_t& carrier_input_index_out)
{
    struct CarrierPart {
        uint8_t part_index;
        PQCCarrierHeader header;
        std::vector<unsigned char> payload;
        uint32_t input_index;
    };

    std::vector<CarrierPart> parts;
    PQCCommitmentType detected_type = PQCCommitmentType::FALCON512;
    bool type_set = false;

    for (uint32_t i = 0; i < tx.vin.size(); ++i) {
        PQCCommitmentType input_type;
        PQCCarrierHeader hdr;
        std::vector<unsigned char> payload;

        if (!PQCParseCarrierPartScriptSig(tx.vin[i].scriptSig, input_type, hdr, payload)) {
            continue;
        }

        if (!type_set) {
            detected_type = input_type;
            type_set = true;
        } else if (input_type != detected_type) {
            continue; // Mixed types in same tx -- skip
        }

        CarrierPart part;
        part.part_index = hdr.part_index;
        part.header = hdr;
        part.payload = payload;
        part.input_index = i;
        parts.push_back(part);
    }

    if (parts.empty()) return false;

    // Sort by part_index
    std::sort(parts.begin(), parts.end(),
              [](const CarrierPart& a, const CarrierPart& b) {
                  return a.part_index < b.part_index;
              });

    // Verify contiguous parts
    uint8_t expected_total = parts[0].header.part_total;
    if (parts.size() != expected_total) return false;
    for (uint8_t p = 0; p < expected_total; ++p) {
        if (parts[p].part_index != p) return false;
    }

    // Reconstruct full payload
    std::vector<unsigned char> full_payload;
    for (size_t p = 0; p < parts.size(); ++p) {
        full_payload.insert(full_payload.end(), parts[p].payload.begin(), parts[p].payload.end());
    }

    uint16_t pk_len = parts[0].header.pk_len;
    if (pk_len > full_payload.size()) return false;

    pubkey_out.assign(full_payload.begin(), full_payload.begin() + pk_len);
    sig_out.assign(full_payload.begin() + pk_len, full_payload.end());

    if (pubkey_out.empty() || sig_out.empty()) return false;

    type_out = detected_type;
    carrier_input_index_out = parts[0].input_index;
    return true;
}

/** Reassemble all carrier parts from tx.vin, then verify SHA256(pk||sig) == commitment. */
bool PQCValidateCommitmentFromCarrier(const CTransaction& tx,
                                       const uint256& commitment,
                                       PQCCommitmentType& type_out,
                                       uint32_t& carrier_input_index_out,
                                       uint16_t& pk_len_out,
                                       uint16_t& sig_len_out)
{
    std::vector<unsigned char> pubkey, sig;
    if (!ReconstructCarrierPayload(tx, type_out, pubkey, sig, carrier_input_index_out))
        return false;

    // Recompute commitment
    uint256 recomputed;
    if (!PQCComputeCommitment(pubkey, sig, recomputed)) return false;
    if (recomputed != commitment) return false;

    pk_len_out = static_cast<uint16_t>(pubkey.size());
    sig_len_out = static_cast<uint16_t>(sig.size());
    return true;
}

/** Thin wrapper: reassemble carrier parts and split into pubkey + signature (no commitment check). */
bool PQCExtractKeyMaterialFromCarrier(const CTransaction& tx,
                                       PQCCommitmentType& type_out,
                                       std::vector<unsigned char>& pubkey_out,
                                       std::vector<unsigned char>& signature_out)
{
    uint32_t carrier_input_index = 0;
    return ReconstructCarrierPayload(tx, type_out, pubkey_out, signature_out, carrier_input_index);
}

/** Validate carrier commitment and verify the PQC signature over message using liboqs. */
bool PQCVerifySignatureFromCarrier(const CTransaction& tx,
                                    const uint256& commitment,
                                    const unsigned char* message, size_t message_len,
                                    PQCCommitmentType& type_out,
                                    uint32_t& carrier_input_index_out,
                                    uint16_t& pk_len_out,
                                    uint16_t& sig_len_out)
{
    std::vector<unsigned char> pubkey, sig;
    if (!ReconstructCarrierPayload(tx, type_out, pubkey, sig, carrier_input_index_out))
        return false;

    // Step 1: Validate SHA256(pk || sig) == commitment
    uint256 recomputed;
    if (!PQCComputeCommitment(pubkey, sig, recomputed)) return false;
    if (recomputed != commitment) return false;

    pk_len_out = static_cast<uint16_t>(pubkey.size());
    sig_len_out = static_cast<uint16_t>(sig.size());

    // Step 2: Verify the PQC signature over the message using liboqs
    if (!message || message_len == 0) return false;
    return PQCVerify(type_out, pubkey, message, message_len, sig);
}

// TX_BASE Reconstruction

/** Strip OP_RETURN and P2SH carrier outputs from TX_C; restore carrier cost to vout[0]. */
bool PQCReconstructTxBase(const CTransaction& txc,
                          CMutableTransaction& txBase_out,
                          CAmount& carrierCost_out)
{
    if (txc.vin.empty() || txc.vout.empty())
        return false;

    // Build the carrier scriptPubKey to identify carrier outputs
    CScript carrierSpk;
    bool haveCarrierSpk = PQCBuildCarrierScriptPubKey(carrierSpk);

    // Copy transaction metadata
    txBase_out.nVersion  = txc.nVersion;
    txBase_out.nLockTime = txc.nLockTime;
    txBase_out.vin.clear();
    txBase_out.vout.clear();

    // Copy inputs with empty scriptSig (unsigned template)
    for (const auto& vin : txc.vin) {
        CTxIn baseIn(vin.prevout, CScript(), vin.nSequence);
        txBase_out.vin.push_back(baseIn);
    }

    // Filter outputs: strip OP_RETURN and P2SH carrier outputs
    carrierCost_out = 0;
    for (const auto& vout : txc.vout) {
        // Skip OP_RETURN outputs
        if (vout.scriptPubKey.size() > 0 && vout.scriptPubKey[0] == OP_RETURN)
            continue;
        // Skip P2SH carrier outputs
        if (haveCarrierSpk && vout.scriptPubKey == carrierSpk) {
            carrierCost_out += vout.nValue;
            continue;
        }
        txBase_out.vout.push_back(vout);
    }

    if (txBase_out.vout.empty())
        return false;

    // Restore carrier cost to the first output (payment output)
    txBase_out.vout[0].nValue += carrierCost_out;
    return true;
}

/** Return the maximum signature length for a PQC type.
 *  Falcon-512 / Dilithium2 lengths come from liboqs metadata; Raccoon-G-44
 *  comes from the in-tree port's RACCOONG_SIG_BYTES constant.
 */
size_t PQCMaxSignatureLength(PQCCommitmentType type)
{
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == PQCCommitmentType::RACCOONG44) {
        return raccoong_sig_max_len();
    }
#endif
#if ENABLE_LIBOQS
    const char* alg_name = PQCGetOQSAlgorithmName(type);
    if (!alg_name) return 0;

    OQS_SIG* sig = OQS_SIG_new(alg_name);
    if (!sig) return 0;

    size_t max_len = sig->length_signature;
    OQS_SIG_free(sig);
    return max_len;
#else
    (void)type;
    return 0;
#endif
}

// liboqs PQC Cryptographic Operations (Falcon-512 and Dilithium2).
// Raccoon-G-44 is served by the in-tree port under src/raccoon_g/.

/** Return the liboqs OQS_SIG algorithm name string for a PQC type, or nullptr
 *  for types not served by liboqs (such as Raccoon-G-44). */
const char* PQCGetOQSAlgorithmName(PQCCommitmentType type)
{
#if ENABLE_LIBOQS
    switch (type) {
    case PQCCommitmentType::FALCON512:
        return OQS_SIG_alg_falcon_512;
    case PQCCommitmentType::DILITHIUM2:
        return OQS_SIG_alg_ml_dsa_44;
    default:
        return nullptr;
    }
#else
    (void)type;
    return nullptr;
#endif
}

/** Generate a PQC keypair. Falcon-512 / Dilithium2 use liboqs; Raccoon-G-44
 *  uses the in-tree port (32-byte seed -> raccoong_keygen_from_seed).
 */
bool PQCGenerateKeypair(PQCCommitmentType type,
                         std::vector<unsigned char>& public_key_out,
                         std::vector<unsigned char>& secret_key_out)
{
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == PQCCommitmentType::RACCOONG44) {
        std::lock_guard<std::mutex> lock(RaccoonGMutex());
        // Cheap belt-and-braces guard: today raccoong_is_ready() returns
        // true unconditionally, but if a future change makes it gate on
        // (e.g.) MPFR init we want to refuse silently rather than march
        // into the in-tree port with uninitialised state.
        if (!raccoong_is_ready()) return false;
        public_key_out.resize(raccoong_pk_len());
        secret_key_out.resize(raccoong_sk_len());
        uint8_t seed[32];
        if (!dogecoin_random_bytes(seed, sizeof(seed), 0)) {
            memory_cleanse(secret_key_out.data(), secret_key_out.size());
            public_key_out.clear();
            secret_key_out.clear();
            return false;
        }
        bool ok = raccoong_keygen_from_seed(seed,
                                            public_key_out.data(), public_key_out.size(),
                                            secret_key_out.data(), secret_key_out.size()) != 0;
        // Wipe the ephemeral seed.
        memory_cleanse(seed, sizeof(seed));
        if (!ok) {
            // The C port may have written partial secret material into the
            // output buffer before failing; wipe it before releasing the
            // allocation back to the standard allocator.
            memory_cleanse(secret_key_out.data(), secret_key_out.size());
            public_key_out.clear();
            secret_key_out.clear();
        }
        return ok;
    }
#endif
#if ENABLE_LIBOQS
    const char* alg_name = PQCGetOQSAlgorithmName(type);
    if (!alg_name) return false;

    OQS_SIG* sig = OQS_SIG_new(alg_name);
    if (!sig) return false;

    public_key_out.resize(sig->length_public_key);
    secret_key_out.resize(sig->length_secret_key);

    OQS_STATUS status = OQS_SIG_keypair(sig, public_key_out.data(), secret_key_out.data());
    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS) {
        public_key_out.clear();
        secret_key_out.clear();
        return false;
    }
    return true;
#else
    (void)type;
    (void)public_key_out;
    (void)secret_key_out;
    return false;
#endif
}

/** Sign message with a PQC secret key. Falcon-512 / Dilithium2 use liboqs;
 *  Raccoon-G-44 uses the in-tree port's raccoong_sign.
 *  signature_out is resized to the actual signature length after signing.
 */
bool PQCSign(PQCCommitmentType type,
             const std::vector<unsigned char>& secret_key,
             const unsigned char* message, size_t message_len,
             std::vector<unsigned char>& signature_out)
{
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == PQCCommitmentType::RACCOONG44) {
        std::lock_guard<std::mutex> lock(RaccoonGMutex());
        if (!raccoong_is_ready()) return false;
        if (secret_key.empty() || !message || message_len == 0) return false;
        if (secret_key.size() != raccoong_sk_len()) return false;
        signature_out.resize(raccoong_sig_max_len());
        size_t sig_len = signature_out.size();
        if (raccoong_sign(secret_key.data(), secret_key.size(),
                          message, message_len,
                          signature_out.data(), &sig_len) == 0) {
            signature_out.clear();
            return false;
        }
        signature_out.resize(sig_len);
        return true;
    }
#endif
#if ENABLE_LIBOQS
    const char* alg_name = PQCGetOQSAlgorithmName(type);
    if (!alg_name) return false;
    if (secret_key.empty() || !message || message_len == 0) return false;

    OQS_SIG* sig = OQS_SIG_new(alg_name);
    if (!sig) return false;

    if (secret_key.size() != sig->length_secret_key) {
        OQS_SIG_free(sig);
        return false;
    }

    signature_out.resize(sig->length_signature);
    size_t sig_len = 0;

    OQS_STATUS status = OQS_SIG_sign(sig, signature_out.data(), &sig_len,
                                      message, message_len, secret_key.data());
    OQS_SIG_free(sig);

    if (status != OQS_SUCCESS) {
        signature_out.clear();
        return false;
    }
    signature_out.resize(sig_len);
    return true;
#else
    (void)type;
    (void)secret_key;
    (void)message;
    (void)message_len;
    (void)signature_out;
    return false;
#endif
}

/** Verify a PQC signature. Falcon-512 / Dilithium2 use liboqs; Raccoon-G-44
 *  uses the in-tree port's raccoong_verify. */
const char* PQCGetVerifierName(PQCCommitmentType type)
{
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == PQCCommitmentType::RACCOONG44) {
        return "raccoong_verify()";
    }
#endif
#if ENABLE_LIBOQS
    if (PQCGetOQSAlgorithmName(type) != nullptr) {
        return "OQS_SIG_verify()";
    }
#endif
    (void)type;
    return "PQCVerify()";
}

bool PQCVerify(PQCCommitmentType type,
               const std::vector<unsigned char>& public_key,
               const unsigned char* message, size_t message_len,
               const std::vector<unsigned char>& signature)
{
#ifdef ENABLE_LIBOQS_RACCOON
    if (type == PQCCommitmentType::RACCOONG44) {
        std::lock_guard<std::mutex> lock(RaccoonGMutex());
        if (!raccoong_is_ready()) return false;
        if (public_key.empty() || !message || message_len == 0 || signature.empty()) return false;
        if (public_key.size() != raccoong_pk_len()) return false;
        return raccoong_verify(public_key.data(), public_key.size(),
                               message, message_len,
                               signature.data(), signature.size()) != 0;
    }
#endif
#if ENABLE_LIBOQS
    const char* alg_name = PQCGetOQSAlgorithmName(type);
    if (!alg_name) return false;
    if (public_key.empty() || !message || message_len == 0 || signature.empty()) return false;

    OQS_SIG* sig = OQS_SIG_new(alg_name);
    if (!sig) return false;

    if (public_key.size() != sig->length_public_key) {
        OQS_SIG_free(sig);
        return false;
    }

    OQS_STATUS status = OQS_SIG_verify(sig, message, message_len,
                                        signature.data(), signature.size(),
                                        public_key.data());
    OQS_SIG_free(sig);
    return status == OQS_SUCCESS;
#else
    (void)type;
    (void)public_key;
    (void)message;
    (void)message_len;
    (void)signature;
    return false;
#endif
}
