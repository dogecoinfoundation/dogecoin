// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2022-2023 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "transactiondesc.h"

#include "bitcoinunits.h"
#include "guiutil.h"
#include "paymentserver.h"
#include "transactionrecord.h"

#include "base58.h"
#include "chainparams.h"
#include "consensus/consensus.h"
#if ENABLE_LIBOQS
#include "pqc/pqc_commitment.h"
#include "support/experimental.h"
EXPERIMENTAL_FEATURE
#endif
#include "validation.h"
#include "script/interpreter.h"
#include "script/script.h"
#include "script/standard.h"
#include "timedata.h"
#include "util.h"
#include "utilstrencodings.h"
#include "wallet/db.h"
#include "wallet/wallet.h"

#include <stdint.h>
#include <string>

#if ENABLE_LIBOQS
/**
 * Reconstruct TX_BASE from TX_C by stripping OP_RETURN and P2SH carrier
 * outputs, restoring carrier cost to vout[0], then compute
 * sighash32 = SignatureHash(scriptPubKey_input0, TX_BASE, 0, SIGHASH_ALL).
 *
 * This matches the libdogecoin SPV verification approach per the BIP spec.
 *
 * @param txc           The commitment transaction (TX_C)
 * @param wallet        Wallet to look up input scriptPubKey and amount
 * @param sighash_out   Receives the recomputed sighash32
 * @return true on success
 */
static bool RecomputeSighash32FromTxC(const CTransaction& txc,
                                       const CWallet* wallet,
                                       uint256& sighash_out)
{
    // Use shared TX_BASE reconstruction from pqc_commitment
    CMutableTransaction txBase;
    CAmount carrierCost = 0;
    if (!PQCReconstructTxBase(txc, txBase, carrierCost))
        return false;

    if (txBase.vout.empty())
        return false;

    // Look up scriptPubKey and amount for input 0.
    // Prefer wallet history, but fall back to chain lookup for external TX_C.
    CScript scriptPubKeyInput0;
    CAmount input0Amount = 0;
    {
        auto it = wallet->mapWallet.find(txc.vin[0].prevout.hash);
        uint32_t n = txc.vin[0].prevout.n;
        if (it != wallet->mapWallet.end()) {
            if (n >= it->second.tx->vout.size())
                return false;
            scriptPubKeyInput0 = it->second.tx->vout[n].scriptPubKey;
            input0Amount = it->second.tx->vout[n].nValue;
        } else {
            CTransactionRef prevTx;
            uint256 hashBlock;
            if (!GetTransaction(txc.vin[0].prevout.hash, prevTx, Params().GetConsensus(0), hashBlock, true) || !prevTx)
                return false;
            if (n >= prevTx->vout.size())
                return false;
            scriptPubKeyInput0 = prevTx->vout[n].scriptPubKey;
            input0Amount = prevTx->vout[n].nValue;
        }
    }

    CTransaction txBaseConst(txBase);
    sighash_out = SignatureHash(scriptPubKeyInput0, txBaseConst, 0,
                                SIGHASH_ALL, input0Amount, SIGVERSION_BASE);
    return true;
}
#endif

QString TransactionDesc::FormatTxStatus(const CWalletTx& wtx)
{
    AssertLockHeld(cs_main);
    if (!CheckFinalTx(wtx))
    {
        if (wtx.tx->nLockTime < LOCKTIME_THRESHOLD)
            return tr("Open for %n more block(s)", "", wtx.tx->nLockTime - chainActive.Height());
        else
            return tr("Open until %1").arg(GUIUtil::dateTimeStr(wtx.tx->nLockTime));
    }
    else
    {
        int nDepth = wtx.GetDepthInMainChain();
        if (nDepth < 0)
            return tr("conflicted with a transaction with %1 confirmations").arg(-nDepth);
        else if (nDepth == 0)
            return tr("0/unconfirmed, %1").arg((wtx.InMempool() ? tr("in memory pool") : tr("not in memory pool"))) + (wtx.isAbandoned() ? ", "+tr("abandoned") : "");
        else if (nDepth < 6)
            return tr("%1/unconfirmed").arg(nDepth);
        else
            return tr("%1 confirmations").arg(nDepth);
    }
}

QString TransactionDesc::toHTML(CWallet *wallet, CWalletTx &wtx, TransactionRecord *rec, int unit)
{
    QString strHTML;

    LOCK2(cs_main, wallet->cs_wallet);
    strHTML.reserve(4000);
    strHTML += "<html><font face='verdana, arial, helvetica, sans-serif'>";

    int64_t nTime = wtx.GetTxTime();
    CAmount nCredit = wtx.GetCredit(ISMINE_ALL);
    CAmount nDebit = wtx.GetDebit(ISMINE_ALL);
    CAmount nNet = nCredit - nDebit;

    strHTML += "<b>" + tr("Status") + ":</b> " + FormatTxStatus(wtx);
    strHTML += "<br>";

    strHTML += "<b>" + tr("Date") + ":</b> " + (nTime ? GUIUtil::dateTimeStr(nTime) : "") + "<br>";

    //
    // From
    //
    if (wtx.IsCoinBase())
    {
        strHTML += "<b>" + tr("Source") + ":</b> " + tr("Generated") + "<br>";
    }
    else if (wtx.mapValue.count("from") && !wtx.mapValue["from"].empty())
    {
        // Online transaction
        strHTML += "<b>" + tr("From") + ":</b> " + GUIUtil::HtmlEscape(wtx.mapValue["from"]) + "<br>";
    }
    else
    {
        // Offline transaction
        if (nNet > 0)
        {
            // Credit
            if (CBitcoinAddress(rec->address).IsValid())
            {
                CTxDestination address = CBitcoinAddress(rec->address).Get();
                if (wallet->mapAddressBook.count(address))
                {
                    strHTML += "<b>" + tr("From") + ":</b> " + tr("unknown") + "<br>";
                    strHTML += "<b>" + tr("To") + ":</b> ";
                    strHTML += GUIUtil::HtmlEscape(rec->address);
                    QString addressOwned = (::IsMine(*wallet, address) == ISMINE_SPENDABLE) ? tr("own address") : tr("watch-only");
                    if (!wallet->mapAddressBook[address].name.empty())
                        strHTML += " (" + addressOwned + ", " + tr("label") + ": " + GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + ")";
                    else
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }
        }
    }

    //
    // To
    //
    if (wtx.mapValue.count("to") && !wtx.mapValue["to"].empty())
    {
        // Online transaction
        std::string strAddress = wtx.mapValue["to"];
        strHTML += "<b>" + tr("To") + ":</b> ";
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        if (wallet->mapAddressBook.count(dest) && !wallet->mapAddressBook[dest].name.empty())
            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[dest].name) + " ";
        strHTML += GUIUtil::HtmlEscape(strAddress) + "<br>";
    }

    //
    // Amount
    //
    if (wtx.IsCoinBase() && nCredit == 0)
    {
        //
        // Coinbase
        //
        CAmount nUnmatured = 0;
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            nUnmatured += wallet->GetCredit(txout, ISMINE_ALL);
        strHTML += "<b>" + tr("Credit") + ":</b> ";
        if (wtx.IsInMainChain())
            strHTML += BitcoinUnits::formatHtmlWithUnit(unit, nUnmatured)+ " (" + tr("matures in %n more block(s)", "", wtx.GetBlocksToMaturity()) + ")";
        else
            strHTML += "(" + tr("not accepted") + ")";
        strHTML += "<br>";
    }
    else if (nNet > 0)
    {
        //
        // Credit
        //
        strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet) + "<br>";
    }
    else
    {
        isminetype fAllFromMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
        {
            isminetype mine = wallet->IsMine(txin);
            if(fAllFromMe > mine) fAllFromMe = mine;
        }

        isminetype fAllToMe = ISMINE_SPENDABLE;
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
        {
            isminetype mine = wallet->IsMine(txout);
            if(fAllToMe > mine) fAllToMe = mine;
        }

        if (fAllFromMe)
        {
            if(fAllFromMe & ISMINE_WATCH_ONLY)
                strHTML += "<b>" + tr("From") + ":</b> " + tr("watch-only") + "<br>";

            //
            // Debit
            //
            BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            {
                // Ignore change
                isminetype toSelf = wallet->IsMine(txout);
                if ((toSelf == ISMINE_SPENDABLE) && (fAllFromMe == ISMINE_SPENDABLE))
                    continue;

                if (!wtx.mapValue.count("to") || wtx.mapValue["to"].empty())
                {
                    // Offline transaction
                    CTxDestination address;
                    if (ExtractDestination(txout.scriptPubKey, address))
                    {
                        strHTML += "<b>" + tr("To") + ":</b> ";
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += GUIUtil::HtmlEscape(CBitcoinAddress(address).ToString());
                        if(toSelf == ISMINE_SPENDABLE)
                            strHTML += " (" + tr("own address") + ")";
                        else if(toSelf & ISMINE_WATCH_ONLY)
                            strHTML += " (" + tr("watch-only") + ")";
                        strHTML += "<br>";
                    }
                }

                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -txout.nValue) + "<br>";
                if(toSelf)
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, txout.nValue) + "<br>";
            }

            if (fAllToMe)
            {
                // Payment to self
                CAmount nChange = wtx.GetChange();
                CAmount nValue = nCredit - nChange;
                strHTML += "<b>" + tr("Total debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nValue) + "<br>";
                strHTML += "<b>" + tr("Total credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nValue) + "<br>";
            }

            CAmount nTxFee = nDebit - wtx.tx->GetValueOut();
            if (nTxFee > 0)
                strHTML += "<b>" + tr("Transaction fee") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -nTxFee) + "<br>";
        }
        else
        {
            //
            // Mixed debit transaction
            //
            BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
                if (wallet->IsMine(txin))
                    strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
            BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
                if (wallet->IsMine(txout))
                    strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";
        }
    }

    strHTML += "<b>" + tr("Net amount") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, nNet, true) + "<br>";

    //
    // Message
    //
    if (wtx.mapValue.count("message") && !wtx.mapValue["message"].empty())
        strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["message"], true) + "<br>";
    if (wtx.mapValue.count("comment") && !wtx.mapValue["comment"].empty())
        strHTML += "<br><b>" + tr("Comment") + ":</b><br>" + GUIUtil::HtmlEscape(wtx.mapValue["comment"], true) + "<br>";

    strHTML += "<b>" + tr("Transaction ID") + ":</b> " + rec->getTxID() + "<br>";
    strHTML += "<b>" + tr("Transaction total size") + ":</b> " + QString::number(wtx.tx->GetTotalSize()) + " bytes<br>";
    strHTML += "<b>" + tr("Output index") + ":</b> " + QString::number(rec->getOutputIndex()) + "<br>";

#if ENABLE_LIBOQS
    PQCCommitmentType pqcType;
    uint256 pqcCommitment;
    uint32_t pqcOutputIndex = 0;
    bool hasPqcCommitment = PQCExtractCommitmentFromTx(*wtx.tx, pqcType, pqcCommitment, pqcOutputIndex);

    // Also detect if this transaction IS a TX_R (carrier reveal) by checking inputs for carrier scriptSig
    bool isTxR = false;
    {
        for (uint32_t i = 0; i < wtx.tx->vin.size(); ++i) {
            PQCCommitmentType inputType;
            if (PQCDetectCarrierScriptSig(wtx.tx->vin[i].scriptSig, inputType)) {
                isTxR = true;
                break;
            }
        }
    }

    if (hasPqcCommitment) {
        // TX_C display
        QString pqcTypeStr = QString::fromLatin1(PQCCommitmentTypeToString(pqcType));
        strHTML += "<br><b>" + tr("Commitment Transaction (TX_C)") + ":</b><br>";
        strHTML += "<b>" + tr("PQC algorithm") + ":</b> " + pqcTypeStr + "<br>";
        strHTML += "<b>" + tr("PQC commitment") + ":</b> " + QString::fromStdString(pqcCommitment.GetHex()) + "<br>";
        strHTML += "<b>" + tr("PQC OP_RETURN output index") + ":</b> " + QString::number(pqcOutputIndex) + "<br>";

        // Show the OP_RETURN scriptPubKey hex
        if (pqcOutputIndex < wtx.tx->vout.size()) {
            const std::string opReturnHex = HexStr(wtx.tx->vout[pqcOutputIndex].scriptPubKey.begin(),
                                                    wtx.tx->vout[pqcOutputIndex].scriptPubKey.end());
            strHTML += "<b>" + tr("OP_RETURN scriptPubKey") + ":</b> " + GUIUtil::HtmlEscape(QString::fromStdString(opReturnHex)) + "<br>";
        }

        // Find P2SH carrier output in this TX_C
        CScript carrierScriptPubKey;
        int carrierOutputIdx = -1;
        if (PQCBuildCarrierScriptPubKey(carrierScriptPubKey)) {
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                if (wtx.tx->vout[i].scriptPubKey == carrierScriptPubKey) {
                    carrierOutputIdx = static_cast<int>(i);
                    break;
                }
            }
        }

        if (carrierOutputIdx >= 0) {
            const std::string carrierSpkHex = HexStr(carrierScriptPubKey.begin(), carrierScriptPubKey.end());
            strHTML += "<b>" + tr("Carrier P2SH output index") + ":</b> " + QString::number(carrierOutputIdx) + "<br>";
            strHTML += "<b>" + tr("Carrier P2SH scriptPubKey") + ":</b> " + GUIUtil::HtmlEscape(QString::fromStdString(carrierSpkHex)) + "<br>";

            CTxDestination dest;
            if (ExtractDestination(carrierScriptPubKey, dest)) {
                strHTML += "<b>" + tr("Carrier P2SH address") + ":</b> " + GUIUtil::HtmlEscape(QString::fromStdString(CBitcoinAddress(dest).ToString())) + "<br>";
            }

            CScript redeemScript;
            if (PQCBuildCarrierRedeemScript(redeemScript)) {
                strHTML += "<b>" + tr("Carrier redeemScript") + ":</b> "
                          + GUIUtil::HtmlEscape(QString::fromStdString(HexStr(redeemScript.begin(), redeemScript.end())))
                          + " (OP_DROP×5 OP_TRUE)<br>";
            }

            strHTML += "<b>" + tr("Carrier output value") + ":</b> "
                      + BitcoinUnits::formatHtmlWithUnit(unit, wtx.tx->vout[carrierOutputIdx].nValue) + "<br>";

            // Search for TX_R that spends this carrier output
            COutPoint carrierOutpoint(wtx.tx->GetHash(), carrierOutputIdx);
            CTransactionRef txrRef;
            bool foundTxR = false;

            // Search wallet transactions for the TX_R
            {
                LOCK(wallet->cs_wallet);
                for (const auto& item : wallet->mapWallet) {
                    const CWalletTx& candidate = item.second;
                    for (const auto& vin : candidate.tx->vin) {
                        if (vin.prevout == carrierOutpoint) {
                            txrRef = candidate.tx;
                            foundTxR = true;
                            break;
                        }
                    }
                    if (foundTxR) break;
                }
            }

            if (foundTxR) {
                strHTML += "<br><b>" + tr("Reveal Transaction (TX_R)") + ":</b><br>";
                strHTML += "<b>" + tr("TX_R txid") + ":</b> " + QString::fromStdString(txrRef->GetHash().GetHex()) + "<br>";

                // Extract carrier payload from TX_R
                PQCCommitmentType txrCarrierType;
                std::vector<unsigned char> txrPubkey, txrSig;
                if (PQCExtractKeyMaterialFromCarrier(*txrRef, txrCarrierType, txrPubkey, txrSig)) {
                    strHTML += "<b>" + tr("TX_R PQC public key") + ":</b> "
                              + GUIUtil::HtmlEscape(QString::fromStdString(HexStr(txrPubkey.begin(), txrPubkey.end()))) + "<br>";
                    strHTML += "<b>" + tr("TX_R PQC public key size") + ":</b> " + QString::number(txrPubkey.size()) + " " + tr("bytes") + "<br>";
                    strHTML += "<b>" + tr("TX_R PQC signature") + ":</b> "
                              + GUIUtil::HtmlEscape(QString::fromStdString(HexStr(txrSig.begin(), txrSig.end()))) + "<br>";
                    strHTML += "<b>" + tr("TX_R PQC signature size") + ":</b> " + QString::number(txrSig.size()) + " " + tr("bytes") + "<br>";

                    // Verify commitment: SHA256(pk||sig) == commitment
                    uint256 recomputed;
                    bool commitmentMatch = false;
                    if (PQCComputeCommitment(txrPubkey, txrSig, recomputed)) {
                        commitmentMatch = (recomputed == pqcCommitment);
                        strHTML += "<b>" + tr("SHA256(pk||sig)") + ":</b> " + QString::fromStdString(recomputed.GetHex()) + "<br>";
                        strHTML += "<b>" + tr("Commitment matches") + ":</b> "
                                  + (commitmentMatch
                                      ? "<span style=\"color:green;\">" + tr("yes") + "</span>"
                                      : "<span style=\"color:red;\">" + tr("NO — MISMATCH") + "</span>") + "<br>";
                    }

                    // Perform PQ cryptographic verification (liboqs OQS_SIG_verify
                    // for Falcon/Dilithium, in-tree raccoong_verify for Raccoon-G-44).
                    // Recompute sighash32(TX_BASE) from TX_C per the BIP spec
                    // (strip OP_RETURN + carriers, restore carrier cost to vout[0])
                    bool cryptoVerified = false;
                    bool usedStoredFallback = false;
                    bool sighashMismatch = false;
                    uint256 recomputedSighash;
                    bool sighashOk = RecomputeSighash32FromTxC(*wtx.tx, wallet, recomputedSighash);
                    if (commitmentMatch && sighashOk) {
                        cryptoVerified = PQCVerify(pqcType, txrPubkey,
                                                    recomputedSighash.begin(), 32,
                                                    txrSig);
                        const std::string recomputedSighashHex = HexStr(recomputedSighash.begin(), recomputedSighash.end());
                        strHTML += "<b>" + tr("TX_BASE sighash32 (recomputed)") + ":</b> "
                                  + GUIUtil::HtmlEscape(QString::fromStdString(recomputedSighashHex)) + "<br>";

                        // Also show stored sighash for comparison if available
                        auto it = wtx.mapValue.find("pqcSigningMessage");
                        if (it != wtx.mapValue.end() && !it->second.empty()) {
                            strHTML += "<b>" + tr("TX_C sighash (stored)") + ":</b> "
                                      + GUIUtil::HtmlEscape(QString::fromStdString(it->second)) + "<br>";
                            sighashMismatch = (it->second != recomputedSighashHex);
                            if (!cryptoVerified && IsHex(it->second)) {
                                std::vector<unsigned char> storedMessageBytes = ParseHex(it->second);
                                if (storedMessageBytes.size() == 32) {
                                    bool storedVerified = PQCVerify(pqcType, txrPubkey,
                                                                    storedMessageBytes.data(), storedMessageBytes.size(),
                                                                    txrSig);
                                    if (storedVerified) {
                                        cryptoVerified = true;
                                        usedStoredFallback = true;
                                    }
                                }
                            }
                        }
                    } else if (!sighashOk) {
                        strHTML += "<b>" + tr("TX_BASE sighash32") + ":</b> "
                                  + tr("could not reconstruct TX_BASE from TX_C (input prevout not in wallet)") + "<br>";
                        // Fall back to stored sighash
                        auto it = wtx.mapValue.find("pqcSigningMessage");
                        if (it != wtx.mapValue.end() && !it->second.empty() && IsHex(it->second)) {
                            std::vector<unsigned char> messageBytes = ParseHex(it->second);
                            cryptoVerified = PQCVerify(pqcType, txrPubkey,
                                                        messageBytes.data(), messageBytes.size(),
                                                        txrSig);
                            usedStoredFallback = cryptoVerified;
                            strHTML += "<b>" + tr("TX_C sighash (stored, fallback)") + ":</b> "
                                      + GUIUtil::HtmlEscape(QString::fromStdString(it->second)) + "<br>";
                        }
                    }

                    {
                        const bool canonicalVerified = cryptoVerified && !usedStoredFallback;
                        QString oqsStatus;
                        if (canonicalVerified) {
                            oqsStatus = "<span style=\"color:green;\">" + tr("PASSED") + "</span>";
                        } else if (cryptoVerified && usedStoredFallback) {
                            oqsStatus = "<span style=\"color:#aa6600;\">"
                                      + tr("FAILED against recomputed TX_BASE sighash (only verified against stored sighash fallback)")
                                      + "</span>";
                        } else {
                            oqsStatus = "<span style=\"color:red;\">" + tr("FAILED") + "</span>";
                        }
                        strHTML += "<b>" + QString::fromLatin1(PQCGetVerifierName(pqcType)) + " " + tr("cryptographic check") + ":</b> " + oqsStatus + "<br>";
                    }
                    if (usedStoredFallback) {
                        strHTML += "<b><span style=\"color:#aa6600;\">" + tr("Verification message source") + ":</span></b> "
                                  + tr("stored TX_C sighash fallback (SPV verifiers such as libdogecoin will reject this signature)") + "<br>";
                        LogPrintf("PQC warning: TX_C %s signature verification succeeded only via stored TX_C sighash fallback; "
                                  "recomputed TX_BASE sighash does not match the signed message and SPV verifiers will reject this commitment.\n",
                                  wtx.GetHash().GetHex());
                    }
                    if (sighashMismatch) {
                        strHTML += "<b><span style=\"color:#aa0000;\">" + tr("WARNING") + ":</span></b> "
                                  + tr("TX_BASE sighash32 (recomputed from on-chain TX_C) does not match the stored TX_C sighash that was actually signed. "
                                       "The on-chain TX_C layout diverged from the TX_BASE template used for signing, so SPV verifiers "
                                       "(e.g. libdogecoin) that reconstruct TX_BASE from TX_C will reject this signature.") + "<br>";
                        LogPrintf("PQC warning: TX_C %s has TX_BASE sighash mismatch (recomputed != stored). "
                                  "SPV verifiers (e.g. libdogecoin) will reject this commitment as non-canonical.\n",
                                  wtx.GetHash().GetHex());
                    }

                    // Overall summary
                    if (commitmentMatch && cryptoVerified && !sighashMismatch && !usedStoredFallback) {
                        strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:green;\">"
                                  + tr("PASSED — commitment and cryptographic verification both verified") + "</span><br>";
                    } else if (commitmentMatch && cryptoVerified && (sighashMismatch || usedStoredFallback)) {
                        strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:#aa6600;\">"
                                  + tr("WARNING — PASSED LOCALLY (stored sighash) but FAILS SPV reconstruction; see warning above") + "</span><br>";
                    } else {
                        QString failReason;
                        if (!commitmentMatch) failReason += tr("commitment mismatch") + "; ";
                        if (!cryptoVerified) failReason += QString::fromLatin1(PQCGetVerifierName(pqcType)) + " " + tr("failed") + "; ";
                        strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:red;\">"
                                  + tr("FAILED — %1").arg(failReason) + "</span><br>";
                    }
                } else {
                    strHTML += "<b>" + tr("TX_R carrier data") + ":</b> " + tr("failed to parse carrier scriptSig") + "<br>";
                }
            } else {
                strHTML += "<b>" + tr("TX_R status") + ":</b> " + tr("not yet found (TX_R may not have been broadcast yet)") + "<br>";
            }
        } else {
            strHTML += "<b>" + tr("Carrier mode") + ":</b> " + tr("disabled (commitment-only, no P2SH carrier output)") + "<br>";
        }
    } else if (isTxR) {
        // TX_R display (this transaction is a carrier reveal)

        // Show From/To/Fee fields that the standard flow skips for TX_R
        // (carrier P2SH input is not IsMine so the normal debit/credit path
        //  only shows Credit and Net amount, missing From/To/Fee)
        {
            // From: carrier P2SH address (from the spent input)
            CScript carrierSpk;
            if (PQCBuildCarrierScriptPubKey(carrierSpk)) {
                CTxDestination carrierDest;
                if (ExtractDestination(carrierSpk, carrierDest)) {
                    strHTML += "<b>" + tr("From") + ":</b> "
                              + GUIUtil::HtmlEscape(QString::fromStdString(CBitcoinAddress(carrierDest).ToString()))
                              + " (" + tr("PQC carrier P2SH") + ")<br>";
                }
            }

            // To: output addresses
            for (unsigned int i = 0; i < wtx.tx->vout.size(); ++i) {
                CTxDestination dest;
                if (ExtractDestination(wtx.tx->vout[i].scriptPubKey, dest)) {
                    QString addressOwned = (::IsMine(*wallet, dest) == ISMINE_SPENDABLE) ? tr("own address") : "";
                    strHTML += "<b>" + tr("To") + ":</b> "
                              + GUIUtil::HtmlEscape(QString::fromStdString(CBitcoinAddress(dest).ToString()));
                    if (!addressOwned.isEmpty())
                        strHTML += " (" + addressOwned + ")";
                    strHTML += "<br>";
                }
            }

            // Transaction fee: sum of inputs - sum of outputs
            CAmount totalIn = 0;
            for (const auto& vin : wtx.tx->vin) {
                // Look up the prevout value (cs_wallet already held from LOCK2 above)
                auto it = wallet->mapWallet.find(vin.prevout.hash);
                if (it != wallet->mapWallet.end() && vin.prevout.n < it->second.tx->vout.size()) {
                    totalIn += it->second.tx->vout[vin.prevout.n].nValue;
                }
            }
            CAmount totalOut = wtx.tx->GetValueOut();
            if (totalIn > totalOut) {
                strHTML += "<b>" + tr("Transaction fee") + ":</b> "
                          + BitcoinUnits::formatHtmlWithUnit(unit, -(totalIn - totalOut)) + "<br>";
            }
        }

        strHTML += "<br><b>" + tr("Reveal Transaction (TX_R)") + ":</b><br>";

        // Extract carrier payload
        PQCCommitmentType txrType;
        std::vector<unsigned char> txrPubkey, txrSig;
        if (PQCExtractKeyMaterialFromCarrier(*wtx.tx, txrType, txrPubkey, txrSig)) {
            QString txrTypeStr = QString::fromLatin1(PQCCommitmentTypeToString(txrType));
            strHTML += "<b>" + tr("PQC algorithm") + ":</b> " + txrTypeStr + "<br>";
            strHTML += "<b>" + tr("PQC public key") + ":</b> "
                      + GUIUtil::HtmlEscape(QString::fromStdString(HexStr(txrPubkey.begin(), txrPubkey.end()))) + "<br>";
            strHTML += "<b>" + tr("PQC public key size") + ":</b> " + QString::number(txrPubkey.size()) + " " + tr("bytes") + "<br>";
            strHTML += "<b>" + tr("PQC signature") + ":</b> "
                      + GUIUtil::HtmlEscape(QString::fromStdString(HexStr(txrSig.begin(), txrSig.end()))) + "<br>";
            strHTML += "<b>" + tr("PQC signature size") + ":</b> " + QString::number(txrSig.size()) + " " + tr("bytes") + "<br>";

            // Find the TX_C by looking at the prevout of the first carrier input
            // Scan for the carrier input index
            uint32_t txrInputIdx = 0;
            for (uint32_t i = 0; i < wtx.tx->vin.size(); ++i) {
                PQCCommitmentType inputType;
                if (PQCDetectCarrierScriptSig(wtx.tx->vin[i].scriptSig, inputType)) {
                    txrInputIdx = i;
                    break;
                }
            }
            const COutPoint& prevout = wtx.tx->vin[txrInputIdx].prevout;
            strHTML += "<b>" + tr("TX_C txid") + ":</b> " + QString::fromStdString(prevout.hash.GetHex()) + "<br>";
            strHTML += "<b>" + tr("TX_C carrier output index") + ":</b> " + QString::number(prevout.n) + "<br>";

            // Look up TX_C in wallet
            uint256 txcCommitment;
            PQCCommitmentType txcType;
            bool foundCommitment = false;
            {
                LOCK(wallet->cs_wallet);
                auto it = wallet->mapWallet.find(prevout.hash);
                if (it != wallet->mapWallet.end()) {
                    uint32_t commitOutIdx = 0;
                    if (PQCExtractCommitmentFromTx(*it->second.tx, txcType, txcCommitment, commitOutIdx)) {
                        foundCommitment = true;
                        strHTML += "<b>" + tr("TX_C commitment") + ":</b> " + QString::fromStdString(txcCommitment.GetHex()) + "<br>";
                    }
                }
            }

            // Verify commitment: SHA256(pk||sig) == commitment from TX_C
            uint256 recomputed;
            bool commitmentMatch = false;
            if (PQCComputeCommitment(txrPubkey, txrSig, recomputed)) {
                strHTML += "<b>" + tr("SHA256(pk||sig)") + ":</b> " + QString::fromStdString(recomputed.GetHex()) + "<br>";
                if (foundCommitment) {
                    commitmentMatch = (recomputed == txcCommitment);
                    strHTML += "<b>" + tr("Commitment matches TX_C") + ":</b> "
                              + (commitmentMatch
                                  ? "<span style=\"color:green;\">" + tr("yes") + "</span>"
                                  : "<span style=\"color:red;\">" + tr("NO — MISMATCH") + "</span>") + "<br>";
                } else {
                    strHTML += "<b>" + tr("TX_C commitment") + ":</b> " + tr("TX_C not found in wallet") + "<br>";
                }
            }

            // Perform PQ cryptographic verification (liboqs OQS_SIG_verify
            // for Falcon/Dilithium, in-tree raccoong_verify for Raccoon-G-44).
            // Recompute sighash32(TX_BASE) from TX_C per the BIP spec
            bool cryptoVerified = false;
            bool usedStoredFallback = false;
            bool sighashMismatch = false;
            {
                CTransactionRef txcRef;
                {
                    LOCK(wallet->cs_wallet);
                    auto it = wallet->mapWallet.find(prevout.hash);
                    if (it != wallet->mapWallet.end()) {
                        txcRef = it->second.tx;
                    }
                }
                if (txcRef) {
                    uint256 recomputedSighash;
                    bool sighashOk = RecomputeSighash32FromTxC(*txcRef, wallet, recomputedSighash);
                    if (foundCommitment && commitmentMatch && sighashOk) {
                        cryptoVerified = PQCVerify(txrType, txrPubkey,
                                                    recomputedSighash.begin(), 32,
                                                    txrSig);
                        const std::string recomputedSighashHex = HexStr(recomputedSighash.begin(), recomputedSighash.end());
                        strHTML += "<b>" + tr("TX_BASE sighash32 (recomputed)") + ":</b> "
                                  + GUIUtil::HtmlEscape(QString::fromStdString(recomputedSighashHex)) + "<br>";

                        // Also show stored sighash for comparison
                        LOCK(wallet->cs_wallet);
                        auto storedIt = wallet->mapWallet.find(prevout.hash);
                        if (storedIt != wallet->mapWallet.end()) {
                            auto msgIt = storedIt->second.mapValue.find("pqcSigningMessage");
                            if (msgIt != storedIt->second.mapValue.end() && !msgIt->second.empty()) {
                                strHTML += "<b>" + tr("TX_C sighash (stored)") + ":</b> "
                                          + GUIUtil::HtmlEscape(QString::fromStdString(msgIt->second)) + "<br>";
                                sighashMismatch = (msgIt->second != recomputedSighashHex);
                                if (!cryptoVerified && IsHex(msgIt->second)) {
                                    std::vector<unsigned char> storedMessageBytes = ParseHex(msgIt->second);
                                    if (storedMessageBytes.size() == 32) {
                                        bool storedVerified = PQCVerify(txrType, txrPubkey,
                                                                        storedMessageBytes.data(), storedMessageBytes.size(),
                                                                        txrSig);
                                        if (storedVerified) {
                                            cryptoVerified = true;
                                            usedStoredFallback = true;
                                        }
                                    }
                                }
                            }
                        }
                    } else if (!sighashOk) {
                        strHTML += "<b>" + tr("TX_BASE sighash32") + ":</b> "
                                  + tr("could not reconstruct TX_BASE from TX_C (input prevout not in wallet)") + "<br>";
                        // Fall back to stored sighash
                        LOCK(wallet->cs_wallet);
                        auto storedIt = wallet->mapWallet.find(prevout.hash);
                        if (storedIt != wallet->mapWallet.end()) {
                            auto msgIt = storedIt->second.mapValue.find("pqcSigningMessage");
                            if (msgIt != storedIt->second.mapValue.end() && !msgIt->second.empty() && IsHex(msgIt->second)) {
                                std::vector<unsigned char> messageBytes = ParseHex(msgIt->second);
                                cryptoVerified = PQCVerify(txrType, txrPubkey,
                                                            messageBytes.data(), messageBytes.size(),
                                                            txrSig);
                                usedStoredFallback = cryptoVerified;
                                strHTML += "<b>" + tr("TX_C sighash (stored, fallback)") + ":</b> "
                                          + GUIUtil::HtmlEscape(QString::fromStdString(msgIt->second)) + "<br>";
                            }
                        }
                    }
                } else {
                    strHTML += "<b>" + tr("TX_BASE sighash32") + ":</b> "
                              + tr("TX_C not found in wallet — cannot verify PQC signature") + "<br>";
                }
            }

            {
                const bool canonicalVerified = cryptoVerified && !usedStoredFallback;
                QString oqsStatus;
                if (canonicalVerified) {
                    oqsStatus = "<span style=\"color:green;\">" + tr("PASSED") + "</span>";
                } else if (cryptoVerified && usedStoredFallback) {
                    oqsStatus = "<span style=\"color:#aa6600;\">"
                              + tr("FAILED against recomputed TX_BASE sighash (only verified against stored sighash fallback)")
                              + "</span>";
                } else {
                    oqsStatus = "<span style=\"color:red;\">" + tr("FAILED") + "</span>";
                }
                strHTML += "<b>" + QString::fromLatin1(PQCGetVerifierName(txrType)) + " " + tr("cryptographic check") + ":</b> " + oqsStatus + "<br>";
            }
            if (usedStoredFallback) {
                strHTML += "<b><span style=\"color:#aa6600;\">" + tr("Verification message source") + ":</span></b> "
                          + tr("stored TX_C sighash fallback (SPV verifiers such as libdogecoin will reject this signature)") + "<br>";
                LogPrintf("PQC warning: TX_R %s signature verification succeeded only via stored TX_C sighash fallback; "
                          "recomputed TX_BASE sighash does not match the signed message and SPV verifiers will reject this commitment.\n",
                          wtx.GetHash().GetHex());
            }
            if (sighashMismatch) {
                strHTML += "<b><span style=\"color:#aa0000;\">" + tr("WARNING") + ":</span></b> "
                          + tr("TX_BASE sighash32 (recomputed from on-chain TX_C) does not match the stored TX_C sighash that was actually signed. "
                               "The on-chain TX_C layout diverged from the TX_BASE template used for signing, so SPV verifiers "
                               "(e.g. libdogecoin) that reconstruct TX_BASE from TX_C will reject this signature.") + "<br>";
                LogPrintf("PQC warning: TX_R %s has TX_BASE sighash mismatch (recomputed != stored). "
                          "SPV verifiers (e.g. libdogecoin) will reject this commitment as non-canonical.\n",
                          wtx.GetHash().GetHex());
            }

            // Overall summary
            if (foundCommitment && commitmentMatch && cryptoVerified && !sighashMismatch && !usedStoredFallback) {
                strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:green;\">"
                          + tr("PASSED — commitment and cryptographic verification both verified") + "</span><br>";
            } else if (foundCommitment && commitmentMatch && cryptoVerified && (sighashMismatch || usedStoredFallback)) {
                strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:#aa6600;\">"
                          + tr("WARNING — PASSED LOCALLY (stored sighash) but FAILS SPV reconstruction; see warning above") + "</span><br>";
            } else {
                QString failReason;
                if (!foundCommitment) failReason += tr("TX_C not found") + "; ";
                if (!commitmentMatch) failReason += tr("commitment mismatch") + "; ";
                if (!cryptoVerified) failReason += QString::fromLatin1(PQCGetVerifierName(txrType)) + " " + tr("failed") + "; ";
                strHTML += "<b>" + tr("PQC signature validation") + ":</b> <span style=\"color:red;\">"
                          + tr("FAILED — %1").arg(failReason) + "</span><br>";
            }
        } else {
            strHTML += "<b>" + tr("Carrier data") + ":</b> " + tr("failed to parse carrier scriptSig") + "<br>";
        }
    } else {
        strHTML += "<b>" + tr("PQC validation") + ":</b> " + tr("no commitment detected") + "<br>";
    }
#endif

    // Message from normal bitcoin:URI (bitcoin:123...?message=example)
    for (const PAIRTYPE(std::string, std::string)& r : wtx.vOrderForm)
        if (r.first == "Message")
            strHTML += "<br><b>" + tr("Message") + ":</b><br>" + GUIUtil::HtmlEscape(r.second, true) + "<br>";

    if (wtx.IsCoinBase())
    {
        quint32 nCoinbaseMaturity = Params().GetConsensus(chainActive.Height()).nCoinbaseMaturity + 1;
        strHTML += "<br>" + tr("Generated coins must mature %1 blocks before they can be spent. When you generated this block, it was broadcast to the network to be added to the block chain. If it fails to get into the chain, its state will change to \"not accepted\" and it won't be spendable. This may occasionally happen if another node generates a block within a few seconds of yours.").arg(QString::number(nCoinbaseMaturity)) + "<br>";
    }

    //
    // Debug view
    //
    if (fDebug)
    {
        strHTML += "<hr><br>" + tr("Debug information") + "<br><br>";
        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
            if(wallet->IsMine(txin))
                strHTML += "<b>" + tr("Debit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, -wallet->GetDebit(txin, ISMINE_ALL)) + "<br>";
        BOOST_FOREACH(const CTxOut& txout, wtx.tx->vout)
            if(wallet->IsMine(txout))
                strHTML += "<b>" + tr("Credit") + ":</b> " + BitcoinUnits::formatHtmlWithUnit(unit, wallet->GetCredit(txout, ISMINE_ALL)) + "<br>";

        strHTML += "<br><b>" + tr("Transaction") + ":</b><br>";
        strHTML += GUIUtil::HtmlEscape(wtx.tx->ToString(), true);

        strHTML += "<br><b>" + tr("Inputs") + ":</b>";
        strHTML += "<ul>";

        BOOST_FOREACH(const CTxIn& txin, wtx.tx->vin)
        {
            COutPoint prevout = txin.prevout;

            CCoins prev;
            if(pcoinsTip->GetCoins(prevout.hash, prev))
            {
                if (prevout.n < prev.vout.size())
                {
                    strHTML += "<li>";
                    const CTxOut &vout = prev.vout[prevout.n];
                    CTxDestination address;
                    if (ExtractDestination(vout.scriptPubKey, address))
                    {
                        if (wallet->mapAddressBook.count(address) && !wallet->mapAddressBook[address].name.empty())
                            strHTML += GUIUtil::HtmlEscape(wallet->mapAddressBook[address].name) + " ";
                        strHTML += QString::fromStdString(CBitcoinAddress(address).ToString());
                    }
                    strHTML = strHTML + " " + tr("Amount") + "=" + BitcoinUnits::formatHtmlWithUnit(unit, vout.nValue);
                    strHTML = strHTML + " IsMine=" + (wallet->IsMine(vout) & ISMINE_SPENDABLE ? tr("true") : tr("false")) + "</li>";
                    strHTML = strHTML + " IsWatchOnly=" + (wallet->IsMine(vout) & ISMINE_WATCH_ONLY ? tr("true") : tr("false")) + "</li>";
                }
            }
        }

        strHTML += "</ul>";
    }

    strHTML += "</font></html>";
    return strHTML;
}
