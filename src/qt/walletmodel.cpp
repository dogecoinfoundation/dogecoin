// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2020-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "config/bitcoin-config.h"

#include "walletmodel.h"

#include "addresstablemodel.h"
#include "consensus/validation.h"
#include "guiconstants.h"
#include "guiutil.h"
#include "paymentserver.h"
#include "recentrequeststablemodel.h"
#include "transactiontablemodel.h"

#include "base58.h"
#include "keystore.h"
#include "script/standard.h"
#if ENABLE_LIBOQS
#include "pqc/pqc_commitment.h"
#include "support/experimental.h"
EXPERIMENTAL_FEATURE
#endif
#include "validation.h"
#include "primitives/transaction.h" // for CMutableTransaction, MakeTransactionRef
#include "net.h" // for g_connman
#include "sync.h"
#include "ui_interface.h"
#include "util.h" // for GetBoolArg
#include "wallet/coincontrol.h"
#include "wallet/wallet.h"
#include "wallet/walletdb.h" // for BackupWallet
#include "utilstrencodings.h"

#include <stdint.h>

#include <QDebug>
#include <QSet>
#include <QTimer>

#include <boost/bind/bind.hpp>
#include <boost/foreach.hpp>

WalletModel::WalletModel(const PlatformStyle *platformStyle, CWallet *_wallet, OptionsModel *_optionsModel, QObject *parent) :
    QObject(parent), wallet(_wallet), optionsModel(_optionsModel), addressTableModel(0),
    transactionTableModel(0),
    recentRequestsTableModel(0),
    cachedBalance(0), cachedUnconfirmedBalance(0), cachedImmatureBalance(0),
    cachedEncryptionStatus(Unencrypted),
    cachedNumBlocks(0)
{
    fHaveWatchOnly = wallet->HaveWatchOnly();
    fForceCheckBalanceChanged = false;

    addressTableModel = new AddressTableModel(wallet, this);
    transactionTableModel = new TransactionTableModel(platformStyle, wallet, this);
    recentRequestsTableModel = new RecentRequestsTableModel(wallet, this);

    // This timer will be fired repeatedly to update the balance
    pollTimer = new QTimer(this);
    connect(pollTimer, SIGNAL(timeout()), this, SLOT(pollBalanceChanged()));
    pollTimer->start(MODEL_UPDATE_DELAY);

    subscribeToCoreSignals();
}

WalletModel::~WalletModel()
{
    unsubscribeFromCoreSignals();
}

CAmount WalletModel::getBalance(const CCoinControl *coinControl) const
{
    if (coinControl)
    {
        CAmount nBalance = 0;
        std::vector<COutput> vCoins;
        wallet->AvailableCoins(vCoins, true, coinControl);
        BOOST_FOREACH(const COutput& out, vCoins)
            if(out.fSpendable)
                nBalance += out.tx->tx->vout[out.i].nValue;

        return nBalance;
    }

    return wallet->GetBalance();
}

CAmount WalletModel::getUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedBalance();
}

CAmount WalletModel::getImmatureBalance() const
{
    return wallet->GetImmatureBalance();
}

bool WalletModel::haveWatchOnly() const
{
    return fHaveWatchOnly;
}

CAmount WalletModel::getWatchBalance() const
{
    return wallet->GetWatchOnlyBalance();
}

CAmount WalletModel::getWatchUnconfirmedBalance() const
{
    return wallet->GetUnconfirmedWatchOnlyBalance();
}

CAmount WalletModel::getWatchImmatureBalance() const
{
    return wallet->GetImmatureWatchOnlyBalance();
}

void WalletModel::updateStatus()
{
    EncryptionStatus newEncryptionStatus = getEncryptionStatus();

    if(cachedEncryptionStatus != newEncryptionStatus)
        Q_EMIT encryptionStatusChanged(newEncryptionStatus);
}

void WalletModel::pollBalanceChanged()
{
    // Get required locks upfront. This avoids the GUI from getting stuck on
    // periodical polls if the core is holding the locks for a longer time -
    // for example, during a wallet rescan.
    TRY_LOCK(cs_main, lockMain);
    if(!lockMain)
        return;
    TRY_LOCK(wallet->cs_wallet, lockWallet);
    if(!lockWallet)
        return;

    if(fForceCheckBalanceChanged || chainActive.Height() != cachedNumBlocks)
    {
        fForceCheckBalanceChanged = false;

        // Balance and number of transactions might have changed
        cachedNumBlocks = chainActive.Height();

        checkBalanceChanged();
        if(transactionTableModel)
            transactionTableModel->updateConfirmations();
    }
}

void WalletModel::checkBalanceChanged()
{
    CAmount newBalance = getBalance();
    CAmount newUnconfirmedBalance = getUnconfirmedBalance();
    CAmount newImmatureBalance = getImmatureBalance();
    CAmount newWatchOnlyBalance = 0;
    CAmount newWatchUnconfBalance = 0;
    CAmount newWatchImmatureBalance = 0;
    if (haveWatchOnly())
    {
        newWatchOnlyBalance = getWatchBalance();
        newWatchUnconfBalance = getWatchUnconfirmedBalance();
        newWatchImmatureBalance = getWatchImmatureBalance();
    }

    if(cachedBalance != newBalance || cachedUnconfirmedBalance != newUnconfirmedBalance || cachedImmatureBalance != newImmatureBalance ||
        cachedWatchOnlyBalance != newWatchOnlyBalance || cachedWatchUnconfBalance != newWatchUnconfBalance || cachedWatchImmatureBalance != newWatchImmatureBalance)
    {
        cachedBalance = newBalance;
        cachedUnconfirmedBalance = newUnconfirmedBalance;
        cachedImmatureBalance = newImmatureBalance;
        cachedWatchOnlyBalance = newWatchOnlyBalance;
        cachedWatchUnconfBalance = newWatchUnconfBalance;
        cachedWatchImmatureBalance = newWatchImmatureBalance;
        Q_EMIT balanceChanged(newBalance, newUnconfirmedBalance, newImmatureBalance,
                            newWatchOnlyBalance, newWatchUnconfBalance, newWatchImmatureBalance);
    }
}

void WalletModel::updateTransaction()
{
    // Balance and number of transactions might have changed
    fForceCheckBalanceChanged = true;
}

void WalletModel::updateAddressBook(const QString &address, const QString &label,
        bool isMine, const QString &purpose, int status)
{
    if(addressTableModel)
        addressTableModel->updateEntry(address, label, isMine, purpose, status);
}

void WalletModel::updateWatchOnlyFlag(bool fHaveWatchonly)
{
    fHaveWatchOnly = fHaveWatchonly;
    Q_EMIT notifyWatchonlyChanged(fHaveWatchonly);
}

bool WalletModel::validateAddress(const QString &address)
{
    CBitcoinAddress addressParsed(address.toStdString());
    return addressParsed.IsValid();
}

WalletModel::SendCoinsReturn WalletModel::prepareTransaction(WalletModelTransaction &transaction, const CCoinControl *coinControl)
{
    CAmount total = 0;
    bool fSubtractFeeFromAmount = false;
    QList<SendCoinsRecipient> recipients = transaction.getRecipients();
    std::vector<CRecipient> vecSend;

    if(recipients.empty())
    {
        return OK;
    }

    QSet<QString> setAddress; // Used to detect duplicates
    int nAddresses = 0;

    // Pre-check input data for validity
    Q_FOREACH(const SendCoinsRecipient &rcp, recipients)
    {
        if (rcp.fSubtractFeeFromAmount)
            fSubtractFeeFromAmount = true;

        if(!validateAddress(rcp.address))
        {
            return InvalidAddress;
        }
        if(rcp.amount <= 0)
        {
            return InvalidAmount;
        }
        setAddress.insert(rcp.address);
        ++nAddresses;

        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
        CRecipient recipient = {scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount};
        vecSend.push_back(recipient);

        total += rcp.amount;

    }
    Q_FOREACH(const SendCoinsRecipient &rcp, recipients)
    {
        if (!rcp.includePqcCommitment) {
            continue;
        }
        if (!IsHex(rcp.pqcCommitmentScriptPubKey.toStdString())) {
            return InvalidAmount;
        }
        std::vector<unsigned char> scriptBytes = ParseHex(rcp.pqcCommitmentScriptPubKey.toStdString());
        if (scriptBytes.empty()) {
            return InvalidAmount;
        }
        CScript scriptPubKey(scriptBytes.begin(), scriptBytes.end());
        CRecipient recipient = {scriptPubKey, 0, false};
        vecSend.push_back(recipient);

        // Add P2SH carrier output(s) when carrier mode is enabled
#if ENABLE_LIBOQS
        if (rcp.pqcCarrierMode) {
            CScript carrierScriptPubKey;
            if (PQCBuildCarrierScriptPubKey(carrierScriptPubKey)) {
                // One carrier output per part needed (1 DOGE each to avoid dust rejection)
                uint8_t parts = rcp.pqcCarrierParts > 0 ? rcp.pqcCarrierParts : 1;
                for (uint8_t p = 0; p < parts; ++p) {
                    CRecipient carrierRecipient = {carrierScriptPubKey, 100000000, false};
                    vecSend.push_back(carrierRecipient);
                }
            }
        }
#endif
        break;
    }
    if(setAddress.size() != nAddresses)
    {
        return DuplicateAddress;
    }

    CAmount nBalance = getBalance(coinControl);

    if(total > nBalance)
    {
        return AmountExceedsBalance;
    }

    {
        LOCK2(cs_main, wallet->cs_wallet);

        transaction.newPossibleKeyChange(wallet);

        CAmount nFeeRequired = 0;
        // Honor an explicit change-position request from the caller's
        // CoinControl (used by the PQC carrier flow to keep TX_C layout
        // identical to the signed TX_BASE template). Default -1 means
        // CreateTransaction will pick a random position.
        int nChangePosRet = (coinControl && coinControl->nChangePosition >= 0)
                            ? coinControl->nChangePosition : -1;
        std::string strFailReason;

        CWalletTx *newTx = transaction.getTransaction();
        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        bool fCreated = wallet->CreateTransaction(vecSend, *newTx, *keyChange, nFeeRequired, nChangePosRet, strFailReason, coinControl);
        transaction.setTransactionFee(nFeeRequired);
        if (fSubtractFeeFromAmount && fCreated)
            transaction.reassignAmounts(nChangePosRet);

        if(!fCreated)
        {
            if(!fSubtractFeeFromAmount && (total + nFeeRequired) > nBalance)
            {
                return SendCoinsReturn(AmountWithFeeExceedsBalance);
            }
            Q_EMIT message(tr("Send Coins"), QString::fromStdString(strFailReason),
                         CClientUIInterface::MSG_ERROR);
            return TransactionCreationFailed;
        }

        // reject absurdly high fee. (This can never happen because the
        // wallet caps the fee at maxTxFee. This merely serves as a
        // belt-and-suspenders check)
        if (nFeeRequired > maxTxFee)
            return AbsurdFee;
    }

    return SendCoinsReturn(OK);
}

#if ENABLE_LIBOQS
bool WalletModel::prepareBaseTransaction(const QList<SendCoinsRecipient>& recipients,
                                          const CCoinControl *coinControl,
                                          CMutableTransaction& txBase_out,
                                          CScript& scriptPubKeyForInput0_out,
                                          CAmount& input0Amount_out,
                                          std::vector<COutPoint>& selectedCoins_out,
                                          CAmount& nFeeRet_out,
                                          QString& error_out,
                                          CTxDestination& changeAddr_out,
                                          int& nChangePosRet_out,
                                          uint32_t& nLockTimeRet_out,
                                          PQCCommitmentType pqcType,
                                          uint8_t carrierParts,
                                          bool carrierMode)
{
    // Build vecSend with payment outputs + dummy OP_RETURN + carrier outputs.
    // This mirrors what prepareTransaction will build for the real TX_C,
    // so that the reconstructed TX_BASE matches on both signer and verifier.
    std::vector<CRecipient> vecSend;
    for (const auto& rcp : recipients) {
        if (!validateAddress(rcp.address)) {
            error_out = tr("Invalid address");
            return false;
        }
        if (rcp.amount <= 0) {
            error_out = tr("Invalid amount");
            return false;
        }
        CScript scriptPubKey = GetScriptForDestination(CBitcoinAddress(rcp.address.toStdString()).Get());
        vecSend.push_back({scriptPubKey, rcp.amount, rcp.fSubtractFeeFromAmount});
    }

    // Dummy OP_RETURN commitment (same size as real: 36 bytes for tag+hash)
    uint256 dummyCommitment;
    CScript dummyCommitScript;
    if (!PQCBuildCommitmentScript(pqcType, dummyCommitment, dummyCommitScript)) {
        error_out = tr("Failed to build dummy commitment script");
        return false;
    }
    vecSend.push_back({dummyCommitScript, 0, false});

    // Add carrier outputs (1 DOGE each) if carrier mode is enabled
    if (carrierMode && carrierParts > 0) {
        CScript carrierScriptPubKey;
        if (PQCBuildCarrierScriptPubKey(carrierScriptPubKey)) {
            for (uint8_t p = 0; p < carrierParts; ++p) {
                vecSend.push_back({carrierScriptPubKey, 100000000, false}); // 1 DOGE
            }
        }
    }

    LOCK2(cs_main, wallet->cs_wallet);

    CWalletTx wtxDummy;
    wtxDummy.fTimeReceivedIsTxTime = true;
    wtxDummy.BindWallet(wallet);
    CReserveKey reserveKey(wallet);
    // Seed the change position from the caller's CoinControl hint (if any),
    // so successive calls (resolving the final carrier part count) can
    // converge on a stable change layout that the real TX_C can reuse.
    int nChangePosRet = (coinControl && coinControl->nChangePosition >= 0)
                        ? coinControl->nChangePosition : -1;
    std::string strFailReason;

    // Create unsigned transaction (sign=false) to get TX_C structure
    bool fCreated = wallet->CreateTransaction(vecSend, wtxDummy, reserveKey, nFeeRet_out,
                                               nChangePosRet, strFailReason, coinControl, false);
    // Keep the reserve key so the same change address is available for later
    reserveKey.KeepKey();

    if (!fCreated) {
        error_out = QString::fromStdString(strFailReason);
        return false;
    }

    // Expose the chosen change position so the caller can force the
    // final TX_C to use the identical layout (otherwise CreateTransaction's
    // random change-position placement breaks TX_BASE reconstruction).
    nChangePosRet_out = nChangePosRet;

    // Expose the chosen nLockTime so the caller can pin the final TX_C to
    // the exact same locktime used when signing the TX_BASE template.
    // Without this, GetLocktimeForNewTransaction()'s ~10% locktime
    // back-dating can cause the final TX_C's nLockTime to drift from the
    // signed template, breaking sighash32(TX_BASE) reconstruction on SPV
    // verifiers such as libdogecoin.
    nLockTimeRet_out = wtxDummy.tx->nLockTime;

    // Extract change destination for reuse in the final TX_C
    changeAddr_out = CNoDestination();
    if (nChangePosRet >= 0 && static_cast<unsigned>(nChangePosRet) < wtxDummy.tx->vout.size()) {
        CTxDestination dest;
        if (ExtractDestination(wtxDummy.tx->vout[nChangePosRet].scriptPubKey, dest)) {
            changeAddr_out = dest;
        }
    }

    // Get coin selection
    selectedCoins_out.clear();
    if (wtxDummy.tx->vin.empty()) {
        error_out = tr("Transaction has no inputs");
        return false;
    }
    for (const auto& txin : wtxDummy.tx->vin) {
        selectedCoins_out.push_back(txin.prevout);
    }

    // Look up the first input's prevout for scriptPubKey and amount
    const COutPoint& prevout0 = wtxDummy.tx->vin[0].prevout;
    auto it = wallet->mapWallet.find(prevout0.hash);
    if (it == wallet->mapWallet.end()) {
        error_out = tr("Could not find first input in wallet");
        return false;
    }
    if (prevout0.n >= it->second.tx->vout.size()) {
        error_out = tr("Input index out of range");
        return false;
    }
    scriptPubKeyForInput0_out = it->second.tx->vout[prevout0.n].scriptPubKey;
    input0Amount_out = it->second.tx->vout[prevout0.n].nValue;

    // Reconstruct TX_BASE from the unsigned TX_C using the BIP spec approach:
    // strip OP_RETURN + carriers, restore carrier cost to vout[0]
    CAmount carrierCost = 0;
    if (!PQCReconstructTxBase(*wtxDummy.tx, txBase_out, carrierCost)) {
        error_out = tr("Failed to reconstruct TX_BASE from TX_C");
        return false;
    }

    return true;
}
#endif

WalletModel::SendCoinsReturn WalletModel::sendCoins(WalletModelTransaction &transaction)
{
    QByteArray transaction_array; /* store serialized transaction */

    {
        LOCK2(cs_main, wallet->cs_wallet);
        CWalletTx *newTx = transaction.getTransaction();

        Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
        {
            if (!rcp.message.isEmpty()) // Message from normal bitcoin:URI (bitcoin:123...?message=example)
                newTx->vOrderForm.push_back(make_pair("Message", rcp.message.toStdString()));
        }

        CReserveKey *keyChange = transaction.getPossibleKeyChange();
        CValidationState state;
        if(!wallet->CommitTransaction(*newTx, *keyChange, g_connman.get(), state))
            return SendCoinsReturn(TransactionCommitFailed, QString::fromStdString(state.GetRejectReason()));

        CDataStream ssTx(SER_NETWORK, PROTOCOL_VERSION);
        ssTx << *newTx->tx;
        transaction_array.append(&(ssTx[0]), ssTx.size());
    }

    // Add addresses / update labels that we've sent to the address book,
    // and emit coinsSent signal for each recipient
    Q_FOREACH(const SendCoinsRecipient &rcp, transaction.getRecipients())
    {
        std::string strAddress = rcp.address.toStdString();
        CTxDestination dest = CBitcoinAddress(strAddress).Get();
        std::string strLabel = rcp.label.toStdString();
        {
            LOCK(wallet->cs_wallet);

            std::map<CTxDestination, CAddressBookData>::iterator mi = wallet->mapAddressBook.find(dest);

            // Check if we have a new address or an updated label
            if (mi == wallet->mapAddressBook.end())
            {
                wallet->SetAddressBook(dest, strLabel, "send");
            }
            else if (mi->second.name != strLabel)
            {
                wallet->SetAddressBook(dest, strLabel, ""); // "" means don't change purpose
            }
        }
        Q_EMIT coinsSent(wallet, rcp, transaction_array);
    }
    checkBalanceChanged(); // update balance immediately, otherwise there could be a short noticeable delay until pollBalanceChanged hits

    return SendCoinsReturn(OK);
}

#if ENABLE_LIBOQS
bool WalletModel::sendCarrierTx(const CTransaction& txc,
                                 PQCCommitmentType pqcType,
                                 const std::vector<unsigned char>& pubkey,
                                 const std::vector<unsigned char>& signature,
                                 uint256& txr_txid_out,
                                 QString& error_out)
{
    // Step 1: Find ALL P2SH carrier outputs in TX_C
    CScript carrierScriptPubKey;
    if (!PQCBuildCarrierScriptPubKey(carrierScriptPubKey)) {
        error_out = tr("Failed to build carrier scriptPubKey");
        return false;
    }

    std::vector<std::pair<int, CAmount> > carrierOutputs; // (index, value)
    for (unsigned int i = 0; i < txc.vout.size(); ++i) {
        if (txc.vout[i].scriptPubKey == carrierScriptPubKey) {
            carrierOutputs.push_back(std::make_pair(static_cast<int>(i), txc.vout[i].nValue));
        }
    }
    if (carrierOutputs.empty()) {
        error_out = tr("No P2SH carrier output found in TX_C");
        return false;
    }

    // Step 2: Compute number of carrier parts needed
    size_t payloadSize = pubkey.size() + signature.size();
    uint8_t partsNeeded = PQCCarrierPartsNeeded(payloadSize);
    if (partsNeeded == 0) {
        error_out = tr("Invalid PQC payload size");
        return false;
    }

    if (static_cast<size_t>(partsNeeded) > carrierOutputs.size()) {
        error_out = tr("TX_C has %1 carrier output(s) but %2 needed for payload")
            .arg(carrierOutputs.size()).arg(partsNeeded);
        return false;
    }

    // Step 3: Build TX_R as a raw transaction with one input per carrier part
    CMutableTransaction txr;
    txr.nVersion = 1;
    txr.nLockTime = 0;

    CAmount totalCarrierValue = 0;
    for (uint8_t p = 0; p < partsNeeded; ++p) {
        CTxIn carrierInput(COutPoint(txc.GetHash(), carrierOutputs[p].first), CScript(), CTxIn::SEQUENCE_FINAL);
        txr.vin.push_back(carrierInput);
        totalCarrierValue += carrierOutputs[p].second;
    }

    // Step 4: Build carrier scriptSig for each part
    for (uint8_t p = 0; p < partsNeeded; ++p) {
        CScript carrierScriptSig;
        if (!PQCBuildCarrierPartScriptSig(pqcType, pubkey, signature, p, carrierScriptSig)) {
            error_out = tr("Failed to build carrier scriptSig for part %1").arg(p);
            return false;
        }
        txr.vin[p].scriptSig = carrierScriptSig;
    }

    // Step 5: Estimate fee and set output
    // Get a change address from the wallet first (to estimate full tx size)
    CPubKey changePubKey;
    {
        LOCK(wallet->cs_wallet);
        if (!wallet->GetKeyFromPool(changePubKey)) {
            error_out = tr("Failed to get change address from wallet keypool");
            return false;
        }
    }
    CScript changeScript = GetScriptForDestination(changePubKey.GetID());
    txr.vout.push_back(CTxOut(0, changeScript)); // placeholder value

    // Serialize to estimate size
    CTransaction txrTemp(txr);
    unsigned int txrSize = ::GetSerializeSize(txrTemp, SER_NETWORK, PROTOCOL_VERSION);
    CAmount fee = static_cast<CAmount>(txrSize) * PQC_CARRIER_FEE_RATE;
    if (fee < PQC_CARRIER_MIN_FEE) fee = PQC_CARRIER_MIN_FEE;

    CAmount outputValue = totalCarrierValue - fee;
    if (outputValue <= 0) {
        error_out = tr("Carrier output value too small to cover TX_R fee");
        return false;
    }
    txr.vout[0].nValue = outputValue;

    // Step 6: Submit to mempool and relay
    CTransactionRef txrRef = MakeTransactionRef(std::move(txr));
    txr_txid_out = txrRef->GetHash();

    {
        CValidationState state;
        bool fMissingInputs = false;
        LOCK(cs_main);
        if (!AcceptToMemoryPool(mempool, state, txrRef, false /* fLimitFree */,
                                &fMissingInputs, nullptr /* plTxnReplaced */,
                                false /* fOverrideMempoolLimit */,
                                0 /* nAbsurdFee */)) {
            error_out = tr("TX_R rejected from mempool: %1").arg(QString::fromStdString(state.GetRejectReason()));
            return false;
        }
    }

    // Add to wallet so it appears in transaction list
    {
        LOCK(wallet->cs_wallet);
        CWalletTx wtxr(wallet, txrRef);
        wallet->AddToWallet(wtxr, false);
    }

    // Relay to peers
    if (g_connman) {
        CInv inv(MSG_TX, txr_txid_out);
        g_connman->ForEachNode([&inv](CNode* pnode) {
            pnode->PushInventory(inv);
        });
    }

    LogPrintf("PQC: TX_R broadcast successfully: %s (spending %d TX_C carrier output(s) from %s)\n",
              txr_txid_out.GetHex(), partsNeeded, txc.GetHash().GetHex());

    return true;
}
#endif

OptionsModel *WalletModel::getOptionsModel()
{
    return optionsModel;
}

AddressTableModel *WalletModel::getAddressTableModel()
{
    return addressTableModel;
}

TransactionTableModel *WalletModel::getTransactionTableModel()
{
    return transactionTableModel;
}

RecentRequestsTableModel *WalletModel::getRecentRequestsTableModel()
{
    return recentRequestsTableModel;
}

WalletModel::EncryptionStatus WalletModel::getEncryptionStatus() const
{
    if(!wallet->IsCrypted())
    {
        return Unencrypted;
    }
    else if(wallet->IsLocked())
    {
        return Locked;
    }
    else
    {
        return Unlocked;
    }
}

bool WalletModel::setWalletEncrypted(bool encrypted, const SecureString &passphrase)
{
    if(encrypted)
    {
        // Encrypt
        return wallet->EncryptWallet(passphrase);
    }
    else
    {
        // Decrypt -- TODO; not supported yet
        return false;
    }
}

bool WalletModel::setWalletLocked(bool locked, const SecureString &passPhrase)
{
    if(locked)
    {
        // Lock
        return wallet->Lock();
    }
    else
    {
        // Unlock
        return wallet->Unlock(passPhrase);
    }
}

bool WalletModel::changePassphrase(const SecureString &oldPass, const SecureString &newPass)
{
    bool retval;
    {
        LOCK(wallet->cs_wallet);
        wallet->Lock(); // Make sure wallet is locked before attempting pass change
        retval = wallet->ChangeWalletPassphrase(oldPass, newPass);
    }
    return retval;
}

bool WalletModel::backupWallet(const QString &filename)
{
    return wallet->BackupWallet(filename.toLocal8Bit().data());
}

// Handlers for core signals
static void NotifyKeyStoreStatusChanged(WalletModel *walletmodel, CCryptoKeyStore *wallet)
{
    qDebug() << "NotifyKeyStoreStatusChanged";
    QMetaObject::invokeMethod(walletmodel, "updateStatus", Qt::QueuedConnection);
}

static void NotifyAddressBookChanged(WalletModel *walletmodel, CWallet *wallet,
        const CTxDestination &address, const std::string &label, bool isMine,
        const std::string &purpose, ChangeType status)
{
    QString strAddress = QString::fromStdString(CBitcoinAddress(address).ToString());
    QString strLabel = QString::fromStdString(label);
    QString strPurpose = QString::fromStdString(purpose);

    qDebug() << "NotifyAddressBookChanged: " + strAddress + " " + strLabel + " isMine=" + QString::number(isMine) + " purpose=" + strPurpose + " status=" + QString::number(status);
    QMetaObject::invokeMethod(walletmodel, "updateAddressBook", Qt::QueuedConnection,
                              Q_ARG(QString, strAddress),
                              Q_ARG(QString, strLabel),
                              Q_ARG(bool, isMine),
                              Q_ARG(QString, strPurpose),
                              Q_ARG(int, status));
}

static void NotifyTransactionChanged(WalletModel *walletmodel, CWallet *wallet, const uint256 &hash, ChangeType status)
{
    Q_UNUSED(wallet);
    Q_UNUSED(hash);
    Q_UNUSED(status);
    QMetaObject::invokeMethod(walletmodel, "updateTransaction", Qt::QueuedConnection);
}

static void ShowProgress(WalletModel *walletmodel, const std::string &title, int nProgress)
{
    // emits signal "showProgress"
    QMetaObject::invokeMethod(walletmodel, "showProgress", Qt::QueuedConnection,
                              Q_ARG(QString, QString::fromStdString(title)),
                              Q_ARG(int, nProgress));
}

static void NotifyWatchonlyChanged(WalletModel *walletmodel, bool fHaveWatchonly)
{
    QMetaObject::invokeMethod(walletmodel, "updateWatchOnlyFlag", Qt::QueuedConnection,
                              Q_ARG(bool, fHaveWatchonly));
}

void WalletModel::subscribeToCoreSignals()
{
    // Connect signals to wallet
    wallet->NotifyStatusChanged.connect(boost::bind(&NotifyKeyStoreStatusChanged, this,
                                                    boost::placeholders::_1));
    wallet->NotifyAddressBookChanged.connect(boost::bind(NotifyAddressBookChanged, this,
                                                         boost::placeholders::_1,
                                                         boost::placeholders::_2,
                                                         boost::placeholders::_3,
                                                         boost::placeholders::_4,
                                                         boost::placeholders::_5,
                                                         boost::placeholders::_6));
    wallet->NotifyTransactionChanged.connect(boost::bind(NotifyTransactionChanged, this,
                                                         boost::placeholders::_1,
                                                         boost::placeholders::_2,
                                                         boost::placeholders::_3));
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this, boost::placeholders::_1,
                                             boost::placeholders::_2));
    wallet->NotifyWatchonlyChanged.connect(boost::bind(NotifyWatchonlyChanged, this,
                                                       boost::placeholders::_1));
}

void WalletModel::unsubscribeFromCoreSignals()
{
    // Disconnect signals from wallet
    wallet->NotifyStatusChanged.disconnect(boost::bind(&NotifyKeyStoreStatusChanged, this,
                                                       boost::placeholders::_1));
    wallet->NotifyAddressBookChanged.disconnect(boost::bind(NotifyAddressBookChanged, this,
                                                            boost::placeholders::_1,
                                                            boost::placeholders::_2,
                                                            boost::placeholders::_3,
                                                            boost::placeholders::_4,
                                                            boost::placeholders::_5,
                                                            boost::placeholders::_6));
    wallet->NotifyTransactionChanged.disconnect(boost::bind(NotifyTransactionChanged, this,
                                                            boost::placeholders::_1,
                                                            boost::placeholders::_2,
                                                            boost::placeholders::_3));
    wallet->ShowProgress.disconnect(boost::bind(ShowProgress, this,
                                                boost::placeholders::_1,
                                                boost::placeholders::_2));
    wallet->NotifyWatchonlyChanged.disconnect(boost::bind(NotifyWatchonlyChanged, this,
                                                          boost::placeholders::_1));
}

// WalletModel::UnlockContext implementation
WalletModel::UnlockContext WalletModel::requestUnlock()
{
    bool was_locked = getEncryptionStatus() == Locked;
    if(was_locked)
    {
        // Request UI to unlock wallet
        Q_EMIT requireUnlock();
    }
    // If wallet is still locked, unlock was failed or cancelled, mark context as invalid
    bool valid = getEncryptionStatus() != Locked;

    return UnlockContext(this, valid, was_locked);
}

WalletModel::UnlockContext::UnlockContext(WalletModel *_wallet, bool _valid, bool _relock):
        wallet(_wallet),
        valid(_valid),
        relock(_relock)
{
}

WalletModel::UnlockContext::~UnlockContext()
{
    if(valid && relock)
    {
        wallet->setWalletLocked(true);
    }
}

void WalletModel::UnlockContext::CopyFrom(const UnlockContext& rhs)
{
    // Transfer context; old object no longer relocks wallet
    *this = rhs;
    rhs.relock = false;
}

bool WalletModel::getPubKey(const CKeyID &address, CPubKey& vchPubKeyOut) const
{
    return wallet->GetPubKey(address, vchPubKeyOut);
}

bool WalletModel::havePrivKey(const CKeyID &address) const
{
    return wallet->HaveKey(address);
}

bool WalletModel::getPrivKey(const CKeyID &address, CKey& vchPrivKeyOut) const
{
    return wallet->GetKey(address, vchPrivKeyOut);
}

// returns a list of COutputs from COutPoints
void WalletModel::getOutputs(const std::vector<COutPoint>& vOutpoints, std::vector<COutput>& vOutputs)
{
    LOCK2(cs_main, wallet->cs_wallet);
    BOOST_FOREACH(const COutPoint& outpoint, vOutpoints)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);
        vOutputs.push_back(out);
    }
}

bool WalletModel::isSpent(const COutPoint& outpoint) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsSpent(outpoint.hash, outpoint.n);
}

// AvailableCoins + LockedCoins grouped by wallet address (put change in one group with wallet address)
void WalletModel::listCoins(std::map<QString, std::vector<COutput> >& mapCoins) const
{
    std::vector<COutput> vCoins;
    wallet->AvailableCoins(vCoins);

    LOCK2(cs_main, wallet->cs_wallet); // ListLockedCoins, mapWallet
    std::vector<COutPoint> vLockedCoins;
    wallet->ListLockedCoins(vLockedCoins);

    // add locked coins
    BOOST_FOREACH(const COutPoint& outpoint, vLockedCoins)
    {
        if (!wallet->mapWallet.count(outpoint.hash)) continue;
        int nDepth = wallet->mapWallet[outpoint.hash].GetDepthInMainChain();
        if (nDepth < 0) continue;
        COutput out(&wallet->mapWallet[outpoint.hash], outpoint.n, nDepth, true, true);
        if (outpoint.n < out.tx->tx->vout.size() && wallet->IsMine(out.tx->tx->vout[outpoint.n]) == ISMINE_SPENDABLE)
            vCoins.push_back(out);
    }

    BOOST_FOREACH(const COutput& out, vCoins)
    {
        COutput cout = out;

        while (wallet->IsChange(cout.tx->tx->vout[cout.i]) && cout.tx->tx->vin.size() > 0 && wallet->IsMine(cout.tx->tx->vin[0]))
        {
            if (!wallet->mapWallet.count(cout.tx->tx->vin[0].prevout.hash)) break;
            cout = COutput(&wallet->mapWallet[cout.tx->tx->vin[0].prevout.hash], cout.tx->tx->vin[0].prevout.n, 0, true, true);
        }

        CTxDestination address;
        if(!out.fSpendable || !ExtractDestination(cout.tx->tx->vout[cout.i].scriptPubKey, address))
            continue;
        mapCoins[QString::fromStdString(CBitcoinAddress(address).ToString())].push_back(out);
    }
}

bool WalletModel::isLockedCoin(uint256 hash, unsigned int n) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->IsLockedCoin(hash, n);
}

void WalletModel::lockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->LockCoin(output);
}

void WalletModel::unlockCoin(COutPoint& output)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->UnlockCoin(output);
}

void WalletModel::listLockedCoins(std::vector<COutPoint>& vOutpts)
{
    LOCK2(cs_main, wallet->cs_wallet);
    wallet->ListLockedCoins(vOutpts);
}

void WalletModel::loadReceiveRequests(std::vector<std::string>& vReceiveRequests)
{
    LOCK(wallet->cs_wallet);
    BOOST_FOREACH(const PAIRTYPE(CTxDestination, CAddressBookData)& item, wallet->mapAddressBook)
        BOOST_FOREACH(const PAIRTYPE(std::string, std::string)& item2, item.second.destdata)
            if (item2.first.size() > 2 && item2.first.substr(0,2) == "rr") // receive request
                vReceiveRequests.push_back(item2.second);
}

bool WalletModel::saveReceiveRequest(const std::string &sAddress, const int64_t nId, const std::string &sRequest)
{
    CTxDestination dest = CBitcoinAddress(sAddress).Get();

    std::stringstream ss;
    ss << nId;
    std::string key = "rr" + ss.str(); // "rr" prefix = "receive request" in destdata

    LOCK(wallet->cs_wallet);
    if (sRequest.empty())
        return wallet->EraseDestData(dest, key);
    else
        return wallet->AddDestData(dest, key, sRequest);
}

bool WalletModel::getWalletMeta(const std::string &key, std::string *value) const
{
    LOCK(wallet->cs_wallet);
    if (!wallet->vchDefaultKey.IsValid()) {
        return false;
    }
    const CTxDestination dest = wallet->vchDefaultKey.GetID();
    return wallet->GetDestData(dest, key, value);
}

bool WalletModel::saveWalletMeta(const std::string &key, const std::string &value)
{
    LOCK(wallet->cs_wallet);
    if (!wallet->vchDefaultKey.IsValid()) {
        return false;
    }
    const CTxDestination dest = wallet->vchDefaultKey.GetID();
    bool ok = false;
    if (value.empty())
        ok = wallet->EraseDestData(dest, key);
    else
        ok = wallet->AddDestData(dest, key, value);
    if (ok) {
        Q_EMIT walletMetaChanged(QString::fromStdString(key));
    }
    return ok;
}

std::vector<std::pair<std::string, std::string>> WalletModel::listWalletMetaWithPrefix(const std::string &prefix) const
{
    std::vector<std::pair<std::string, std::string>> out;
    LOCK(wallet->cs_wallet);
    if (!wallet->vchDefaultKey.IsValid()) {
        return out;
    }
    const CTxDestination dest = wallet->vchDefaultKey.GetID();
    const auto it = wallet->mapAddressBook.find(dest);
    if (it == wallet->mapAddressBook.end()) {
        return out;
    }
    for (const auto &kv : it->second.destdata) {
        if (kv.first.size() >= prefix.size() &&
            kv.first.compare(0, prefix.size(), prefix) == 0) {
            out.emplace_back(kv.first, kv.second);
        }
    }
    return out;
}

QString WalletModel::getWalletFilePath() const
{
    return QString::fromStdString((GetDataDir() / wallet->strWalletFile).string());
}

bool WalletModel::transactionCanBeAbandoned(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    const CWalletTx *wtx = wallet->GetWalletTx(hash);
    if (!wtx || wtx->isAbandoned() || wtx->GetDepthInMainChain() > 0 || wtx->InMempool())
        return false;
    return true;
}

bool WalletModel::abandonTransaction(uint256 hash) const
{
    LOCK2(cs_main, wallet->cs_wallet);
    return wallet->AbandonTransaction(hash);
}

bool WalletModel::isWalletEnabled()
{
   return !GetBoolArg("-disablewallet", DEFAULT_DISABLE_WALLET);
}

bool WalletModel::hdEnabled() const
{
    return wallet->IsHDEnabled();
}

int WalletModel::getDefaultConfirmTarget() const
{
    return nTxConfirmTarget;
}
