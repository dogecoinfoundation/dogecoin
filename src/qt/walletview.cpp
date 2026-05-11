// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "walletview.h"

#include "config/bitcoin-config.h"
#include "addressbookpage.h"
#include "askpassphrasedialog.h"
#include "bitcoingui.h"
#include "clientmodel.h"
#include "guiutil.h"
#include "importkeysdialog.h"
#ifdef USE_BIP39
#include "importbip39dialog.h"
#endif
#include "optionsmodel.h"
#include "overviewpage.h"
#include "platformstyle.h"
#include "receivecoinsdialog.h"
#include "sendcoinsdialog.h"
#include "signverifymessagedialog.h"
#include "transactiontablemodel.h"
#include "transactionview.h"
#include "walletmodel.h"
#include "utilitydialog.h"

#include "utilstrencodings.h"
#include "ui_interface.h"
#include "wallet/crypter.h"

#include "crypto/aes.h"
#include "crypto/sha256.h"
#include "crypto/sha512.h"
#include "random.h"
#include "support/cleanse.h"
#include "support/experimental.h"
#include "init.h"

#if ENABLE_LIBOQS
EXPERIMENTAL_FEATURE
#include <oqs/oqs.h>
#include "pqc/pqc_commitment.h"
#endif

#include <QAction>
#include <QActionGroup>
#include <QApplication>
#include <QComboBox>
#include <QFileDialog>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QInputDialog>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDateTime>
#include <QFormLayout>
#include <QLineEdit>
#include <QFile>
#include <QJsonDocument>
#include <QJsonObject>
#include <QLabel>
#include <QListWidget>
#include <QMessageBox>
#include <QPlainTextEdit>
#include <QProgressDialog>
#include <QPushButton>
#include <QRegularExpression>
#include <QVBoxLayout>

namespace {

QByteArray Sha256Bytes(const QByteArray& input)
{
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256().Write(reinterpret_cast<const unsigned char*>(input.constData()), input.size()).Finalize(digest);
    QByteArray out(reinterpret_cast<const char*>(digest), sizeof(digest));
    memory_cleanse(digest, sizeof(digest));
    return out;
}

const char* PQCSignatureStoragePrefixForAlgorithm(const QString& algorithm)
{
    if (algorithm == "dilithium2") return "pqc_sigkey_dilithium2";
#ifdef ENABLE_LIBOQS_RACCOON
    if (algorithm == "raccoong44") return "pqc_sigkey_raccoong44";
#endif
    return "pqc_sigkey_falcon512";
}

// Build a per-public-key storage key so the wallet can hold multiple stored
// keypairs per algorithm. Suffix is the first 16 hex chars (8 bytes) of
// SHA256(public_key_hex_bytes); the input is the ASCII hex string itself so
// callers can compute the same key from a JSON-loaded pubHex without re-decoding.
std::string PQCSignatureStorageKeyForPubHex(const QString& algorithm, const QString& pubHex)
{
    const QByteArray pubHexBytes = pubHex.toLatin1();
    const QByteArray digest = Sha256Bytes(pubHexBytes);
    const QString suffix = QString::fromLatin1(digest.left(8).toHex());
    return std::string(PQCSignatureStoragePrefixForAlgorithm(algorithm)) + "_" + suffix.toStdString();
}

QByteArray DeriveKeyMaterial(const QByteArray& secret, const QByteArray& context, int outLen)
{
    QByteArray out;
    int counter = 0;
    while (out.size() < outLen) {
        QByteArray blockInput = secret + context + QByteArray::number(counter++);
        out.append(Sha256Bytes(blockInput));
    }
    out.truncate(outLen);
    return out;
}

/**
 * Derive an AES-256-CBC key (32 bytes) and IV (16 bytes) from passphrase + salt
 * using the same SHA-512 KDF as CCrypter::BytesToKeySHA512AES.
 * Stores key in keyOut[0..31] and IV in keyOut[32..47].
 * Caller must memory_cleanse the buffer after use.
 */
void DeriveAesKeyIV(const SecureString& passphrase,
                    const std::vector<unsigned char>& salt,
                    unsigned int rounds,
                    unsigned char keyOut[CSHA512::OUTPUT_SIZE])
{
    CSHA512 di;
    di.Write(reinterpret_cast<const unsigned char*>(passphrase.c_str()), passphrase.size());
    if (!salt.empty())
        di.Write(salt.data(), salt.size());
    di.Finalize(keyOut);
    for (unsigned int i = 0; i < rounds - 1; i++)
        di.Reset().Write(keyOut, CSHA512::OUTPUT_SIZE).Finalize(keyOut);
}

} // namespace

WalletView::WalletView(const PlatformStyle *_platformStyle, QWidget *parent):
    QStackedWidget(parent),
    clientModel(0),
    walletModel(0),
    platformStyle(_platformStyle)
{
    // Create tabs
    overviewPage = new OverviewPage(platformStyle);

    transactionsPage = new QWidget(this);
    QVBoxLayout *vbox = new QVBoxLayout();
    QHBoxLayout *hbox_buttons = new QHBoxLayout();
    transactionView = new TransactionView(platformStyle, this);
    vbox->addWidget(transactionView);
    QPushButton *exportButton = new QPushButton(tr("&Export"), this);
    exportButton->setToolTip(tr("Export the data in the current tab to a file"));
    if (platformStyle->getImagesOnButtons()) {
        exportButton->setIcon(platformStyle->SingleColorIcon(":/icons/export"));
    }
    hbox_buttons->addStretch();
    hbox_buttons->addWidget(exportButton);
    vbox->addLayout(hbox_buttons);
    transactionsPage->setLayout(vbox);

    receiveCoinsPage = new ReceiveCoinsDialog(platformStyle);
    sendCoinsPage = new SendCoinsDialog(platformStyle);

    usedSendingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::SendingTab, this);
    usedReceivingAddressesPage = new AddressBookPage(platformStyle, AddressBookPage::ForEditing, AddressBookPage::ReceivingTab, this);

    addWidget(overviewPage);
    addWidget(transactionsPage);
    addWidget(receiveCoinsPage);
    addWidget(sendCoinsPage);

    importKeysDialog = new ImportKeysDialog(platformStyle);

#ifdef USE_BIP39
EXPERIMENTAL_FEATURE
    // Create import BIP39 mnemonic dialog
    importBip39Dialog = new ImportBip39Dialog(platformStyle);
#endif

    // Clicking on a transaction on the overview pre-selects the transaction on the transaction history page
    connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), transactionView, SLOT(focusTransaction(QModelIndex)));
    connect(overviewPage, SIGNAL(outOfSyncWarningClicked()), this, SLOT(requestedSyncWarningInfo()));

    // Double-clicking on a transaction on the transaction history page shows details
    connect(transactionView, SIGNAL(doubleClicked(QModelIndex)), transactionView, SLOT(showDetails()));

    // Clicking on "Export" allows to export the transaction list
    connect(exportButton, SIGNAL(clicked()), transactionView, SLOT(exportClicked()));

    // Pass through messages from sendCoinsPage
    connect(sendCoinsPage, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
    // Pass through messages from transactionView
    connect(transactionView, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));
}

WalletView::~WalletView()
{
}

void WalletView::setBitcoinGUI(BitcoinGUI *gui)
{
    if (gui)
    {
        // Clicking on a transaction on the overview page simply sends you to transaction history page
        connect(overviewPage, SIGNAL(transactionClicked(QModelIndex)), gui, SLOT(gotoHistoryPage()));

        // Receive and report messages
        connect(this, SIGNAL(message(QString,QString,unsigned int)), gui, SLOT(message(QString,QString,unsigned int)));

        // Pass through encryption status changed signals
        connect(this, SIGNAL(encryptionStatusChanged(int)), gui, SLOT(setEncryptionStatus(int)));

        // Pass through transaction notifications
        connect(this, SIGNAL(incomingTransaction(QString,int,CAmount,QString,QString,QString)), gui, SLOT(incomingTransaction(QString,int,CAmount,QString,QString,QString)));

        // Connect HD enabled state signal
        connect(this, SIGNAL(hdEnabledStatusChanged(int)), gui, SLOT(setHDStatus(int)));
    }
}

void WalletView::setClientModel(ClientModel *_clientModel)
{
    this->clientModel = _clientModel;

    overviewPage->setClientModel(_clientModel);
    sendCoinsPage->setClientModel(_clientModel);
}

void WalletView::setWalletModel(WalletModel *_walletModel)
{
    this->walletModel = _walletModel;

    // Put transaction list in tabs
    transactionView->setModel(_walletModel);
    overviewPage->setWalletModel(_walletModel);
    receiveCoinsPage->setModel(_walletModel);
    sendCoinsPage->setModel(_walletModel);
    usedReceivingAddressesPage->setModel(_walletModel->getAddressTableModel());
    usedSendingAddressesPage->setModel(_walletModel->getAddressTableModel());

    if (_walletModel)
    {
        // Receive and pass through messages from wallet model
        connect(_walletModel, SIGNAL(message(QString,QString,unsigned int)), this, SIGNAL(message(QString,QString,unsigned int)));

        // Handle changes in encryption status
        connect(_walletModel, SIGNAL(encryptionStatusChanged(int)), this, SIGNAL(encryptionStatusChanged(int)));
        updateEncryptionStatus();

        // update HD status
        Q_EMIT hdEnabledStatusChanged(_walletModel->hdEnabled());

        // Balloon pop-up for new transaction
        connect(_walletModel->getTransactionTableModel(), SIGNAL(rowsInserted(QModelIndex,int,int)),
                this, SLOT(processNewTransaction(QModelIndex,int,int)));

        // Ask for passphrase if needed
        connect(_walletModel, SIGNAL(requireUnlock()), this, SLOT(unlockWallet()));

        // Show progress dialog
        connect(_walletModel, SIGNAL(showProgress(QString,int)), this, SLOT(showProgress(QString,int)));
    }
}

void WalletView::processNewTransaction(const QModelIndex& parent, int start, int /*end*/)
{
    // Prevent balloon-spam when initial block download is in progress
    if (!walletModel || !clientModel || clientModel->inInitialBlockDownload())
        return;

    TransactionTableModel *ttm = walletModel->getTransactionTableModel();
    if (!ttm || ttm->processingQueuedTransactions())
        return;

    QString date = ttm->index(start, TransactionTableModel::Date, parent).data().toString();
    qint64 amount = ttm->index(start, TransactionTableModel::Amount, parent).data(Qt::EditRole).toULongLong();
    QString type = ttm->index(start, TransactionTableModel::Type, parent).data().toString();
    QModelIndex index = ttm->index(start, 0, parent);
    QString address = ttm->data(index, TransactionTableModel::AddressRole).toString();
    QString label = ttm->data(index, TransactionTableModel::LabelRole).toString();

    Q_EMIT incomingTransaction(date, walletModel->getOptionsModel()->getDisplayUnit(), amount, type, address, label);
}

void WalletView::gotoOverviewPage()
{
    setCurrentWidget(overviewPage);
}

void WalletView::gotoHistoryPage()
{
    setCurrentWidget(transactionsPage);
}

void WalletView::gotoReceiveCoinsPage()
{
    setCurrentWidget(receiveCoinsPage);
}

void WalletView::gotoSendCoinsPage(QString addr)
{
    setCurrentWidget(sendCoinsPage);

    if (!addr.isEmpty())
        sendCoinsPage->setAddress(addr);
}

void WalletView::gotoSignMessageTab(QString addr)
{
    // calls show() in showTab_SM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_SM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_SM(addr);
}

void WalletView::gotoVerifyMessageTab(QString addr)
{
    // calls show() in showTab_VM()
    SignVerifyMessageDialog *signVerifyMessageDialog = new SignVerifyMessageDialog(platformStyle, this);
    signVerifyMessageDialog->setAttribute(Qt::WA_DeleteOnClose);
    signVerifyMessageDialog->setModel(walletModel);
    signVerifyMessageDialog->showTab_VM(true);

    if (!addr.isEmpty())
        signVerifyMessageDialog->setAddress_VM(addr);
}

void WalletView::gotoImportKeysDialog()
{
    setCurrentWidget(importKeysDialog);
}

#ifdef USE_BIP39
EXPERIMENTAL_FEATURE
void WalletView::gotoImportBip39Dialog()
{
    setCurrentWidget(importBip39Dialog);
}
#endif

bool WalletView::handlePaymentRequest(const SendCoinsRecipient& recipient)
{
    return sendCoinsPage->handlePaymentRequest(recipient);
}

void WalletView::showOutOfSyncWarning(bool fShow)
{
    overviewPage->showOutOfSyncWarning(fShow);
}

void WalletView::updateEncryptionStatus()
{
    Q_EMIT encryptionStatusChanged(walletModel->getEncryptionStatus());
}

void WalletView::encryptWallet(bool status)
{
    if(!walletModel)
        return;
    AskPassphraseDialog dlg(status ? AskPassphraseDialog::Encrypt : AskPassphraseDialog::Decrypt, this);
    dlg.setModel(walletModel);
    dlg.exec();

    updateEncryptionStatus();
}

void WalletView::backupWallet()
{
    QString filename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet"), QString(),
        tr("Wallet Data (*.dat)"), NULL);

    if (filename.isEmpty())
        return;

    if (!walletModel->backupWallet(filename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(filename),
            CClientUIInterface::MSG_ERROR);
        }
    else {
        Q_EMIT message(tr("Backup Successful"), tr("The wallet data was successfully saved to %1.").arg(filename),
            CClientUIInterface::MSG_INFORMATION);
    }
}

void WalletView::backupWalletEncrypted()
{
    if (!walletModel) {
        return;
    }

    QString outFilename = GUIUtil::getSaveFileName(this,
        tr("Backup Wallet (PQC Envelope)"), QString(),
        tr("PQC Envelope (*.pqce)"), NULL);
    if (outFilename.isEmpty())
        return;
    if (!outFilename.endsWith(".pqce"))
        outFilename += ".pqce";

    const QString tempWalletFilename = outFilename + ".wallet.tmp.dat";
    if (!walletModel->backupWallet(tempWalletFilename)) {
        Q_EMIT message(tr("Backup Failed"), tr("There was an error trying to save the wallet data to %1.").arg(tempWalletFilename),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    bool okAes = false;
    QString aesPassphrase = QInputDialog::getText(
        this,
        tr("AES Backup Passphrase"),
        tr("Enter passphrase for AES layer:"),
        QLineEdit::Password,
        QString(),
        &okAes);
    if (!okAes || aesPassphrase.isEmpty()) {
        QFile::remove(tempWalletFilename);
        return;
    }

    bool okPqc = false;
    QString pqcPassphrase = QInputDialog::getText(
        this,
        tr("PQC Backup Passphrase"),
        tr("Enter passphrase for PQC layer:"),
        QLineEdit::Password,
        QString(),
        &okPqc);
    if (!okPqc || pqcPassphrase.isEmpty()) {
        QFile::remove(tempWalletFilename);
        return;
    }

    // Show progress dialog during encryption
    QProgressDialog progress(tr("Encrypting wallet backup..."), QString(), 0, 100, this);
    progress.setWindowModality(Qt::ApplicationModal);
    progress.setMinimumDuration(0);
    progress.setCancelButton(nullptr);
    progress.setAutoClose(false);
    progress.setValue(5);
    progress.setLabelText(tr("Reading wallet file..."));
    QApplication::processEvents();

    QFile walletFile(tempWalletFilename);
    if (!walletFile.open(QIODevice::ReadOnly)) {
        QFile::remove(tempWalletFilename);
        Q_EMIT message(tr("Backup Failed"), tr("Unable to open temporary wallet backup %1.").arg(tempWalletFilename),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    QByteArray plain = walletFile.readAll();
    walletFile.close();
    QFile::remove(tempWalletFilename);
    if (plain.isEmpty()) {
        Q_EMIT message(tr("Encryption Failed"), tr("Temporary wallet backup is empty."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    progress.setValue(15);
    progress.setLabelText(tr("Encrypting with AES-256-CBC (layer 1)..."));
    QApplication::processEvents();

    // Layer 1: AES-256-CBC encryption with passphrase-derived key
    // NOTE: We use AES256CBCEncrypt directly instead of CCrypter::Encrypt
    // because CCrypter requires CKeyingMaterial (secure_allocator) which has
    // a 256 KB arena limit and would segfault for wallet files > 256 KB.
    std::vector<unsigned char> aesSalt(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(aesSalt.data(), WALLET_CRYPTO_SALT_SIZE);
    QByteArray aesPassphraseBytes = aesPassphrase.toUtf8();
    SecureString aesPass(aesPassphraseBytes.constData(), aesPassphraseBytes.constData() + aesPassphraseBytes.size());

    unsigned char aesKeyBuf[CSHA512::OUTPUT_SIZE];
    DeriveAesKeyIV(aesPass, aesSalt, 25000, aesKeyBuf);

    std::vector<unsigned char> aesCipher(plain.size() + AES_BLOCKSIZE);
    {
        AES256CBCEncrypt aesEnc(aesKeyBuf, aesKeyBuf + WALLET_CRYPTO_KEY_SIZE, true);
        int nLen = aesEnc.Encrypt(
            reinterpret_cast<const unsigned char*>(plain.constData()),
            plain.size(), aesCipher.data());
        memory_cleanse(aesKeyBuf, sizeof(aesKeyBuf));
        if (nLen < plain.size()) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!plain.isEmpty()) memory_cleanse(plain.data(), plain.size());
            Q_EMIT message(tr("Encryption Failed"), tr("Unable to encrypt wallet backup data with AES layer."),
                CClientUIInterface::MSG_ERROR);
            return;
        }
        aesCipher.resize(nLen);
    }
    if (!plain.isEmpty()) memory_cleanse(plain.data(), plain.size());

    progress.setValue(35);
    progress.setLabelText(tr("Generating ML-KEM-768 keypair (layer 2)..."));
    QApplication::processEvents();

#if ENABLE_LIBOQS
    // Layer 2: ML-KEM-768 key encapsulation + AES-256-CBC
    // Generate a KEM keypair, encapsulate a shared secret, use it to
    // encrypt the AES ciphertext.  The KEM secret key is itself encrypted
    // with the PQC passphrase so the user must supply both passwords to
    // decrypt.  This gives genuine post-quantum protection: even if the
    // passphrase KDF is weakened by Grover's algorithm, the ML-KEM layer
    // remains quantum-resistant.

    OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
    if (kem == nullptr) {
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        Q_EMIT message(tr("Encryption Failed"), tr("ML-KEM-768 algorithm unavailable in liboqs."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    std::vector<unsigned char> kemPk(kem->length_public_key);
    std::vector<unsigned char> kemSk(kem->length_secret_key);
    std::vector<unsigned char> kemCt(kem->length_ciphertext);
    std::vector<unsigned char> sharedSecret(kem->length_shared_secret);

    if (OQS_KEM_keypair(kem, kemPk.data(), kemSk.data()) != OQS_SUCCESS) {
        OQS_KEM_free(kem);
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        Q_EMIT message(tr("Encryption Failed"), tr("ML-KEM-768 keypair generation failed."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    if (OQS_KEM_encaps(kem, kemCt.data(), sharedSecret.data(), kemPk.data()) != OQS_SUCCESS) {
        memory_cleanse(kemSk.data(), kemSk.size());
        OQS_KEM_free(kem);
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        Q_EMIT message(tr("Encryption Failed"), tr("ML-KEM-768 encapsulation failed."),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    OQS_KEM_free(kem);

    progress.setValue(50);
    progress.setLabelText(tr("Encrypting with KEM-derived key..."));
    QApplication::processEvents();

    // Derive an AES key + IV from the KEM shared secret via SHA-512
    unsigned char kemDerived[CSHA512::OUTPUT_SIZE];
    CSHA512().Write(sharedSecret.data(), sharedSecret.size()).Finalize(kemDerived);
    memory_cleanse(sharedSecret.data(), sharedSecret.size());

    // Use AES256CBCEncrypt directly to avoid CKeyingMaterial 256 KB limit
    std::vector<unsigned char> outerCipher(aesCipher.size() + AES_BLOCKSIZE);
    {
        AES256CBCEncrypt kemEnc(kemDerived, kemDerived + WALLET_CRYPTO_KEY_SIZE, true);
        int kemLen = kemEnc.Encrypt(aesCipher.data(), aesCipher.size(), outerCipher.data());
        memory_cleanse(kemDerived, sizeof(kemDerived));
        if (kemLen < (int)aesCipher.size()) {
            memory_cleanse(kemSk.data(), kemSk.size());
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            Q_EMIT message(tr("Encryption Failed"), tr("Unable to encrypt with KEM-derived key."),
                CClientUIInterface::MSG_ERROR);
            return;
        }
        outerCipher.resize(kemLen);
    }

    // Encrypt the KEM secret key with the PQC passphrase
    progress.setValue(65);
    progress.setLabelText(tr("Encrypting KEM secret key with PQC passphrase..."));
    QApplication::processEvents();

    std::vector<unsigned char> pqcSalt(WALLET_CRYPTO_SALT_SIZE);
    GetStrongRandBytes(pqcSalt.data(), WALLET_CRYPTO_SALT_SIZE);
    QByteArray pqcPassphraseBytes = pqcPassphrase.toUtf8();
    SecureString pqcPass(pqcPassphraseBytes.constData(), pqcPassphraseBytes.constData() + pqcPassphraseBytes.size());
    const int pqcRounds = 50000;

    CCrypter skCrypter;
    if (!skCrypter.SetKeyFromPassphrase(pqcPass, pqcSalt, pqcRounds, 0)) {
        memory_cleanse(kemSk.data(), kemSk.size());
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
        Q_EMIT message(tr("Encryption Failed"), tr("Unable to derive PQC passphrase key."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    CKeyingMaterial skMaterial(kemSk.begin(), kemSk.end());
    memory_cleanse(kemSk.data(), kemSk.size());
    std::vector<unsigned char> encryptedSk;
    if (!skCrypter.Encrypt(skMaterial, encryptedSk)) {
        memory_cleanse(&skMaterial[0], skMaterial.size());
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
        Q_EMIT message(tr("Encryption Failed"), tr("Unable to encrypt KEM secret key."),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    memory_cleanse(&skMaterial[0], skMaterial.size());

    if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
    if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());

    progress.setValue(80);
    progress.setLabelText(tr("Writing encrypted envelope file..."));
    QApplication::processEvents();

    const QByteArray envelopeAlgo = "AES256-CBC+ML-KEM-768";
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(envelopeAlgo.constData()), envelopeAlgo.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(outerCipher.data()), outerCipher.size());
    hasher.Finalize(digest);

    QFile outFile(outFilename);
    if (!outFile.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        memory_cleanse(digest, sizeof(digest));
        Q_EMIT message(tr("Encryption Failed"), tr("Unable to write envelope file %1.").arg(outFilename),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    outFile.write("DGC-PQCE4\n");
    outFile.write("ALGO:" + envelopeAlgo + "\n");
    outFile.write("AES_KDF:sha512-aes256cbc\n");
    outFile.write("AES_SALT:" + QByteArray(reinterpret_cast<const char*>(aesSalt.data()), aesSalt.size()).toHex() + "\n");
    outFile.write("AES_ROUNDS:25000\n");
    outFile.write("KEM_ALG:ML-KEM-768\n");
    outFile.write("KEM_CT:" + QByteArray(reinterpret_cast<const char*>(kemCt.data()), kemCt.size()).toHex() + "\n");
    outFile.write("KEM_SK_KDF:sha512-aes256cbc\n");
    outFile.write("KEM_SK_SALT:" + QByteArray(reinterpret_cast<const char*>(pqcSalt.data()), pqcSalt.size()).toHex() + "\n");
    outFile.write("KEM_SK_ROUNDS:" + QByteArray::number(pqcRounds) + "\n");
    outFile.write("KEM_SK_ENC:" + QByteArray(reinterpret_cast<const char*>(encryptedSk.data()), encryptedSk.size()).toBase64() + "\n");
    outFile.write("DATA_SHA256:" + QByteArray(reinterpret_cast<const char*>(digest), sizeof(digest)).toHex() + "\n");
    outFile.write("DATA_B64:" + QByteArray(reinterpret_cast<const char*>(outerCipher.data()), outerCipher.size()).toBase64() + "\n");
    outFile.close();
    memory_cleanse(digest, sizeof(digest));

    progress.setValue(100);
    progress.close();

    QMessageBox::information(this, tr("Backup Successful"),
        tr("Double-encrypted (AES-256-CBC + ML-KEM-768) wallet backup was successfully saved to %1.").arg(outFilename));

#else
    // liboqs is required for PQC envelope creation (ML-KEM-768)
    if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
    Q_EMIT message(tr("Encryption Failed"),
        tr("PQC envelope backup requires liboqs (ML-KEM-768). Rebuild with --with-liboqs --enable-experimental."),
        CClientUIInterface::MSG_ERROR);
    return;
#endif // ENABLE_LIBOQS
}

void WalletView::restoreWalletEncrypted()
{
    if (!walletModel) {
        return;
    }

    QString inFilename = GUIUtil::getOpenFileName(this,
        tr("Restore Wallet (PQC Envelope)"), QString(),
        tr("PQC Envelope (*.pqce)"), NULL);
    if (inFilename.isEmpty()) {
        return;
    }

    QFile inFile(inFilename);
    if (!inFile.open(QIODevice::ReadOnly)) {
        Q_EMIT message(tr("Restore Failed"), tr("Unable to open envelope file %1.").arg(inFilename),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    const QList<QByteArray> lines = inFile.readAll().split('\n');
    inFile.close();

    QMap<QByteArray, QByteArray> fields;
    QByteArray header;
    for (int i = 0; i < lines.size(); ++i) {
        QByteArray line = lines.at(i).trimmed();
        if (line.isEmpty()) continue;
        if (i == 0 && !line.contains(':')) {
            header = line;
            continue;
        }
        int sep = line.indexOf(':');
        if (sep <= 0) continue;
        fields.insert(line.left(sep), line.mid(sep + 1));
    }

    const bool isV4 = (header == "DGC-PQCE4");
    const bool isV3 = (header == "DGC-PQCE3");
    if (!isV4 && !isV3) {
        Q_EMIT message(tr("Restore Failed"), tr("Unsupported envelope format: %1").arg(QString::fromLatin1(header)),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    const QByteArray algo = fields.value("ALGO");
    if (isV4 && algo != "AES256-CBC+ML-KEM-768") {
        Q_EMIT message(tr("Restore Failed"), tr("Unsupported envelope algorithm: %1").arg(QString::fromLatin1(algo)),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    if (isV3 && algo != "AES256-CBC+PQC-PASS-CASCADE" && algo != "AES256-CBC+AES256-CBC-CASCADE") {
        Q_EMIT message(tr("Restore Failed"), tr("Unsupported envelope algorithm: %1").arg(QString::fromLatin1(algo)),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    // Common fields
    const QByteArray aesSaltHex = fields.value("AES_SALT");
    const QByteArray aesRoundsRaw = fields.value("AES_ROUNDS");
    const QByteArray expectedDigestHex = fields.value("DATA_SHA256");
    const QByteArray dataB64 = fields.value("DATA_B64");
    if (aesSaltHex.isEmpty() || aesRoundsRaw.isEmpty() || expectedDigestHex.isEmpty() || dataB64.isEmpty()) {
        Q_EMIT message(tr("Restore Failed"), tr("Envelope is missing required fields."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    const QByteArray aesSalt = QByteArray::fromHex(aesSaltHex);
    bool okAesRounds = false;
    const int aesRounds = QString::fromLatin1(aesRoundsRaw).toInt(&okAesRounds);
    if (!okAesRounds || aesRounds <= 0 || aesSalt.isEmpty()) {
        Q_EMIT message(tr("Restore Failed"), tr("Envelope AES KDF parameters are invalid."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    std::vector<unsigned char> outerCipher = DecodeBase64(dataB64.toStdString().c_str(), NULL);
    if (outerCipher.empty()) {
        Q_EMIT message(tr("Restore Failed"), tr("Envelope encrypted payload is invalid."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    // Verify integrity digest
    unsigned char digest[CSHA256::OUTPUT_SIZE];
    CSHA256 hasher;
    hasher.Write(reinterpret_cast<const unsigned char*>(algo.constData()), algo.size());
    hasher.Write(reinterpret_cast<const unsigned char*>(outerCipher.data()), outerCipher.size());
    hasher.Finalize(digest);
    const QByteArray digestHex(reinterpret_cast<const char*>(digest), sizeof(digest));
    const QByteArray digestHexAscii = digestHex.toHex();
    memory_cleanse(digest, sizeof(digest));
    if (QString::compare(QString::fromLatin1(expectedDigestHex), QString::fromLatin1(digestHexAscii), Qt::CaseInsensitive) != 0) {
        Q_EMIT message(tr("Restore Failed"), tr("Envelope digest check failed."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    // Prompt for passphrases
    bool okAes = false;
    const QString aesPassphrase = QInputDialog::getText(
        this,
        tr("AES Backup Passphrase"),
        tr("Enter passphrase for AES layer:"),
        QLineEdit::Password,
        QString(),
        &okAes);
    if (!okAes || aesPassphrase.isEmpty()) {
        return;
    }
    bool okPqc = false;
    const QString pqcPassphrase = QInputDialog::getText(
        this,
        tr("PQC Backup Passphrase"),
        tr("Enter passphrase for PQC layer:"),
        QLineEdit::Password,
        QString(),
        &okPqc);
    if (!okPqc || pqcPassphrase.isEmpty()) {
        return;
    }

    QByteArray aesPassphraseBytes = aesPassphrase.toUtf8();
    QByteArray pqcPassphraseBytes = pqcPassphrase.toUtf8();

    // NOTE: We use AES256CBCDecrypt directly instead of CCrypter::Decrypt
    // because CCrypter requires CKeyingMaterial (secure_allocator) which has
    // a 256 KB arena limit and would segfault for wallet files > 256 KB.
    std::vector<unsigned char> aesCipherData;

    if (isV4) {
#if ENABLE_LIBOQS
        // V4: ML-KEM-768 decapsulation
        const QByteArray kemAlg = fields.value("KEM_ALG");
        const QByteArray kemCtHex = fields.value("KEM_CT");
        const QByteArray kemSkKdf = fields.value("KEM_SK_KDF");
        const QByteArray kemSkSaltHex = fields.value("KEM_SK_SALT");
        const QByteArray kemSkRoundsRaw = fields.value("KEM_SK_ROUNDS");
        const QByteArray kemSkEncB64 = fields.value("KEM_SK_ENC");

        if (kemAlg != "ML-KEM-768" || kemCtHex.isEmpty() || kemSkKdf != "sha512-aes256cbc" ||
            kemSkSaltHex.isEmpty() || kemSkRoundsRaw.isEmpty() || kemSkEncB64.isEmpty()) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("Envelope is missing required KEM fields."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        const QByteArray kemSkSalt = QByteArray::fromHex(kemSkSaltHex);
        bool okSkRounds = false;
        const int kemSkRounds = QString::fromLatin1(kemSkRoundsRaw).toInt(&okSkRounds);
        if (!okSkRounds || kemSkRounds <= 0 || kemSkSalt.isEmpty()) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("Envelope KEM secret key KDF parameters are invalid."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        // Decrypt the KEM secret key with PQC passphrase
        SecureString pqcPass(pqcPassphraseBytes.constData(), pqcPassphraseBytes.constData() + pqcPassphraseBytes.size());
        CCrypter skCrypter;
        std::vector<unsigned char> kemSkSaltBytes(kemSkSalt.begin(), kemSkSalt.end());
        if (!skCrypter.SetKeyFromPassphrase(pqcPass, kemSkSaltBytes, kemSkRounds, 0)) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("Unable to derive PQC passphrase key."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        std::vector<unsigned char> encryptedSk = DecodeBase64(kemSkEncB64.toStdString().c_str(), NULL);
        CKeyingMaterial skMaterial;
        if (!skCrypter.Decrypt(encryptedSk, skMaterial)) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("PQC password decryption of KEM secret key failed."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        // KEM decapsulation
        const QByteArray kemCtBytes = QByteArray::fromHex(kemCtHex);
        OQS_KEM *kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_768);
        if (kem == nullptr) {
            memory_cleanse(&skMaterial[0], skMaterial.size());
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("ML-KEM-768 algorithm unavailable in liboqs."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        if (skMaterial.size() != kem->length_secret_key || (size_t)kemCtBytes.size() != kem->length_ciphertext) {
            memory_cleanse(&skMaterial[0], skMaterial.size());
            OQS_KEM_free(kem);
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("KEM secret key or ciphertext size mismatch."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        std::vector<unsigned char> sharedSecret(kem->length_shared_secret);
        OQS_STATUS rc = OQS_KEM_decaps(kem, sharedSecret.data(),
            reinterpret_cast<const unsigned char*>(kemCtBytes.constData()),
            reinterpret_cast<const unsigned char*>(skMaterial.data()));
        memory_cleanse(&skMaterial[0], skMaterial.size());
        OQS_KEM_free(kem);

        if (rc != OQS_SUCCESS) {
            memory_cleanse(sharedSecret.data(), sharedSecret.size());
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("ML-KEM-768 decapsulation failed."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        // Derive AES key from shared secret
        unsigned char kemDerived[CSHA512::OUTPUT_SIZE];
        CSHA512().Write(sharedSecret.data(), sharedSecret.size()).Finalize(kemDerived);
        memory_cleanse(sharedSecret.data(), sharedSecret.size());

        // Use AES256CBCDecrypt directly to avoid CKeyingMaterial 256 KB limit
        aesCipherData.resize(outerCipher.size());
        {
            AES256CBCDecrypt kemDec(kemDerived, kemDerived + WALLET_CRYPTO_KEY_SIZE, true);
            int kemLen = kemDec.Decrypt(outerCipher.data(), outerCipher.size(), aesCipherData.data());
            memory_cleanse(kemDerived, sizeof(kemDerived));
            if (kemLen == 0) {
                if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
                if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
                Q_EMIT message(tr("Restore Failed"), tr("KEM-layer decryption failed."),
                    CClientUIInterface::MSG_ERROR);
                return;
            }
            aesCipherData.resize(kemLen);
        }
#else
        if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
        if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
        Q_EMIT message(tr("Restore Failed"), tr("This envelope requires liboqs (ML-KEM-768) which is not enabled in this build."),
            CClientUIInterface::MSG_ERROR);
        return;
#endif // ENABLE_LIBOQS
    } else {
        // V3: Legacy AES cascade decryption
        const QByteArray pqcSaltHex = fields.value("PQC_SALT");
        const QByteArray pqcRoundsRaw = fields.value("PQC_ROUNDS");
        if (pqcSaltHex.isEmpty() || pqcRoundsRaw.isEmpty()) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("Envelope is missing required PQC fields."),
                CClientUIInterface::MSG_ERROR);
            return;
        }
        const QByteArray pqcSalt = QByteArray::fromHex(pqcSaltHex);
        bool okPqcRounds = false;
        const int pqcRounds = QString::fromLatin1(pqcRoundsRaw).toInt(&okPqcRounds);
        if (!okPqcRounds || pqcRounds <= 0 || pqcSalt.isEmpty()) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            Q_EMIT message(tr("Restore Failed"), tr("Envelope PQC KDF parameters are invalid."),
                CClientUIInterface::MSG_ERROR);
            return;
        }

        SecureString pqcPass(pqcPassphraseBytes.constData(), pqcPassphraseBytes.constData() + pqcPassphraseBytes.size());
        std::vector<unsigned char> pqcSaltBytes(pqcSalt.begin(), pqcSalt.end());

        // Use AES256CBCDecrypt directly to avoid CKeyingMaterial 256 KB limit
        unsigned char pqcKeyBuf[CSHA512::OUTPUT_SIZE];
        DeriveAesKeyIV(pqcPass, pqcSaltBytes, pqcRounds, pqcKeyBuf);

        aesCipherData.resize(outerCipher.size());
        {
            AES256CBCDecrypt pqcDec(pqcKeyBuf, pqcKeyBuf + WALLET_CRYPTO_KEY_SIZE, true);
            int pqcLen = pqcDec.Decrypt(outerCipher.data(), outerCipher.size(), aesCipherData.data());
            memory_cleanse(pqcKeyBuf, sizeof(pqcKeyBuf));
            if (pqcLen == 0) {
                if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
                if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
                Q_EMIT message(tr("Restore Failed"), tr("PQC password decryption failed."),
                    CClientUIInterface::MSG_ERROR);
                return;
            }
            aesCipherData.resize(pqcLen);
        }
    }

    // AES layer decryption (common to both V3 and V4)
    // Use AES256CBCDecrypt directly to avoid CKeyingMaterial 256 KB limit
    SecureString aesPass(aesPassphraseBytes.constData(), aesPassphraseBytes.constData() + aesPassphraseBytes.size());
    std::vector<unsigned char> aesSaltBytes(aesSalt.begin(), aesSalt.end());

    unsigned char aesKeyBuf[CSHA512::OUTPUT_SIZE];
    DeriveAesKeyIV(aesPass, aesSaltBytes, aesRounds, aesKeyBuf);

    std::vector<unsigned char> plainData(aesCipherData.size());
    {
        AES256CBCDecrypt aesDec(aesKeyBuf, aesKeyBuf + WALLET_CRYPTO_KEY_SIZE, true);
        int aesLen = aesDec.Decrypt(aesCipherData.data(), aesCipherData.size(), plainData.data());
        memory_cleanse(aesKeyBuf, sizeof(aesKeyBuf));
        if (aesLen == 0) {
            if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
            if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
            if (!aesCipherData.empty()) memory_cleanse(aesCipherData.data(), aesCipherData.size());
            Q_EMIT message(tr("Restore Failed"), tr("AES password decryption failed."),
                CClientUIInterface::MSG_ERROR);
            return;
        }
        plainData.resize(aesLen);
    }

    if (!aesPassphraseBytes.isEmpty()) memory_cleanse(aesPassphraseBytes.data(), aesPassphraseBytes.size());
    if (!pqcPassphraseBytes.isEmpty()) memory_cleanse(pqcPassphraseBytes.data(), pqcPassphraseBytes.size());
    if (!aesCipherData.empty()) memory_cleanse(aesCipherData.data(), aesCipherData.size());

    if (plainData.empty()) {
        Q_EMIT message(tr("Restore Failed"), tr("Decrypted wallet backup is empty."),
            CClientUIInterface::MSG_ERROR);
        return;
    }

    const QString tempWalletOut = inFilename + ".decrypted.wallet.dat";
    QFile outWallet(tempWalletOut);
    if (!outWallet.open(QIODevice::WriteOnly | QIODevice::Truncate)) {
        if (!plainData.empty()) memory_cleanse(plainData.data(), plainData.size());
        Q_EMIT message(tr("Restore Failed"), tr("Unable to write decrypted wallet data."),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    outWallet.write(reinterpret_cast<const char*>(plainData.data()), plainData.size());
    outWallet.close();
    if (!plainData.empty()) memory_cleanse(plainData.data(), plainData.size());

    const QMessageBox::StandardButton answer = QMessageBox::question(
        this,
        tr("Restore Wallet"),
        tr("Replace current wallet file with decrypted backup and restart now?\n\nCurrent wallet file: %1\nDecrypted backup: %2")
            .arg(walletModel->getWalletFilePath(), tempWalletOut),
        QMessageBox::Yes | QMessageBox::No,
        QMessageBox::No);

    if (answer != QMessageBox::Yes) {
        Q_EMIT message(tr("Restore Complete"), tr("Decrypted wallet written to %1").arg(tempWalletOut),
            CClientUIInterface::MSG_INFORMATION);
        return;
    }

    const QString walletPath = walletModel->getWalletFilePath();
    if (walletPath.isEmpty()) {
        Q_EMIT message(tr("Restore Failed"), tr("Unable to resolve current wallet file path."),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    if (QFile::exists(walletPath)) {
        const QString backupCurrent = walletPath + ".before-pqce-restore.bak";
        QFile::remove(backupCurrent);
        if (!QFile::rename(walletPath, backupCurrent)) {
            Q_EMIT message(tr("Restore Failed"), tr("Unable to backup current wallet file %1").arg(walletPath),
                CClientUIInterface::MSG_ERROR);
            return;
        }
    }
    if (!QFile::copy(tempWalletOut, walletPath)) {
        Q_EMIT message(tr("Restore Failed"), tr("Unable to copy decrypted wallet into active wallet file."),
            CClientUIInterface::MSG_ERROR);
        return;
    }
    QFile::remove(tempWalletOut);

    Q_EMIT message(tr("Restore Successful"), tr("Wallet file was restored from PQC envelope. Client will now restart."),
        CClientUIInterface::MSG_INFORMATION);
    StartShutdown();
}

void WalletView::showPQCSignatureDialog()
{
    QDialog dlg(this);
    dlg.setWindowTitle(tr("Manage PQC Keys..."));
    dlg.resize(780, 460);
    QVBoxLayout* vbox = new QVBoxLayout(&dlg);
    QLabel* helpLabel = new QLabel(tr("Manage PQC signature keys for the selected algorithm.\n"
                                      "Generate and store encrypted key pairs, review stored keys, and remove stored keys."), &dlg);
    helpLabel->setWordWrap(true);
    vbox->addWidget(helpLabel);

    QComboBox* algorithm = new QComboBox(&dlg);
    algorithm->addItem("falcon512");
    algorithm->addItem("dilithium2");
#ifdef ENABLE_LIBOQS_RACCOON
    algorithm->addItem("raccoong44");
#endif

    QLineEdit* publicKeyHex = new QLineEdit(&dlg);
    publicKeyHex->setReadOnly(true);
    publicKeyHex->setPlaceholderText(tr("Hex-encoded public key"));
    QPlainTextEdit* privateKeyHex = new QPlainTextEdit(&dlg);
    privateKeyHex->setReadOnly(true);
    privateKeyHex->setPlaceholderText(tr("Encrypted private key export requires passphrase"));
    privateKeyHex->setLineWrapMode(QPlainTextEdit::NoWrap);
    privateKeyHex->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    privateKeyHex->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
    privateKeyHex->setFixedHeight(64);
    QPushButton* generateKeypairButton = new QPushButton(tr("Generate && Store Encrypted Key Pair"), &dlg);
    QPushButton* importKeypairButton = new QPushButton(tr("Import Key Pair"), &dlg);
    QPushButton* exportPrivateKeyButton = new QPushButton(tr("Export Private Key"), &dlg);
    QPushButton* removeStoredButton = new QPushButton(tr("Remove Stored Key"), &dlg);
    QListWidget* keyInventoryList = new QListWidget(&dlg);
    QLabel* storedStatusLabel = new QLabel(&dlg);
    storedStatusLabel->setWordWrap(true);
    QLabel* actionStatusLabel = new QLabel(&dlg);
    actionStatusLabel->setWordWrap(true);

    QFormLayout* form = new QFormLayout();
    form->addRow(tr("Algorithm:"), algorithm);
    vbox->addLayout(form);

    QGridLayout* keyButtons = new QGridLayout();
    keyButtons->addWidget(generateKeypairButton, 0, 0);
    keyButtons->addWidget(importKeypairButton, 0, 1);
    keyButtons->addWidget(exportPrivateKeyButton, 1, 0);
    keyButtons->addWidget(removeStoredButton, 1, 1);
    keyButtons->setColumnStretch(0, 0);
    keyButtons->setColumnStretch(1, 0);
    vbox->addLayout(keyButtons);

    vbox->addWidget(new QLabel(tr("Stored key pairs:"), &dlg));
    keyInventoryList->setMinimumHeight(84);
    keyInventoryList->setMaximumHeight(130);
    vbox->addWidget(keyInventoryList);
    vbox->addWidget(new QLabel(tr("Public key (hex):"), &dlg));
    vbox->addWidget(publicKeyHex);
    vbox->addWidget(new QLabel(tr("Private key (hex):"), &dlg));
    vbox->addWidget(privateKeyHex);
    vbox->addWidget(storedStatusLabel);
    vbox->addWidget(actionStatusLabel);

    QDialogButtonBox* buttons = new QDialogButtonBox(QDialogButtonBox::Close, &dlg);
    vbox->addWidget(buttons);

    auto refreshStoredStatus = [&]() {
        QListWidgetItem* currentItem = keyInventoryList->currentItem();
        if (!walletModel) {
            storedStatusLabel->setText(tr("Wallet model is not available."));
            removeStoredButton->setEnabled(false);
            exportPrivateKeyButton->setEnabled(false);
            publicKeyHex->clear();
            privateKeyHex->clear();
            return;
        }

        if (!currentItem) {
            storedStatusLabel->setText(tr("Stored key status: no %1 key is saved in wallet metadata.")
                                       .arg(algorithm->currentText()));
            removeStoredButton->setEnabled(false);
            exportPrivateKeyButton->setEnabled(false);
            publicKeyHex->clear();
            privateKeyHex->clear();
            return;
        }
        const QString selectedAlgorithm = currentItem->data(Qt::UserRole).toString();
        const QString pubHex = currentItem->data(Qt::UserRole + 1).toString();
        const bool hasEncryptedPrivate = currentItem->data(Qt::UserRole + 3).toBool();
        const QString created = currentItem->data(Qt::UserRole + 4).toString();
        QString summary = tr("Stored key status: %1 key is saved").arg(selectedAlgorithm);
        if (!created.isEmpty()) {
            summary += tr(" (created %1)").arg(created);
        }
        summary += hasEncryptedPrivate
            ? tr(" with encrypted private key material.")
            : tr(" without encrypted private key material.");
        if (!pubHex.isEmpty() && pubHex.size() > 16) {
            summary += tr(" Public key: %1...%2").arg(pubHex.left(8), pubHex.right(8));
        }
        storedStatusLabel->setText(summary);
        publicKeyHex->setText(pubHex);
        removeStoredButton->setEnabled(true);
        exportPrivateKeyButton->setEnabled(hasEncryptedPrivate);
    };

    auto selectStoredItem = [&](const QString& algorithmName, const QString& pubHex) {
        for (int i = 0; i < keyInventoryList->count(); ++i) {
            QListWidgetItem* item = keyInventoryList->item(i);
            if (!item) continue;
            if (item->data(Qt::UserRole).toString() == algorithmName &&
                item->data(Qt::UserRole + 1).toString() == pubHex) {
                keyInventoryList->setCurrentRow(i);
                return true;
            }
        }
        return false;
    };

    auto refreshStoredInventory = [&]() {
        keyInventoryList->clear();
        if (!walletModel) {
            refreshStoredStatus();
            return;
        }
        const char* algorithms[] = {
            "falcon512",
            "dilithium2",
#ifdef ENABLE_LIBOQS_RACCOON
            "raccoong44"
#endif
        };

        for (size_t i = 0; i < sizeof(algorithms) / sizeof(algorithms[0]); ++i) {
            const QString algorithmName = QString::fromLatin1(algorithms[i]);
            const std::string prefix = PQCSignatureStoragePrefixForAlgorithm(algorithmName);
            const auto entries = walletModel->listWalletMetaWithPrefix(prefix);
            for (const auto& kv : entries) {
                QJsonParseError parseError;
                QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(kv.second), &parseError);
                if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
                    continue;
                }
                const QJsonObject obj = doc.object();
                const QString pubHex = obj.value("public_key_hex").toString().trimmed();
                if (pubHex.isEmpty()) {
                    continue;
                }
                QString label = QString("%1 • %2...%3")
                    .arg(algorithmName)
                    .arg(pubHex.left(10))
                    .arg(pubHex.right(8));
                const QString created = obj.value("created_utc").toString().trimmed();
                if (!created.isEmpty()) {
                    label += tr(" (created %1)").arg(created);
                }
                QListWidgetItem* item = new QListWidgetItem(label, keyInventoryList);
                item->setData(Qt::UserRole, algorithmName);
                item->setData(Qt::UserRole + 1, pubHex);
                item->setData(Qt::UserRole + 2, QString::fromStdString(kv.first));
                item->setData(Qt::UserRole + 3, !obj.value("encrypted_private_key_hex").toString().isEmpty());
                item->setData(Qt::UserRole + 4, created);
            }
        }

        for (int i = 0; i < keyInventoryList->count(); ++i) {
            QListWidgetItem* item = keyInventoryList->item(i);
            if (item && item->data(Qt::UserRole).toString() == algorithm->currentText()) {
                keyInventoryList->setCurrentRow(i);
                refreshStoredStatus();
                return;
            }
        }
        if (keyInventoryList->count() > 0) {
            keyInventoryList->setCurrentRow(0);
        }
        refreshStoredStatus();
    };

    connect(buttons, &QDialogButtonBox::rejected, &dlg, &QDialog::reject);
    connect(algorithm, &QComboBox::currentTextChanged, [&]() {
        for (int i = 0; i < keyInventoryList->count(); ++i) {
            QListWidgetItem* item = keyInventoryList->item(i);
            if (item && item->data(Qt::UserRole).toString() == algorithm->currentText()) {
                keyInventoryList->setCurrentRow(i);
                refreshStoredStatus();
                return;
            }
        }
        keyInventoryList->setCurrentItem(nullptr);
        refreshStoredStatus();
    });
    connect(keyInventoryList, &QListWidget::currentItemChanged, [&]() {
        QListWidgetItem* item = keyInventoryList->currentItem();
        if (item) {
            const QString itemAlgorithm = item->data(Qt::UserRole).toString();
            if (algorithm->currentText() != itemAlgorithm) {
                algorithm->setCurrentText(itemAlgorithm);
            }
        }
        refreshStoredStatus();
    });
    connect(removeStoredButton, &QPushButton::clicked, [&]() {
        if (!walletModel) {
            actionStatusLabel->setText(tr("Wallet model is not available."));
            return;
        }
        QListWidgetItem* selectedItem = keyInventoryList->currentItem();
        if (!selectedItem) {
            actionStatusLabel->setText(tr("Select a stored key pair first."));
            return;
        }
        const QString selectedAlgorithm = selectedItem->data(Qt::UserRole).toString();
        const QString storageKey = selectedItem->data(Qt::UserRole + 2).toString();
        const QMessageBox::StandardButton confirm = QMessageBox::question(
            &dlg,
            tr("Remove Stored PQC Key"),
            tr("Remove stored %1 key from wallet metadata?").arg(selectedAlgorithm));
        if (confirm != QMessageBox::Yes) {
            actionStatusLabel->setText(tr("Removal cancelled."));
            return;
        }
        if (!walletModel->saveWalletMeta(storageKey.toStdString(), std::string())) {
            actionStatusLabel->setText(tr("Failed to remove stored %1 key.").arg(selectedAlgorithm));
            return;
        }
        actionStatusLabel->setText(tr("Removed stored %1 key from wallet metadata.").arg(selectedAlgorithm));
        privateKeyHex->clear();
        refreshStoredInventory();
    });
    connect(exportPrivateKeyButton, &QPushButton::clicked, [&]() {
        if (!walletModel) {
            actionStatusLabel->setText(tr("Wallet model is not available."));
            return;
        }
        QListWidgetItem* selectedItem = keyInventoryList->currentItem();
        if (!selectedItem) {
            actionStatusLabel->setText(tr("Select a stored key pair first."));
            return;
        }
        std::string metaJson;
        const QString storageKey = selectedItem->data(Qt::UserRole + 2).toString();
        if (!walletModel->getWalletMeta(storageKey.toStdString(), &metaJson)) {
            actionStatusLabel->setText(tr("Failed to load selected stored key."));
            return;
        }
        QJsonParseError parseError;
        QJsonDocument doc = QJsonDocument::fromJson(QByteArray::fromStdString(metaJson), &parseError);
        if (parseError.error != QJsonParseError::NoError || !doc.isObject()) {
            actionStatusLabel->setText(tr("Stored key metadata is invalid."));
            return;
        }
        QJsonObject obj = doc.object();
        const QString encryptedHex = obj.value("encrypted_private_key_hex").toString().trimmed();
        const QString saltHex = obj.value("salt_hex").toString().trimmed();
        const int rounds = obj.value("kdf_rounds").toInt(25000);
        if (encryptedHex.isEmpty() || saltHex.isEmpty()) {
            actionStatusLabel->setText(tr("Selected key has no encrypted private key material."));
            return;
        }
        if (!IsHex(encryptedHex.toStdString()) || !IsHex(saltHex.toStdString())) {
            actionStatusLabel->setText(tr("Stored encrypted private key material is invalid."));
            return;
        }

        bool ok = false;
        QString passphrase = QInputDialog::getText(
            &dlg,
            tr("Export PQC Private Key"),
            tr("Enter passphrase to decrypt the stored private key:"),
            QLineEdit::Password,
            QString(),
            &ok);
        if (!ok || passphrase.isEmpty()) {
            actionStatusLabel->setText(tr("Private key export cancelled."));
            return;
        }

        std::vector<unsigned char> encryptedPrivate = ParseHex(encryptedHex.toStdString());
        std::vector<unsigned char> salt = ParseHex(saltHex.toStdString());
        QByteArray passphraseBytes = passphrase.toUtf8();
        SecureString pass(passphraseBytes.constData(), passphraseBytes.constData() + passphraseBytes.size());
        CCrypter keyCrypter;
        if (!keyCrypter.SetKeyFromPassphrase(pass, salt, rounds, 0)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            actionStatusLabel->setText(tr("Failed to derive decryption key from passphrase."));
            return;
        }
        CKeyingMaterial decryptedPrivate;
        if (!keyCrypter.Decrypt(encryptedPrivate, decryptedPrivate)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            actionStatusLabel->setText(tr("Failed to decrypt private key. Check passphrase."));
            return;
        }
        if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
        const QString privateHex = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(decryptedPrivate.data()), decryptedPrivate.size()).toHex());
        privateKeyHex->setPlainText(privateHex);
        if (!decryptedPrivate.empty()) memory_cleanse(decryptedPrivate.data(), decryptedPrivate.size());
        actionStatusLabel->setText(tr("Private key exported to field for selected key."));
    });
    connect(importKeypairButton, &QPushButton::clicked, [&]() {
        if (!walletModel) {
            actionStatusLabel->setText(tr("Wallet model is not available."));
            return;
        }
        QDialog importDlg(&dlg);
        importDlg.setWindowTitle(tr("Import PQC Key Pair"));
        importDlg.resize(720, 320);
        QVBoxLayout* importVbox = new QVBoxLayout(&importDlg);

        QComboBox* importAlgorithm = new QComboBox(&importDlg);
        importAlgorithm->addItem("falcon512");
        importAlgorithm->addItem("dilithium2");
#ifdef ENABLE_LIBOQS_RACCOON
        importAlgorithm->addItem("raccoong44");
#endif
        importAlgorithm->setCurrentText(algorithm->currentText());

        QLineEdit* importPublicKeyHex = new QLineEdit(&importDlg);
        importPublicKeyHex->setPlaceholderText(tr("Public key hex"));
        QPlainTextEdit* importPrivateKeyHex = new QPlainTextEdit(&importDlg);
        importPrivateKeyHex->setPlaceholderText(tr("Private key hex"));
        importPrivateKeyHex->setLineWrapMode(QPlainTextEdit::NoWrap);
        importPrivateKeyHex->setHorizontalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        importPrivateKeyHex->setVerticalScrollBarPolicy(Qt::ScrollBarAsNeeded);
        importPrivateKeyHex->setFixedHeight(84);

        QFormLayout* importForm = new QFormLayout();
        importForm->addRow(tr("Algorithm:"), importAlgorithm);
        importForm->addRow(tr("Public key (hex):"), importPublicKeyHex);
        importForm->addRow(tr("Private key (hex):"), importPrivateKeyHex);
        importVbox->addLayout(importForm);

        QDialogButtonBox* importButtons = new QDialogButtonBox(QDialogButtonBox::Ok | QDialogButtonBox::Cancel, &importDlg);
        importVbox->addWidget(importButtons);
        connect(importButtons, &QDialogButtonBox::rejected, &importDlg, &QDialog::reject);
        connect(importButtons, &QDialogButtonBox::accepted, &importDlg, &QDialog::accept);

        if (importDlg.exec() != QDialog::Accepted) {
            actionStatusLabel->setText(tr("PQC key import cancelled."));
            return;
        }

        const QString selectedAlgorithm = importAlgorithm->currentText();
        const QString publicHex = importPublicKeyHex->text().trimmed();
        QString privateHex = importPrivateKeyHex->toPlainText().trimmed();
        privateHex.remove(QRegularExpression("\\s+"));
        if (publicHex.isEmpty() || privateHex.isEmpty()) {
            actionStatusLabel->setText(tr("Both public and private key hex are required."));
            return;
        }
        if (!IsHex(publicHex.toStdString()) || !IsHex(privateHex.toStdString())) {
            actionStatusLabel->setText(tr("Imported key hex is invalid."));
            return;
        }

        bool ok = false;
        QString passphrase = QInputDialog::getText(
            &dlg,
            tr("Encrypt Imported PQC Private Key"),
            tr("Enter passphrase to encrypt imported private key:"),
            QLineEdit::Password,
            QString(),
            &ok);
        if (!ok || passphrase.isEmpty()) {
            actionStatusLabel->setText(tr("PQC key import cancelled."));
            return;
        }

        std::vector<unsigned char> rawPrivateKey = ParseHex(privateHex.toStdString());
        if (rawPrivateKey.empty()) {
            actionStatusLabel->setText(tr("Imported private key is empty."));
            return;
        }
        std::vector<unsigned char> salt(WALLET_CRYPTO_SALT_SIZE);
        GetStrongRandBytes(salt.data(), salt.size());
        QByteArray passphraseBytes = passphrase.toUtf8();
        SecureString pass(passphraseBytes.constData(), passphraseBytes.constData() + passphraseBytes.size());
        CCrypter keyCrypter;
        if (!keyCrypter.SetKeyFromPassphrase(pass, salt, 25000, 0)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            if (!rawPrivateKey.empty()) memory_cleanse(rawPrivateKey.data(), rawPrivateKey.size());
            actionStatusLabel->setText(tr("Failed to derive key encryption key."));
            return;
        }
        CKeyingMaterial privateMaterial(rawPrivateKey.begin(), rawPrivateKey.end());
        std::vector<unsigned char> encryptedPrivateKey;
        if (!keyCrypter.Encrypt(privateMaterial, encryptedPrivateKey)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            if (!rawPrivateKey.empty()) memory_cleanse(rawPrivateKey.data(), rawPrivateKey.size());
            if (!privateMaterial.empty()) memory_cleanse(&privateMaterial[0], privateMaterial.size());
            actionStatusLabel->setText(tr("Failed to encrypt imported private key."));
            return;
        }

        if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
        if (!rawPrivateKey.empty()) memory_cleanse(rawPrivateKey.data(), rawPrivateKey.size());
        if (!privateMaterial.empty()) memory_cleanse(&privateMaterial[0], privateMaterial.size());

        QJsonObject keyObj;
        keyObj["version"] = 1;
        keyObj["algorithm"] = selectedAlgorithm;
        keyObj["created_utc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        keyObj["public_key_hex"] = publicHex;
        keyObj["encrypted_private_key_hex"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(encryptedPrivateKey.data()), encryptedPrivateKey.size()).toHex());
        keyObj["salt_hex"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(salt.data()), salt.size()).toHex());
        keyObj["kdf"] = "sha512-aes256cbc";
        keyObj["kdf_rounds"] = 25000;
        const QByteArray serialized = QJsonDocument(keyObj).toJson(QJsonDocument::Compact);

        const std::string storageKey = PQCSignatureStorageKeyForPubHex(selectedAlgorithm, publicHex);
        if (!walletModel->saveWalletMeta(storageKey, serialized.toStdString())) {
            actionStatusLabel->setText(tr("Failed to persist imported PQC key pair."));
            return;
        }
        actionStatusLabel->setText(tr("Imported and stored %1 key pair in wallet metadata (private key encrypted).")
                                   .arg(selectedAlgorithm));
        privateKeyHex->clear();
        refreshStoredInventory();
        selectStoredItem(selectedAlgorithm, publicHex);
        refreshStoredStatus();
    });
    connect(generateKeypairButton, &QPushButton::clicked, [&]() {
        if (!walletModel) {
            actionStatusLabel->setText(tr("Wallet model is not available."));
            return;
        }
        bool ok = false;
        QString passphrase = QInputDialog::getText(
            &dlg,
            tr("Encrypt PQC Private Key"),
            tr("Enter passphrase to encrypt generated PQC private key:"),
            QLineEdit::Password,
            QString(),
            &ok);
        if (!ok || passphrase.isEmpty()) {
            actionStatusLabel->setText(tr("PQC key generation cancelled."));
            return;
        }

        // Show progress dialog during key generation and encryption
        QProgressDialog progress(tr("Generating PQC key pair..."), QString(), 0, 100, &dlg);
        progress.setWindowModality(Qt::ApplicationModal);
        progress.setMinimumDuration(0);
        progress.setCancelButton(nullptr);
        progress.setAutoClose(false);
        progress.setValue(5);
        progress.setLabelText(tr("Generating %1 key pair...").arg(algorithm->currentText()));
        QApplication::processEvents();

#if ENABLE_LIBOQS
        // Generate real PQC keypair using liboqs (e.g. Falcon-512: pk=897, sk=1281 bytes)
        PQCCommitmentType pqcType;
        if (!ParsePQCCommitmentType(algorithm->currentText().toStdString(), pqcType)) {
            progress.close();
            actionStatusLabel->setText(tr("Unknown PQC algorithm: %1").arg(algorithm->currentText()));
            return;
        }
        std::vector<unsigned char> realPublicKey;
        std::vector<unsigned char> realSecretKey;
        if (!PQCGenerateKeypair(pqcType, realPublicKey, realSecretKey)) {
            progress.close();
            actionStatusLabel->setText(tr("Failed to generate %1 keypair via liboqs.").arg(algorithm->currentText()));
            return;
        }

        QByteArray publicKey(reinterpret_cast<const char*>(realPublicKey.data()), realPublicKey.size());
        QByteArray privateKey(reinterpret_cast<const char*>(realSecretKey.data()), realSecretKey.size());
        memory_cleanse(realSecretKey.data(), realSecretKey.size());
#else
        progress.close();
        actionStatusLabel->setText(tr("PQC key generation requires liboqs. Rebuild with --with-liboqs --enable-experimental."));
        return;
        QByteArray publicKey;
        QByteArray privateKey;
#endif

        progress.setValue(40);
        progress.setLabelText(tr("Encrypting private key..."));
        QApplication::processEvents();

        std::vector<unsigned char> salt(WALLET_CRYPTO_SALT_SIZE);
        GetStrongRandBytes(salt.data(), salt.size());
        QByteArray passphraseBytes = passphrase.toUtf8();
        SecureString pass(passphraseBytes.constData(), passphraseBytes.constData() + passphraseBytes.size());
        CCrypter keyCrypter;
        if (!keyCrypter.SetKeyFromPassphrase(pass, salt, 25000, 0)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            if (!privateKey.isEmpty()) memory_cleanse(privateKey.data(), privateKey.size());
            progress.close();
            actionStatusLabel->setText(tr("Failed to derive key encryption key."));
            return;
        }
        CKeyingMaterial privateMaterial(reinterpret_cast<const unsigned char*>(privateKey.constData()),
                                        reinterpret_cast<const unsigned char*>(privateKey.constData()) + privateKey.size());
        std::vector<unsigned char> encryptedPrivateKey;
        if (!keyCrypter.Encrypt(privateMaterial, encryptedPrivateKey)) {
            if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
            if (!privateKey.isEmpty()) memory_cleanse(privateKey.data(), privateKey.size());
            if (!privateMaterial.empty()) memory_cleanse(&privateMaterial[0], privateMaterial.size());
            progress.close();
            actionStatusLabel->setText(tr("Failed to encrypt generated private key."));
            return;
        }

        if (!passphraseBytes.isEmpty()) memory_cleanse(passphraseBytes.data(), passphraseBytes.size());
        if (!privateKey.isEmpty()) memory_cleanse(privateKey.data(), privateKey.size());
        if (!privateMaterial.empty()) memory_cleanse(&privateMaterial[0], privateMaterial.size());

        progress.setValue(70);
        progress.setLabelText(tr("Storing encrypted key pair..."));
        QApplication::processEvents();

        QJsonObject keyObj;
        keyObj["version"] = 1;
        keyObj["algorithm"] = algorithm->currentText();
        keyObj["created_utc"] = QDateTime::currentDateTimeUtc().toString(Qt::ISODate);
        keyObj["public_key_hex"] = QString::fromLatin1(publicKey.toHex());
        keyObj["encrypted_private_key_hex"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(encryptedPrivateKey.data()), encryptedPrivateKey.size()).toHex());
        keyObj["salt_hex"] = QString::fromLatin1(QByteArray(reinterpret_cast<const char*>(salt.data()), salt.size()).toHex());
        keyObj["kdf"] = "sha512-aes256cbc";
        keyObj["kdf_rounds"] = 25000;
        const QByteArray serialized = QJsonDocument(keyObj).toJson(QJsonDocument::Compact);

        const QString generatedPubHex = QString::fromLatin1(publicKey.toHex());
        const std::string storageKey = PQCSignatureStorageKeyForPubHex(algorithm->currentText(), generatedPubHex);
        if (!walletModel->saveWalletMeta(storageKey, serialized.toStdString())) {
            progress.close();
            actionStatusLabel->setText(tr("Failed to persist generated PQC key in wallet metadata."));
            return;
        }

        progress.setValue(100);
        progress.close();

        QMessageBox::information(&dlg, tr("PQC Key Generation Successful"),
            tr("Successfully generated and stored %1 key pair.\n\n"
               "Public key size: %2 bytes\n"
               "Private key: encrypted and stored in wallet metadata.")
            .arg(algorithm->currentText())
            .arg(publicKey.size()));

        actionStatusLabel->setText(tr("Generated and stored %1 key pair in wallet metadata (private key encrypted, pk=%2 bytes).")
                                   .arg(algorithm->currentText())
                                   .arg(publicKey.size()));
        privateKeyHex->clear();
        refreshStoredInventory();
        selectStoredItem(algorithm->currentText(), generatedPubHex);
        refreshStoredStatus();
    });
    refreshStoredInventory();
    dlg.exec();
}

void WalletView::changePassphrase()
{
    AskPassphraseDialog dlg(AskPassphraseDialog::ChangePass, this);
    dlg.setModel(walletModel);
    dlg.exec();
}

void WalletView::unlockWallet()
{
    if(!walletModel)
        return;
    // Unlock wallet when requested by wallet model
    if (walletModel->getEncryptionStatus() == WalletModel::Locked)
    {
        AskPassphraseDialog dlg(AskPassphraseDialog::Unlock, this);
        dlg.setModel(walletModel);
        dlg.exec();
    }
}

void WalletView::usedSendingAddresses()
{
    if(!walletModel)
        return;

    usedSendingAddressesPage->show();
    usedSendingAddressesPage->raise();
    usedSendingAddressesPage->activateWindow();
}

void WalletView::usedReceivingAddresses()
{
    if(!walletModel)
        return;

    usedReceivingAddressesPage->show();
    usedReceivingAddressesPage->raise();
    usedReceivingAddressesPage->activateWindow();
}

void WalletView::importPrivateKey()
{
    if(!walletModel)
        return;

    importKeysDialog->show();
    importKeysDialog->raise();
    importKeysDialog->activateWindow();
}

#ifdef USE_BIP39
EXPERIMENTAL_FEATURE
void WalletView::importBip39Mnemonic()
{
    if(!walletModel)
        return;

    importBip39Dialog->show();
    importBip39Dialog->raise();
    importBip39Dialog->activateWindow();
}
#endif

void WalletView::showProgress(const QString &title, int nProgress)
{
    if (nProgress == 0)
    {
        progressDialog = new QProgressDialog(title, "", 0, 100);
        progressDialog->setWindowModality(Qt::ApplicationModal);
        progressDialog->setMinimumDuration(0);
        progressDialog->setCancelButton(0);
        progressDialog->setAutoClose(false);
        progressDialog->setValue(0);
    }
    else if (nProgress == 100)
    {
        if (progressDialog)
        {
            progressDialog->close();
            progressDialog->deleteLater();
        }
    }
    else if (progressDialog)
        progressDialog->setValue(nProgress);
}

void WalletView::requestedSyncWarningInfo()
{
    Q_EMIT outOfSyncWarningClicked();
}

void WalletView::printPaperWallets()
{
    if(!walletModel)
        return;

    PaperWalletDialog dlg(this);
    dlg.setModel(walletModel);
    dlg.setClientModel(clientModel);
    dlg.exec();
}
