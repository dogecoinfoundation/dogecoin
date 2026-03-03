// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_DASHB0RD_H
#define BITCOIN_QT_DASHB0RD_H

#include <QWidget>

class ClientModel;
class WalletModel;
class PlatformStyle;
class Dashb0rdPage;

class Dashb0rd : public QWidget
{
    Q_OBJECT

public:
    explicit Dashb0rd(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~Dashb0rd();

    void setClientModel(ClientModel* model);
    void setWalletModel(WalletModel* model);

private:
    const PlatformStyle* m_platformStyle;
    Dashb0rdPage* m_page;
};

#endif // BITCOIN_QT_DASHB0RD_H
