// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "dashb0rd.h"

#include "dashb0rdpage.h"

#include <QVBoxLayout>

Dashb0rd::Dashb0rd(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent),
      m_platformStyle(platformStyle),
      m_page(nullptr)
{
    // Embed the dashboard page directly so this wrapper can forward model updates.
    QVBoxLayout* root = new QVBoxLayout(this);
    root->setContentsMargins(0, 0, 0, 0);
    root->setSpacing(0);

    // Constructor order for Dashb0rdPage is (platformStyle, parent).
    m_page = new Dashb0rdPage(m_platformStyle, this);
    root->addWidget(m_page);
}

Dashb0rd::~Dashb0rd()
{
}

void Dashb0rd::setClientModel(ClientModel* model)
{
    // Forward the shared client model to the underlying dashboard page.
    if (m_page) m_page->setClientModel(model);
}

void Dashb0rd::setWalletModel(WalletModel* model)
{
    // Forward the wallet model so page-level wallet features can use it.
    if (m_page) m_page->setWalletModel(model);
}
