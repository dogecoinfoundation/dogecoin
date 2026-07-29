// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2020-2022 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "splashscreen.h"

#include "networkstyle.h"
#include "platformstyle.h"

#include "clientversion.h"
#include "init.h"
#include "util.h"
#include "ui_interface.h"
#include "version.h"

#ifdef ENABLE_WALLET
#include "wallet/wallet.h"
#endif

#include <QApplication>
#include <QCloseEvent>
#include <QDesktopWidget>
#include <QMenu>
#include <QPainter>
#include <QPushButton>
#include <QRadialGradient>
#include <QActionGroup>

#include <boost/bind/bind.hpp>

SplashScreen::SplashScreen(Qt::WindowFlags f, const NetworkStyle *networkStyle) :
    QWidget(0, f), curAlignment(0), networkStyle(networkStyle), darkModeButton(nullptr), darkModeTintMenu(nullptr)
{
    buildPixmap(PlatformStyle::isDarkModeEnabled());

    // Set window title
    setWindowTitle(tr(PACKAGE_NAME) + " " + networkStyle->getTitleAddText());

    // Resize window and move to center of desktop, disallow resizing
    const qreal ratio = pixmap.devicePixelRatio();
    QRect r(QPoint(), QSize(pixmap.size().width()/ratio, pixmap.size().height()/ratio));
    resize(r.size());
    setFixedSize(r.size());
    move(QApplication::desktop()->screenGeometry().center() - r.center());
    darkModeButton = new QPushButton(this);
    darkModeButton->setContextMenuPolicy(Qt::CustomContextMenu);
    darkModeTintMenu = new QMenu(darkModeButton);
    QActionGroup* tintGroup = new QActionGroup(darkModeTintMenu);
    tintGroup->setExclusive(true);
    for (int tint = 0; tint < PlatformStyle::darkModeTintCount(); ++tint) {
        QAction* tintAction = new QAction(PlatformStyle::darkModeTintName(tint), darkModeTintMenu);
        tintAction->setData(tint);
        tintAction->setCheckable(true);
        tintGroup->addAction(tintAction);
        darkModeTintMenu->addAction(tintAction);
    }
    connect(darkModeButton, SIGNAL(clicked()), this, SLOT(toggleDarkMode()));
    connect(darkModeButton, SIGNAL(customContextMenuRequested(QPoint)), this, SLOT(showDarkTintMenu(QPoint)));
    connect(darkModeTintMenu, SIGNAL(triggered(QAction*)), this, SLOT(onDarkTintSelected(QAction*)));
    updateDarkModeButton();
    darkModeButton->show();

    subscribeToCoreSignals();
}

SplashScreen::~SplashScreen()
{
    unsubscribeFromCoreSignals();
}

void SplashScreen::slotFinish(QWidget *mainWin)
{
    Q_UNUSED(mainWin);

    /* If the window is minimized, hide() will be ignored. */
    /* Make sure we de-minimize the splashscreen window before hiding */
    if (isMinimized())
        showNormal();
    hide();
    deleteLater(); // No more need for this
}

static void InitMessage(SplashScreen *splash, const std::string &message)
{
    const QColor progressColor = PlatformStyle::isDarkModeEnabled() ? QColor(214,232,220) : QColor(55,55,55);
    QMetaObject::invokeMethod(splash, "showMessage",
        Qt::QueuedConnection,
        Q_ARG(QString, QString::fromStdString(message)),
        Q_ARG(int, Qt::AlignBottom|Qt::AlignHCenter),
        Q_ARG(QColor, progressColor));
}

static void ShowProgress(SplashScreen *splash, const std::string &title, int nProgress)
{
    InitMessage(splash, title + strprintf("%d", nProgress) + "%");
}

#ifdef ENABLE_WALLET
void SplashScreen::ConnectWallet(CWallet* wallet)
{
    wallet->ShowProgress.connect(boost::bind(ShowProgress, this,
                                             boost::placeholders::_1,
                                             boost::placeholders::_2));
    connectedWallets.push_back(wallet);
}
#endif

void SplashScreen::subscribeToCoreSignals()
{
    // Connect signals to client
    uiInterface.InitMessage.connect(boost::bind(InitMessage, this,
                                                boost::placeholders::_1));
    uiInterface.ShowProgress.connect(boost::bind(ShowProgress, this,
                                                 boost::placeholders::_1,boost::placeholders::_2));
#ifdef ENABLE_WALLET
    uiInterface.LoadWallet.connect(boost::bind(&SplashScreen::ConnectWallet, this,
                                               boost::placeholders::_1));
#endif
}

void SplashScreen::unsubscribeFromCoreSignals()
{
    // Disconnect signals from client
    uiInterface.InitMessage.disconnect(boost::bind(InitMessage, this,
                                                   boost::placeholders::_1));
    uiInterface.ShowProgress.disconnect(boost::bind(ShowProgress, this,
                                                    boost::placeholders::_1,
                                                    boost::placeholders::_2));
#ifdef ENABLE_WALLET
    Q_FOREACH(CWallet* const & pwallet, connectedWallets) {
        pwallet->ShowProgress.disconnect(boost::bind(ShowProgress, this,
                                                     boost::placeholders::_1,
                                                     boost::placeholders::_2));
    }
#endif
}

void SplashScreen::showMessage(const QString &message, int alignment, const QColor &color)
{
    curMessage = message;
    curAlignment = alignment;
    curColor = color;
    update();
}

void SplashScreen::toggleDarkMode()
{
    const bool darkModeEnabled = PlatformStyle::isDarkModeEnabled();
    PlatformStyle::setDarkModeEnabled(!darkModeEnabled);
    buildPixmap(!darkModeEnabled);
    updateDarkModeButton();
    update();
}

void SplashScreen::buildPixmap(bool darkModeEnabled)
{
    // set reference point, paddings
    int paddingRight            = 50;
    int paddingTop              = 50;
    int titleVersionVSpace      = 17;
    int titleCopyrightVSpace    = 40;

    float fontFactor            = 1.0;
    float devicePixelRatio      = 1.0;
#if QT_VERSION > 0x050100
    devicePixelRatio = ((QGuiApplication*)QCoreApplication::instance())->devicePixelRatio();
#endif

    // define text to place
    QString titleText       = tr(PACKAGE_NAME);
    QString versionText     = QString("Version %1").arg(QString::fromStdString(FormatFullVersion()));
    QString copyrightText   = QString::fromUtf8(CopyrightHolders(strprintf("\xc2\xA9 %u-%u ", 2009, COPYRIGHT_YEAR)).c_str());
    QString titleAddText    = networkStyle->getTitleAddText();

    QString font            = "Comic Sans MS";

    // create a bitmap according to device pixelratio
    QSize splashSize(480*devicePixelRatio,320*devicePixelRatio);
    pixmap = QPixmap(splashSize);

#if QT_VERSION > 0x050100
    // change to HiDPI if it makes sense
    pixmap.setDevicePixelRatio(devicePixelRatio);
#endif

    QPainter pixPaint(&pixmap);
    const QColor textColor = darkModeEnabled ? QColor(214,232,220) : QColor(100,100,100);
    pixPaint.setPen(textColor);

    // draw a slightly radial gradient
    QRadialGradient gradient(QPoint(0,0), splashSize.width()/devicePixelRatio);
    if (darkModeEnabled) {
        gradient.setColorAt(0, QColor(22, 31, 27));
        gradient.setColorAt(1, QColor(15, 23, 19));
    } else {
        gradient.setColorAt(0, Qt::white);
        gradient.setColorAt(1, QColor(247,247,247));
    }
    QRect rGradient(QPoint(0,0), splashSize);
    pixPaint.fillRect(rGradient, gradient);

    // draw the bitcoin icon, expected size of PNG: 1024x1024
    QRect rectIcon(QPoint(-150,-122), QSize(430,430));

    const QSize requiredSize(1024,1024);
    QPixmap icon(networkStyle->getAppIcon().pixmap(requiredSize));

    pixPaint.drawPixmap(rectIcon, icon);

    // check font size and drawing with
    pixPaint.setFont(QFont(font, 33*fontFactor));
    QFontMetrics fm = pixPaint.fontMetrics();
    int titleTextWidth = fm.width(titleText);
    if (titleTextWidth > 176) {
        fontFactor = fontFactor * 176 / titleTextWidth;
    }

    pixPaint.setFont(QFont(font, 33*fontFactor));
    fm = pixPaint.fontMetrics();
    titleTextWidth  = fm.width(titleText);
    pixPaint.drawText(pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight,paddingTop,titleText);

    pixPaint.setFont(QFont(font, 15*fontFactor));

    // if the version string is too long, reduce size
    fm = pixPaint.fontMetrics();
    int versionTextWidth  = fm.width(versionText);
    if(versionTextWidth > titleTextWidth+paddingRight-10) {
        pixPaint.setFont(QFont(font, 10*fontFactor));
        titleVersionVSpace -= 5;
    }
    pixPaint.drawText(pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight+2,paddingTop+titleVersionVSpace,versionText);

    // draw copyright stuff
    {
        pixPaint.setFont(QFont(font, 10*fontFactor));
        const int x = pixmap.width()/devicePixelRatio-titleTextWidth-paddingRight;
        const int y = paddingTop+titleCopyrightVSpace;
        QRect copyrightRect(x, y, pixmap.width() - x - paddingRight, pixmap.height() - y);
        pixPaint.drawText(copyrightRect, Qt::AlignLeft | Qt::AlignTop | Qt::TextWordWrap, copyrightText);
    }

    // draw additional text if special network
    if(!titleAddText.isEmpty()) {
        QFont boldFont = QFont(font, 10*fontFactor);
        boldFont.setWeight(QFont::Bold);
        pixPaint.setFont(boldFont);
        fm = pixPaint.fontMetrics();
        int titleAddTextWidth  = fm.width(titleAddText);
        pixPaint.drawText(pixmap.width()/devicePixelRatio-titleAddTextWidth-10,15,titleAddText);
    }

    pixPaint.end();
    curColor = darkModeEnabled ? QColor(214,232,220) : QColor(55,55,55);
}

void SplashScreen::updateDarkModeButton()
{
    if (darkModeButton == nullptr) {
        return;
    }
    const bool darkModeEnabled = PlatformStyle::isDarkModeEnabled();
    const QChar sunGlyph(0x2600);
    const QChar moonGlyph(0x263E);
    darkModeButton->setText(darkModeEnabled ? QString(sunGlyph) : QString(moonGlyph));
    darkModeButton->setToolTip(darkModeEnabled ? tr("Switch to light mode (right-click for green tint options)") : tr("Switch to dark mode (right-click for green tint options)"));
    darkModeButton->setFixedSize(24, 24);
    darkModeButton->move(width() - darkModeButton->width() - 10, height() - darkModeButton->height() - 10);
}

void SplashScreen::showDarkTintMenu(const QPoint& point)
{
    if (!darkModeTintMenu || !darkModeButton) {
        return;
    }
    const int currentTint = PlatformStyle::darkModeTint();
    Q_FOREACH (QAction* action, darkModeTintMenu->actions())
    {
        action->setChecked(action->data().toInt() == currentTint);
    }
    darkModeTintMenu->exec(darkModeButton->mapToGlobal(point));
}

void SplashScreen::onDarkTintSelected(QAction* action)
{
    if (!action) {
        return;
    }
    PlatformStyle::setDarkModeTint(action->data().toInt());
    buildPixmap(PlatformStyle::isDarkModeEnabled());
    updateDarkModeButton();
    update();
}

void SplashScreen::paintEvent(QPaintEvent *event)
{
    QPainter painter(this);
    painter.drawPixmap(0, 0, pixmap);
    QRect r = rect().adjusted(5, 5, -5, -5);
    painter.setPen(curColor);
    painter.drawText(r, curAlignment, curMessage);
}

void SplashScreen::closeEvent(QCloseEvent *event)
{
    StartShutdown(); // allows an "emergency" shutdown during startup
    event->ignore();
}
