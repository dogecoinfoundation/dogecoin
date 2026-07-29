// Copyright (c) 2011-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SPLASHSCREEN_H
#define BITCOIN_QT_SPLASHSCREEN_H

#include <QSplashScreen>

class CWallet;
class NetworkStyle;
class QPushButton;
class QMenu;
class QAction;

/** Class for the splashscreen with information of the running client.
 *
 * @note this is intentionally not a QSplashScreen. Bitcoin Core initialization
 * can take a long time, and in that case a progress window that cannot be
 * moved around and minimized has turned out to be frustrating to the user.
 */
class SplashScreen : public QWidget
{
    Q_OBJECT

public:
    explicit SplashScreen(Qt::WindowFlags f, const NetworkStyle *networkStyle);
    ~SplashScreen();

protected:
    void paintEvent(QPaintEvent *event);
    void closeEvent(QCloseEvent *event);

public Q_SLOTS:
    /** Slot to call finish() method as it's not defined as slot */
    void slotFinish(QWidget *mainWin);

    /** Show message and progress */
    void showMessage(const QString &message, int alignment, const QColor &color);

    /** Toggle dark mode while splash screen is visible. */
    void toggleDarkMode();
    /** Show tint menu for splash dark mode button. */
    void showDarkTintMenu(const QPoint& point);
    /** Handle tint selection from splash dark mode button menu. */
    void onDarkTintSelected(QAction* action);

private:
    /** Connect core signals to splash screen */
    void subscribeToCoreSignals();
    /** Disconnect core signals to splash screen */
    void unsubscribeFromCoreSignals();
    /** Connect wallet signals to splash screen */
    void ConnectWallet(CWallet*);
    /** Rebuild splash pixmap with current dark/light mode setting. */
    void buildPixmap(bool darkModeEnabled);
    /** Update splash dark mode button label and placement. */
    void updateDarkModeButton();

    QPixmap pixmap;
    QString curMessage;
    QColor curColor;
    int curAlignment;
    const NetworkStyle* networkStyle;
    QPushButton* darkModeButton;
    QMenu* darkModeTintMenu;

    QList<CWallet*> connectedWallets;
};

#endif // BITCOIN_QT_SPLASHSCREEN_H
