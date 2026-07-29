// Copyright (c) 2015 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_PLATFORMSTYLE_H
#define BITCOIN_QT_PLATFORMSTYLE_H

#include <QIcon>
#include <QPalette>
#include <QPixmap>
#include <QString>

/* Coin network-specific GUI style information */
class PlatformStyle
{
public:
    /** Get style associated with provided platform name, or 0 if not known */
    static const PlatformStyle *instantiate(const QString &platformId);

    /** Return whether dark mode is currently enabled in GUI settings. */
    static bool isDarkModeEnabled();

    /** Persist dark mode preference and apply it to the running application. */
    static void setDarkModeEnabled(bool enabled);

    /** Return current dark-mode tint index. */
    static int darkModeTint();

    /** Return display label for a dark-mode tint index. */
    static QString darkModeTintName(int tint);

    /** Return total number of available dark-mode tints. */
    static int darkModeTintCount();

    /** Persist dark-mode tint and apply immediately when dark mode is enabled. */
    static void setDarkModeTint(int tint);

    /** Apply either dark or light theme to the running application. */
    static void applyTheme(bool darkModeEnabled);

    /** Create the default dark mode palette used by the Qt application. */
    static QPalette createDarkModePalette();

    const QString &getName() const { return name; }

    bool getImagesOnButtons() const { return imagesOnButtons; }
    bool getUseExtraSpacing() const { return useExtraSpacing; }

    QColor TextColor() const { return textColor; }
    QColor SingleColor() const { return singleColor; }

    /** Colorize an image (given filename) with the icon color */
    QImage SingleColorImage(const QString& filename) const;

    /** Colorize an icon (given filename) with the icon color */
    QIcon SingleColorIcon(const QString& filename) const;

    /** Colorize an icon (given object) with the icon color */
    QIcon SingleColorIcon(const QIcon& icon) const;

    /** Colorize an icon (given filename) with the text color */
    QIcon TextColorIcon(const QString& filename) const;

    /** Colorize an icon (given object) with the text color */
    QIcon TextColorIcon(const QIcon& icon) const;

private:
    PlatformStyle(const QString &name, bool imagesOnButtons, bool colorizeIcons, bool useExtraSpacing);

    QString name;
    bool imagesOnButtons;
    bool colorizeIcons;
    bool useExtraSpacing;
    QColor singleColor;
    QColor textColor;
    /* ... more to come later */
};

#endif // BITCOIN_QT_PLATFORMSTYLE_H
