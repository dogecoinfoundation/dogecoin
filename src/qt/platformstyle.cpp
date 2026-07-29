// Copyright (c) 2015-2016 The Bitcoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "platformstyle.h"

#include "guiconstants.h"

#include <QApplication>
#include <QColor>
#include <QCoreApplication>
#include <QEvent>
#include <QIcon>
#include <QImage>
#include <QObject>
#include <QPalette>
#include <QPixmap>
#include <QSettings>
#include <QStyle>
#include <QStyleFactory>
#include <QWidget>

static const struct {
    const char *platformId;
    /** Show images on push buttons */
    const bool imagesOnButtons;
    /** Colorize single-color icons */
    const bool colorizeIcons;
    /** Extra padding/spacing in transactionview */
    const bool useExtraSpacing;
} platform_styles[] = {
    {"macosx", false, false, true},
    {"windows", true, false, false},
    /* Other: linux, unix, ... */
    {"other", true, true, false}
};
static const unsigned platform_styles_count = sizeof(platform_styles)/sizeof(*platform_styles);
static const char* DARK_MODE_SETTING = "fUseDarkMode";
static const char* DARK_MODE_TINT_SETTING = "nDarkModeTint";

namespace {
struct DarkTintColors {
    const char* name;
    QColor windowColor;
    QColor baseColor;
    QColor alternateBaseColor;
    QColor buttonColor;
    QColor highlightColor;
    QColor highlightedTextColor;
    QColor borderColor;
    QColor darkColor;
    QColor shadowColor;
    QColor lightColor;
};

const DarkTintColors DARK_TINTS[] = {
    {"Forest", QColor(26, 32, 28), QColor(18, 24, 20), QColor(32, 40, 35), QColor(35, 44, 38), QColor(74, 163, 111), QColor(10, 24, 16), QColor(46, 58, 51), QColor(16, 20, 18), QColor(8, 10, 9), QColor(45, 56, 49)},
    {"Pine", QColor(22, 31, 27), QColor(15, 23, 19), QColor(28, 40, 33), QColor(31, 43, 36), QColor(59, 153, 111), QColor(9, 22, 16), QColor(40, 56, 47), QColor(13, 19, 16), QColor(7, 10, 8), QColor(40, 54, 46)},
    {"Moss", QColor(29, 34, 26), QColor(21, 25, 19), QColor(36, 42, 31), QColor(39, 47, 35), QColor(109, 162, 89), QColor(13, 24, 11), QColor(50, 59, 44), QColor(17, 20, 15), QColor(9, 10, 8), QColor(49, 58, 43)},
    {"Mint", QColor(22, 33, 30), QColor(15, 24, 21), QColor(29, 42, 38), QColor(31, 45, 40), QColor(72, 177, 140), QColor(8, 25, 19), QColor(41, 60, 53), QColor(13, 20, 18), QColor(7, 10, 9), QColor(41, 58, 51)}
};

int ClampDarkTintIndex(int tint)
{
    const int tintCount = static_cast<int>(sizeof(DARK_TINTS) / sizeof(*DARK_TINTS));
    if (tint < 0 || tint >= tintCount) {
        return 0;
    }
    return tint;
}

int CurrentDarkTintFromSettings()
{
    QSettings settings(QAPP_ORG_NAME, QAPP_APP_NAME_DEFAULT);
    if (!settings.contains(DARK_MODE_TINT_SETTING)) {
        settings.setValue(DARK_MODE_TINT_SETTING, 0);
    }
    return ClampDarkTintIndex(settings.value(DARK_MODE_TINT_SETTING, 0).toInt());
}

const DarkTintColors& ActiveDarkTintColors()
{
    return DARK_TINTS[CurrentDarkTintFromSettings()];
}

}

namespace {
/* Local functions for colorizing single-color images */

void MakeSingleColorImage(QImage& img, const QColor& colorbase)
{
    img = img.convertToFormat(QImage::Format_ARGB32);
    for (int x = img.width(); x--; )
    {
        for (int y = img.height(); y--; )
        {
            const QRgb rgb = img.pixel(x, y);
            img.setPixel(x, y, qRgba(colorbase.red(), colorbase.green(), colorbase.blue(), qAlpha(rgb)));
        }
    }
}

QIcon ColorizeIcon(const QIcon& ico, const QColor& colorbase)
{
    QIcon new_ico;
    QSize sz;
    Q_FOREACH(sz, ico.availableSizes())
    {
        QImage img(ico.pixmap(sz).toImage());
        MakeSingleColorImage(img, colorbase);
        new_ico.addPixmap(QPixmap::fromImage(img));
    }
    return new_ico;
}

QImage ColorizeImage(const QString& filename, const QColor& colorbase)
{
    QImage img(filename);
    MakeSingleColorImage(img, colorbase);
    return img;
}

QIcon ColorizeIcon(const QString& filename, const QColor& colorbase)
{
    return QIcon(QPixmap::fromImage(ColorizeImage(filename, colorbase)));
}

}


PlatformStyle::PlatformStyle(const QString &_name, bool _imagesOnButtons, bool _colorizeIcons, bool _useExtraSpacing):
    name(_name),
    imagesOnButtons(_imagesOnButtons),
    colorizeIcons(_colorizeIcons),
    useExtraSpacing(_useExtraSpacing),
    singleColor(0,0,0),
    textColor(0,0,0)
{
    // Determine icon highlighting color
    if (colorizeIcons) {
        const QColor colorHighlightBg(QApplication::palette().color(QPalette::Highlight));
        const QColor colorHighlightFg(QApplication::palette().color(QPalette::HighlightedText));
        const QColor colorText(QApplication::palette().color(QPalette::WindowText));
        const int colorTextLightness = colorText.lightness();
        QColor colorbase;
        if (abs(colorHighlightBg.lightness() - colorTextLightness) < abs(colorHighlightFg.lightness() - colorTextLightness))
            colorbase = colorHighlightBg;
        else
            colorbase = colorHighlightFg;
        singleColor = colorbase;
    }
    // Determine text color
    textColor = QColor(QApplication::palette().color(QPalette::WindowText));
}

QImage PlatformStyle::SingleColorImage(const QString& filename) const
{
    if (!colorizeIcons)
        return QImage(filename);
    return ColorizeImage(filename, SingleColor());
}

QIcon PlatformStyle::SingleColorIcon(const QString& filename) const
{
    if (!colorizeIcons)
        return QIcon(filename);
    return ColorizeIcon(filename, SingleColor());
}

QIcon PlatformStyle::SingleColorIcon(const QIcon& icon) const
{
    if (!colorizeIcons)
        return icon;
    return ColorizeIcon(icon, SingleColor());
}

QIcon PlatformStyle::TextColorIcon(const QString& filename) const
{
    return ColorizeIcon(filename, TextColor());
}

QIcon PlatformStyle::TextColorIcon(const QIcon& icon) const
{
    return ColorizeIcon(icon, TextColor());
}

const PlatformStyle *PlatformStyle::instantiate(const QString &platformId)
{
    for (unsigned x=0; x<platform_styles_count; ++x)
    {
        if (platformId == platform_styles[x].platformId)
        {
            return new PlatformStyle(
                    platform_styles[x].platformId,
                    platform_styles[x].imagesOnButtons,
                    platform_styles[x].colorizeIcons,
                    platform_styles[x].useExtraSpacing);
        }
    }
    return 0;
}

QPalette PlatformStyle::createDarkModePalette()
{
    QPalette darkPalette;

    const DarkTintColors& tint = ActiveDarkTintColors();
    const QColor textColor(214, 232, 220);
    const QColor mutedTextColor(137, 161, 146);

    darkPalette.setColor(QPalette::Window, tint.windowColor);
    darkPalette.setColor(QPalette::WindowText, textColor);
    darkPalette.setColor(QPalette::Base, tint.baseColor);
    darkPalette.setColor(QPalette::AlternateBase, tint.alternateBaseColor);
    darkPalette.setColor(QPalette::ToolTipBase, tint.alternateBaseColor);
    darkPalette.setColor(QPalette::ToolTipText, textColor);
    darkPalette.setColor(QPalette::Text, textColor);
    darkPalette.setColor(QPalette::Button, tint.buttonColor);
    darkPalette.setColor(QPalette::ButtonText, textColor);
    darkPalette.setColor(QPalette::Mid, tint.borderColor);
    darkPalette.setColor(QPalette::Dark, tint.darkColor);
    darkPalette.setColor(QPalette::Shadow, tint.shadowColor);
    darkPalette.setColor(QPalette::Light, tint.lightColor);
    darkPalette.setColor(QPalette::Link, tint.highlightColor);
    darkPalette.setColor(QPalette::Highlight, tint.highlightColor);
    darkPalette.setColor(QPalette::HighlightedText, tint.highlightedTextColor);
    darkPalette.setColor(QPalette::BrightText, QColor(255, 128, 128));
    darkPalette.setColor(QPalette::Disabled, QPalette::Text, mutedTextColor);
    darkPalette.setColor(QPalette::Disabled, QPalette::ButtonText, mutedTextColor);
    darkPalette.setColor(QPalette::Disabled, QPalette::WindowText, mutedTextColor);

    return darkPalette;
}

bool PlatformStyle::isDarkModeEnabled()
{
    QSettings settings(QAPP_ORG_NAME, QAPP_APP_NAME_DEFAULT);
    if (!settings.contains(DARK_MODE_SETTING)) {
        settings.setValue(DARK_MODE_SETTING, true);
    }
    return settings.value(DARK_MODE_SETTING, true).toBool();
}

int PlatformStyle::darkModeTint()
{
    return CurrentDarkTintFromSettings();
}

QString PlatformStyle::darkModeTintName(int tint)
{
    return QString::fromLatin1(DARK_TINTS[ClampDarkTintIndex(tint)].name);
}

int PlatformStyle::darkModeTintCount()
{
    return static_cast<int>(sizeof(DARK_TINTS) / sizeof(*DARK_TINTS));
}

void PlatformStyle::setDarkModeTint(int tint)
{
    QSettings settings(QAPP_ORG_NAME, QAPP_APP_NAME_DEFAULT);
    settings.setValue(DARK_MODE_TINT_SETTING, ClampDarkTintIndex(tint));
    if (isDarkModeEnabled()) {
        applyTheme(true);
    }
}

void PlatformStyle::applyTheme(bool darkModeEnabled)
{
    if (!qobject_cast<QApplication*>(QCoreApplication::instance())) {
        return;
    }

    QStyle* fusionStyle = QStyleFactory::create("Fusion");
    if (fusionStyle) {
        QApplication::setStyle(fusionStyle);
    }

    if (darkModeEnabled) {
        QApplication::setPalette(createDarkModePalette());
        const QString borderColor = ActiveDarkTintColors().borderColor.name();
        qApp->setStyleSheet(
            QString("QDialog, QMessageBox { border: 1px solid %1; }"
                    "QMenu { border: 1px solid %1; }").arg(borderColor));
    } else {
        const QStyle* currentStyle = QApplication::style();
        QApplication::setPalette(currentStyle ? currentStyle->standardPalette() : QPalette());
        qApp->setStyleSheet("");
    }
}

void PlatformStyle::setDarkModeEnabled(bool enabled)
{
    QSettings settings(QAPP_ORG_NAME, QAPP_APP_NAME_DEFAULT);
    settings.setValue(DARK_MODE_SETTING, enabled);
    applyTheme(enabled);
}
