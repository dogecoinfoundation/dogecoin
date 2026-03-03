// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_SPARKLINEWIDGET_H
#define BITCOIN_QT_SPARKLINEWIDGET_H

#include <cstdint>
#include <functional>

#include <QString>
#include <QVector>
#include <QWidget>

class QEvent;
class QMouseEvent;

class SparklineWidget : public QWidget
{
public:
    explicit SparklineWidget(QWidget* parent = nullptr);
    ~SparklineWidget() override;

    void setData(const QVector<double>& data);
    void setHoverTextProvider(const std::function<QString(int, double)>& provider);
    void setDoubleClickHandler(const std::function<void(int, double)>& handler);
    void clear();

protected:
    void paintEvent(QPaintEvent* event) override;
    void mouseMoveEvent(QMouseEvent* event) override;
    void mouseDoubleClickEvent(QMouseEvent* event) override;
    void leaveEvent(QEvent* event) override;

private:
    int sampleIndexForPos(const QPoint& pos) const;

    QVector<double> m_data;
    std::function<QString(int, double)> m_hoverTextProvider;
    std::function<void(int, double)> m_doubleClickHandler;
};

#endif // BITCOIN_QT_SPARKLINEWIDGET_H
