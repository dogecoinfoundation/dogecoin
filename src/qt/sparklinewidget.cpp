// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "sparklinewidget.h"

#include <QEvent>
#include <QMouseEvent>
#include <QPainter>
#include <QPaintEvent>
#include <QToolTip>
#include <QtMath>

#include <algorithm>

SparklineWidget::SparklineWidget(QWidget* parent)
    : QWidget(parent)
{
    setSizePolicy(QSizePolicy::Expanding, QSizePolicy::Expanding);
    setMinimumHeight(34);
    setMouseTracking(true);
}

SparklineWidget::~SparklineWidget() = default;

void SparklineWidget::setData(const QVector<double>& data)
{
    m_data = data;
    update();
}

void SparklineWidget::setHoverTextProvider(const std::function<QString(int, double)>& provider)
{
    m_hoverTextProvider = provider;
}

void SparklineWidget::setDoubleClickHandler(const std::function<void(int, double)>& handler)
{
    m_doubleClickHandler = handler;
}

void SparklineWidget::clear()
{
    m_data.clear();
    update();
}

void SparklineWidget::paintEvent(QPaintEvent* /*event*/)
{
    QPainter p(this);
    p.setRenderHint(QPainter::Antialiasing, true);

    // Background (use widget palette, do not hardcode colors)
    p.fillRect(rect(), palette().brush(QPalette::Base));

    if (m_data.isEmpty() || width() <= 2 || height() <= 2) {
        return;
    }

    // Compute min/max for normalization
    double minv = m_data[0];
    double maxv = m_data[0];
    for (double v : m_data) {
        if (v < minv) minv = v;
        if (v > maxv) maxv = v;
    }
    const double range = (maxv - minv);

    const int w = width();
    const int h = height();

    // Padding
    const int pad = 2;
    const QRectF r(pad, pad, w - 2.0 * pad, h - 2.0 * pad);

    // Build polyline points
    const int n = m_data.size();
    QPolygonF poly;
    poly.reserve(n);

    for (int i = 0; i < n; ++i) {
        const double x = r.left() + (n == 1 ? 0.0 : (r.width() * i / double(n - 1)));

        double norm = 0.5;
        if (range > 0.0) {
            norm = (m_data[i] - minv) / range; // 0..1
        }
        // invert Y so higher values go up
        const double y = r.bottom() - (r.height() * norm);
        poly << QPointF(x, y);
    }

    // Draw line with accent color for better visibility on dashboard
    const QColor lineColor = palette().color(QPalette::Highlight);
    QPen pen(lineColor);
    pen.setWidthF(1.2);
    p.setPen(pen);
    p.drawPolyline(poly);

    // Optional: a subtle baseline midline when flat (range == 0)
    if (range == 0.0) {
        QPen mid(palette().color(QPalette::Mid));
        mid.setWidthF(1.0);
        p.setPen(mid);
        p.drawLine(QPointF(r.left(), r.center().y()), QPointF(r.right(), r.center().y()));
    }
}

int SparklineWidget::sampleIndexForPos(const QPoint& pos) const
{
    static const int kMinSampleWidth = 4;
    static const int kSamplePad = 2;
    const int count = m_data.size();
    if (count <= 1 || width() <= kMinSampleWidth) {
        return 0;
    }
    const double left = kSamplePad;
    const double right = width() - kSamplePad;
    const double clampedX = std::max(left, std::min<double>(pos.x(), right));
    const double ratio = (clampedX - left) / std::max(1.0, right - left);
    int index = qRound(ratio * (count - 1));
    index = std::max(0, std::min(index, count - 1));
    return index;
}

void SparklineWidget::mouseMoveEvent(QMouseEvent* event)
{
    if (m_data.isEmpty()) {
        QWidget::mouseMoveEvent(event);
        return;
    }

    if (m_hoverTextProvider) {
        const int index = sampleIndexForPos(event->pos());
        const QString tooltip = m_hoverTextProvider(index, m_data[index]);
        if (!tooltip.isEmpty()) {
            QToolTip::showText(event->globalPos(), tooltip, this);
        }
    }

    QWidget::mouseMoveEvent(event);
}

void SparklineWidget::mouseDoubleClickEvent(QMouseEvent* event)
{
    if (!m_data.isEmpty() && m_doubleClickHandler) {
        const int index = sampleIndexForPos(event->pos());
        m_doubleClickHandler(index, m_data[index]);
    }
    QWidget::mouseDoubleClickEvent(event);
}

void SparklineWidget::leaveEvent(QEvent* event)
{
    QToolTip::hideText();
    QWidget::leaveEvent(event);
}
