// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef BITCOIN_QT_DASHB0RDPAGE_H
#define BITCOIN_QT_DASHB0RDPAGE_H

#include <cstdint>

#include <QHash>
#include <QString>
#include <QPoint>
#include <QVector>
#include <QWidget>

class ClientModel;
class PlatformStyle;
class QGridLayout;
class QLabel;
class QResizeEvent;
class QShowEvent;
class QHideEvent;
class QSpinBox;
class QTimer;
class SparklineWidget;
class WalletModel;

class Dashb0rdPage : public QWidget
{
    Q_OBJECT

public:
    explicit Dashb0rdPage(const PlatformStyle* platformStyle, QWidget* parent = nullptr);
    ~Dashb0rdPage() override;

    void setClientModel(ClientModel* model);
    void setWalletModel(WalletModel* model);

protected:
    bool eventFilter(QObject* watched, QEvent* event) override;
    void resizeEvent(QResizeEvent* event) override;
    void showEvent(QShowEvent* event) override;
    void hideEvent(QHideEvent* event) override;

private Q_SLOTS:
    void pollStats();
    void setStatsWindow(int blocks);

private:
    void pushSample(QVector<double>& series, SparklineWidget* spark, double value, const QString& txid = QString(), const QString& blockHash = QString());
    QWidget* createMetricBox(const QString& label, QLabel*& valueLabel, SparklineWidget*& spark);
    void relayoutMetricBoxes();
    QString formatSparklineHoverText(SparklineWidget* spark, int index, double value) const;
    void showSparklineDetailsDialog(SparklineWidget* spark, int index, double value);
    QString scriptTypeFilterForSpark(SparklineWidget* spark) const;

    ClientModel* m_clientModel;
    WalletModel* m_walletModel;
    const PlatformStyle* m_platformStyle;

    QTimer* m_pollTimer;
    QLabel* m_lastUpdated;
    QWidget* m_metricsContainer;
    QGridLayout* m_metricGrid;
    QVector<QWidget*> m_metricBoxes;
    QPoint m_dragStartPos;
    QWidget* m_dragSourceBox;
    int64_t m_prevMempoolTxCount;
    int m_statsWindowBlocks;
    QSpinBox* m_statsWindowSpinBox;

    // Chain Tip Metrics
    QLabel* m_chainTipHeightValue;
    QLabel* m_chainTipDifficultyValue;
    QLabel* m_chainTipTimeValue;
    QLabel* m_chainTipBitsValue;
    SparklineWidget* m_chainTipHeightSpark;
    SparklineWidget* m_chainTipDifficultySpark;
    SparklineWidget* m_chainTipTimeSpark;
    SparklineWidget* m_chainTipBitsSpark;
    QVector<double> m_chainTipHeightSeries;
    QVector<double> m_chainTipDifficultySeries;
    QVector<double> m_chainTipTimeSeries;
    QVector<double> m_chainTipBitsSeries;

    // Mempool Metrics
    QLabel* m_mempoolTxCountValue;
    QLabel* m_mempoolTotalBytesValue;
    QLabel* m_mempoolP2pkhValue;
    QLabel* m_mempoolP2shValue;
    QLabel* m_mempoolMultisigValue;
    QLabel* m_mempoolOpReturnValue;
    QLabel* m_mempoolNonstandardValue;
    QLabel* m_mempoolOutputCountValue;
    SparklineWidget* m_mempoolTxCountSpark;
    SparklineWidget* m_mempoolTotalBytesSpark;
    SparklineWidget* m_mempoolP2pkhSpark;
    SparklineWidget* m_mempoolP2shSpark;
    SparklineWidget* m_mempoolMultisigSpark;
    SparklineWidget* m_mempoolOpReturnSpark;
    SparklineWidget* m_mempoolNonstandardSpark;
    SparklineWidget* m_mempoolOutputCountSpark;
    QVector<double> m_mempoolTxCountSeries;
    QVector<double> m_mempoolTotalBytesSeries;
    QVector<double> m_mempoolP2pkhSeries;
    QVector<double> m_mempoolP2shSeries;
    QVector<double> m_mempoolMultisigSeries;
    QVector<double> m_mempoolOpReturnSeries;
    QVector<double> m_mempoolNonstandardSeries;
    QVector<double> m_mempoolOutputCountSeries;

    // Rolling Stats Metrics
    QLabel* m_statsTransactionsValue;
    QLabel* m_statsTpsValue;
    QLabel* m_statsVolumeValue;
    QLabel* m_statsOutputsValue;
    QLabel* m_statsBytesValue;
    QLabel* m_statsMedianFeeValue;
    QLabel* m_statsAvgFeeValue;
    SparklineWidget* m_statsTransactionsSpark;
    SparklineWidget* m_statsTpsSpark;
    SparklineWidget* m_statsVolumeSpark;
    SparklineWidget* m_statsOutputsSpark;
    SparklineWidget* m_statsBytesSpark;
    SparklineWidget* m_statsMedianFeeSpark;
    SparklineWidget* m_statsAvgFeeSpark;
    QVector<double> m_statsTransactionsSeries;
    QVector<double> m_statsTpsSeries;
    QVector<double> m_statsVolumeSeries;
    QVector<double> m_statsOutputsSeries;
    QVector<double> m_statsBytesSeries;
    QVector<double> m_statsMedianFeeSeries;
    QVector<double> m_statsAvgFeeSeries;

    // Uptime
    QLabel* m_uptimeValue;
    SparklineWidget* m_uptimeSpark;
    QVector<double> m_uptimeSeries;

    struct PointContext
    {
        qint64 timestamp;
        QString txid;
        QString blockHash;
    };
    QHash<SparklineWidget*, QVector<PointContext> > m_pointContexts;
};

#endif // BITCOIN_QT_DASHB0RDPAGE_H
