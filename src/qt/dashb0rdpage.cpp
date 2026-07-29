// Copyright (c) 2011-2016 The Bitcoin Core developers
// Copyright (c) 2021-2026 The Dogecoin Core developers
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#if defined(HAVE_CONFIG_H)
#include "config/bitcoin-config.h"
#endif

#include "dashb0rdpage.h"

#include "clientmodel.h"
#include "guiutil.h"
#include "platformstyle.h"
#include "sparklinewidget.h"

#include "rpc/client.h"
#include "rpc/server.h"
#include "util.h"

#include <univalue.h>

#include <QDateTime>
#include <QDialog>
#include <QDialogButtonBox>
#include <QDrag>
#include <QDragEnterEvent>
#include <QDropEvent>
#include <QFont>
#include <QFrame>
#include <QGridLayout>
#include <QHBoxLayout>
#include <QLabel>
#include <QMenu>
#include <QMimeData>
#include <QMouseEvent>
#include <QHelpEvent>
#include <QHeaderView>
#include <QHideEvent>
#include <QPalette>
#include <QPainter>
#include <QPixmap>
#include <QApplication>
#include <QResizeEvent>
#include <QScrollArea>
#include <QShowEvent>
#include <QSpinBox>
#include <QStringList>
#include <QTimer>
#include <QTreeWidget>
#include <QToolTip>
#include <QVBoxLayout>

#include <algorithm>
#include <cctype>
#include <limits>

namespace {
static const int kPollIntervalMs = 1000;
static const int kMaxSparkPoints = 120;
static const int kMetricGridColumns = 4;
// Slightly wider visual separation between metric tiles.
static const int kMetricGridSpacing = 20;
static const int kDefaultStatsWindowBlocks = 100;
static const char* kMetricMimeType = "application/x-dashb0rd-metric-index";
static const char* kMetricDefinitionProperty = "metricDefinition";
static const int kMetricBoxMinWidth = 280;
static const int kMetricBoxWidthChars = 38;
static const int kSparklineMinHeight = 40;

static QLabel* MakeValueLabel()
{
    QLabel* l = new QLabel(QObject::tr("n/a"));
    l->setAlignment(Qt::AlignCenter);
    l->setTextInteractionFlags(Qt::TextSelectableByMouse);
    QFont f = l->font();
    f.setPointSize(f.pointSize() + 2);
    l->setFont(f);
    return l;
}

static int64_t GetInt64(const UniValue& obj, const char* key)
{
    // Missing/non-numeric fields are treated as 0 to keep UI refresh resilient.
    const UniValue& v = find_value(obj, key);
    return v.isNum() ? v.get_int64() : 0;
}

static double GetDouble(const UniValue& obj, const char* key)
{
    // Missing/non-numeric fields are treated as 0.0 to avoid UI exceptions.
    const UniValue& v = find_value(obj, key);
    return v.isNum() ? v.get_real() : 0.0;
}

static QString GetString(const UniValue& obj, const char* key)
{
    // Missing/non-string fields become empty text in the UI.
    const UniValue& v = find_value(obj, key);
    return v.isStr() ? QString::fromStdString(v.get_str()) : QString();
}

static QString TooltipValueKindForLabel(const QString& label)
{
    if (label == QObject::tr("Chain Tip Time")) return "epoch_time";
    if (label == QObject::tr("Bits (hex)")) return "bits_hex";
    if (label == QObject::tr("Mempool Bytes") || label == QObject::tr("Bytes")) return "bytes";
    if (label == QObject::tr("Volume (DOGE)") || label == QObject::tr("Median Fee/Block") || label == QObject::tr("Avg Fee/Block")) return "doge";
    if (label == QObject::tr("TPS")) return "tps";
    if (label == QObject::tr("Uptime")) return "duration_sec";
    if (label == QObject::tr("Difficulty")) return "difficulty";
    return "count";
}

static QString MetricDefinitionForLabel(const QString& label)
{
    if (label == QObject::tr("Block Height")) return QObject::tr("Current blockchain height.");
    if (label == QObject::tr("Difficulty")) return QObject::tr("Network mining difficulty.");
    if (label == QObject::tr("Chain Tip Time")) return QObject::tr("Timestamp of the most recent block (ISO-8601).");
    if (label == QObject::tr("Bits (hex)")) return QObject::tr("Compact difficulty target in hexadecimal format.");
    if (label == QObject::tr("Mempool TX")) return QObject::tr("Number of transactions in the mempool.");
    if (label == QObject::tr("Mempool Bytes")) return QObject::tr("Total mempool memory usage in bytes.");
    if (label == QObject::tr("P2PKH Count")) return QObject::tr("Count of Pay-to-PubKey-Hash outputs in mempool.");
    if (label == QObject::tr("P2SH Count")) return QObject::tr("Count of Pay-to-Script-Hash outputs in mempool.");
    if (label == QObject::tr("Multisig Count")) return QObject::tr("Count of multisig outputs in mempool.");
    if (label == QObject::tr("OP_RETURN Count")) return QObject::tr("Count of OP_RETURN outputs in mempool.");
    if (label == QObject::tr("Nonstandard Count")) return QObject::tr("Count of nonstandard outputs in mempool.");
    if (label == QObject::tr("Total Outputs")) return QObject::tr("Total outputs across all mempool transactions.");
    if (label == QObject::tr("Transactions")) return QObject::tr("Total transactions across analyzed blocks.");
    if (label == QObject::tr("TPS")) return QObject::tr("Estimated transactions per second over analyzed blocks.");
    if (label == QObject::tr("Volume (DOGE)")) return QObject::tr("Sum of output values in analyzed blocks.");
    if (label == QObject::tr("Outputs")) return QObject::tr("Total transaction outputs in analyzed blocks.");
    if (label == QObject::tr("Bytes")) return QObject::tr("Total serialized block bytes in analyzed window.");
    if (label == QObject::tr("Median Fee/Block")) return QObject::tr("Median miner fee per block in analyzed window.");
    if (label == QObject::tr("Avg Fee/Block")) return QObject::tr("Average miner fee per block in analyzed window.");
    if (label == QObject::tr("Uptime")) return QObject::tr("Node uptime in seconds since startup.");
    return QString();
}

static int MetricBoxMaxWidthPx(const QWidget* widget)
{
    if (!widget) return kMetricBoxMinWidth;
    const int scaledWidth = widget->fontMetrics().averageCharWidth() * kMetricBoxWidthChars;
    return std::max(kMetricBoxMinWidth, scaledWidth);
}

static QString FormatValueForKind(const QString& kind, double value)
{
    if (kind == "count") return QString::number(static_cast<qint64>(value));
    if (kind == "bytes") return QString("%1 B").arg(QString::number(static_cast<qint64>(value)));
    if (kind == "doge") return QString("%1 DOGE").arg(QString::number(value, 'f', 8));
    if (kind == "tps") return QString("%1 tx/s").arg(QString::number(value, 'f', 3));
    if (kind == "epoch_time") {
        const qint64 epoch = value < 0 ? 0 : static_cast<qint64>(value);
        return QDateTime::fromTime_t(static_cast<uint>(epoch)).toString(Qt::ISODate);
    }
    if (kind == "bits_hex") return QString("0x%1").arg(static_cast<qulonglong>(value), 0, 16);
    if (kind == "duration_sec") return QString("%1 s").arg(QString::number(static_cast<qint64>(value)));
    if (kind == "difficulty") return QString::number(value, 'f', 2);
    return QString::number(value, 'g', 12);
}

static QDateTime DateTimeFromEpochCompat(qint64 secs)
{
    if (secs < 0) secs = 0;
    if (secs > std::numeric_limits<uint>::max()) secs = std::numeric_limits<uint>::max();
    return QDateTime::fromTime_t(static_cast<uint>(secs));
}

static bool DecodeContextToUniValue(const QString& txid, const QString& blockHash, UniValue& out, QString& errorMessage)
{
    try {
        JSONRPCRequest req;
        req.fHelp = false;
        req.params = UniValue(UniValue::VARR);

        if (!txid.isEmpty() && !blockHash.isEmpty()) {
            req.strMethod = "getblock";
            req.params.push_back(UniValue(blockHash.toStdString()));
            req.params.push_back(UniValue(2));
            const UniValue blockResult = tableRPC.execute(req);
            const UniValue& txList = find_value(blockResult, "tx");
            if (!txList.isNull() && txList.isArray()) {
                const std::vector<UniValue>& txValues = txList.getValues();
                const std::string wantedTxid = txid.toStdString();
                for (const UniValue& txObj : txValues) {
                    if (!txObj.isObject()) continue;
                    const UniValue& txidValue = find_value(txObj, "txid");
                    if (txidValue.isStr() && txidValue.get_str() == wantedTxid) {
                        out = txObj;
                        return true;
                    }
                }
            }
            errorMessage = QObject::tr("Transaction %1 not found in block %2.").arg(txid).arg(blockHash);
            return false;
        } else if (!txid.isEmpty()) {
            req.strMethod = "getrawtransaction";
            req.params.push_back(UniValue(txid.toStdString()));
            req.params.push_back(UniValue(true));
        } else if (!blockHash.isEmpty()) {
            req.strMethod = "getblock";
            req.params.push_back(UniValue(blockHash.toStdString()));
            req.params.push_back(UniValue(true));
        } else {
            errorMessage = QObject::tr("No transaction or block context available for this point.");
            return false;
        }
        out = tableRPC.execute(req);
        return true;
    } catch (const std::exception& e) {
        errorMessage = QObject::tr("Unable to decode context: %1").arg(QString::fromStdString(e.what()));
    } catch (...) {
        errorMessage = QObject::tr("Unable to decode context.");
    }
    return false;
}

static void AddUniValueNode(QTreeWidgetItem* parent, const QString& key, const UniValue& value)
{
    QTreeWidgetItem* item = new QTreeWidgetItem(parent);
    item->setText(0, key);
    if (value.isObject()) {
        item->setText(1, "{...}");
        const std::vector<std::string>& keys = value.getKeys();
        const std::vector<UniValue>& values = value.getValues();
        for (size_t i = 0; i < keys.size() && i < values.size(); ++i) {
            AddUniValueNode(item, QString::fromStdString(keys[i]), values[i]);
        }
        return;
    }
    if (value.isArray()) {
        item->setText(1, QString("[%1]").arg(value.size()));
        const std::vector<UniValue>& values = value.getValues();
        for (size_t i = 0; i < values.size(); ++i) {
            AddUniValueNode(item, QString("[%1]").arg(i), values[i]);
        }
        return;
    }
    item->setText(1, QString::fromStdString(value.write()));
}

static void PopulateDecodedTree(QTreeWidget* tree, const bool decodedOk, const UniValue& decoded, const QString& decodeError)
{
    tree->clear();
    if (decodedOk) {
        if (decoded.isObject()) {
            const std::vector<std::string>& keys = decoded.getKeys();
            const std::vector<UniValue>& values = decoded.getValues();
            for (size_t i = 0; i < keys.size() && i < values.size(); ++i) {
                AddUniValueNode(tree->invisibleRootItem(), QString::fromStdString(keys[i]), values[i]);
            }
        } else {
            AddUniValueNode(tree->invisibleRootItem(), QObject::tr("context"), decoded);
        }
    } else {
        QTreeWidgetItem* err = new QTreeWidgetItem(tree->invisibleRootItem());
        err->setText(0, QObject::tr("error"));
        err->setText(1, decodeError);
    }
    tree->expandToDepth(1);
}

static QString UnquoteJsonString(const QString& valueIn)
{
    QString value = valueIn.trimmed();
    if (value.size() >= 2 && value.startsWith('"') && value.endsWith('"')) {
        value = value.mid(1, value.size() - 2);
    }
    return value;
}

static QTreeWidgetItem* FindChildByKey(QTreeWidgetItem* parent, const QString& key)
{
    if (!parent) return nullptr;
    for (int i = 0; i < parent->childCount(); ++i) {
        QTreeWidgetItem* child = parent->child(i);
        if (child && child->text(0) == key) return child;
    }
    return nullptr;
}

static bool HighlightScriptAsmForType(QTreeWidget* tree, const QString& scriptType)
{
    if (!tree || scriptType.isEmpty()) return false;

    QList<QTreeWidgetItem*> nodeStack;
    for (int i = 0; i < tree->topLevelItemCount(); ++i) {
        nodeStack.push_back(tree->topLevelItem(i));
    }

    while (!nodeStack.isEmpty()) {
        QTreeWidgetItem* scriptPubKeyNode = nodeStack.takeLast();
        if (!scriptPubKeyNode) continue;
        for (int i = 0; i < scriptPubKeyNode->childCount(); ++i) {
            nodeStack.push_back(scriptPubKeyNode->child(i));
        }
        if (scriptPubKeyNode->text(0) != "scriptPubKey") continue;

        QTreeWidgetItem* typeNode = FindChildByKey(scriptPubKeyNode, "type");
        if (!typeNode) continue;
        const QString typeValue = UnquoteJsonString(typeNode->text(1));
        if (typeValue != scriptType) continue;

        QTreeWidgetItem* asmNode = FindChildByKey(scriptPubKeyNode, "asm");
        if (!asmNode) continue;

        for (QTreeWidgetItem* p = asmNode; p; p = p->parent()) {
            p->setExpanded(true);
        }
        tree->setCurrentItem(asmNode);
        asmNode->setSelected(true);
        tree->scrollToItem(asmNode);
        return true;
    }
    return false;
}

static bool IsLikelyTxid(QString value)
{
    value = value.trimmed();
    if (value.size() >= 2 && value.startsWith('"') && value.endsWith('"')) {
        value = value.mid(1, value.size() - 2);
    }
    if (value.size() != 64) return false;
    for (int i = 0; i < value.size(); ++i) {
        if (!std::isxdigit(static_cast<unsigned char>(value.at(i).toLatin1()))) return false;
    }
    return true;
}

} // namespace

Dashb0rdPage::Dashb0rdPage(const PlatformStyle* platformStyle, QWidget* parent)
    : QWidget(parent)
    , m_clientModel(nullptr)
    , m_walletModel(nullptr)
    , m_platformStyle(platformStyle)
    , m_pollTimer(new QTimer(this))
    , m_lastUpdated(nullptr)
    , m_metricsContainer(nullptr)
    , m_metricGrid(nullptr)
    , m_dragSourceBox(nullptr)
    , m_prevMempoolTxCount(-1)
    , m_statsWindowBlocks(kDefaultStatsWindowBlocks)
    , m_statsWindowSpinBox(nullptr)
    , m_chainTipHeightValue(nullptr)
    , m_chainTipDifficultyValue(nullptr)
    , m_chainTipTimeValue(nullptr)
    , m_chainTipBitsValue(nullptr)
    , m_chainTipHeightSpark(nullptr)
    , m_chainTipDifficultySpark(nullptr)
    , m_chainTipTimeSpark(nullptr)
    , m_chainTipBitsSpark(nullptr)
    , m_mempoolTxCountValue(nullptr)
    , m_mempoolTotalBytesValue(nullptr)
    , m_mempoolP2pkhValue(nullptr)
    , m_mempoolP2shValue(nullptr)
    , m_mempoolMultisigValue(nullptr)
    , m_mempoolOpReturnValue(nullptr)
    , m_mempoolNonstandardValue(nullptr)
    , m_mempoolOutputCountValue(nullptr)
    , m_mempoolTxCountSpark(nullptr)
    , m_mempoolTotalBytesSpark(nullptr)
    , m_mempoolP2pkhSpark(nullptr)
    , m_mempoolP2shSpark(nullptr)
    , m_mempoolMultisigSpark(nullptr)
    , m_mempoolOpReturnSpark(nullptr)
    , m_mempoolNonstandardSpark(nullptr)
    , m_mempoolOutputCountSpark(nullptr)
    , m_statsTransactionsValue(nullptr)
    , m_statsTpsValue(nullptr)
    , m_statsVolumeValue(nullptr)
    , m_statsOutputsValue(nullptr)
    , m_statsBytesValue(nullptr)
    , m_statsMedianFeeValue(nullptr)
    , m_statsAvgFeeValue(nullptr)
    , m_statsTransactionsSpark(nullptr)
    , m_statsTpsSpark(nullptr)
    , m_statsVolumeSpark(nullptr)
    , m_statsOutputsSpark(nullptr)
    , m_statsBytesSpark(nullptr)
    , m_statsMedianFeeSpark(nullptr)
    , m_statsAvgFeeSpark(nullptr)
    , m_uptimeValue(nullptr)
    , m_uptimeSpark(nullptr)
{
    QScrollArea* scrollArea = new QScrollArea(this);
    scrollArea->setWidgetResizable(true);
    scrollArea->setFrameShape(QFrame::NoFrame);

    QWidget* scrollContent = new QWidget();
    QVBoxLayout* outer = new QVBoxLayout(scrollContent);
    outer->setContentsMargins(18, 14, 18, 14);
    outer->setSpacing(12);

    QLabel* title = new QLabel(tr("Dashb0rd - All Metrics"));
    QFont tf = title->font();
    tf.setPointSize(tf.pointSize() + 8);
    tf.setBold(true);
    title->setFont(tf);
    outer->addWidget(title);

    QHBoxLayout* windowLayout = new QHBoxLayout();
    QLabel* windowLabel = new QLabel(tr("Rolling Window Blocks:"), this);
    m_statsWindowSpinBox = new QSpinBox(this);
    m_statsWindowSpinBox->setRange(1, 5000);
    m_statsWindowSpinBox->setValue(m_statsWindowBlocks);
    windowLayout->addWidget(windowLabel);
    windowLayout->addWidget(m_statsWindowSpinBox);
    windowLayout->addStretch();
    outer->addLayout(windowLayout);

    m_lastUpdated = new QLabel(tr("Last updated: n/a"));
    m_lastUpdated->setTextInteractionFlags(Qt::TextSelectableByMouse);
    outer->addWidget(m_lastUpdated);

    m_metricsContainer = scrollContent;
    m_metricsContainer->setAcceptDrops(true);
    m_metricsContainer->installEventFilter(this);

    m_metricGrid = new QGridLayout();
    m_metricGrid->setHorizontalSpacing(kMetricGridSpacing);
    m_metricGrid->setVerticalSpacing(kMetricGridSpacing);
    m_metricGrid->setAlignment(Qt::AlignTop | Qt::AlignLeft);

    int row = 0;
    int col = 0;

    auto addMetric = [&](const QString& label, QLabel*& value, SparklineWidget*& spark) {
        QWidget* box = createMetricBox(label, value, spark);
        box->setProperty("metricLabel", label);
        box->setAcceptDrops(true);
        box->installEventFilter(this);
        box->setCursor(Qt::OpenHandCursor);
        spark->setProperty("tooltipValueKind", TooltipValueKindForLabel(label));
        spark->setHoverTextProvider([this, spark](int index, double sampleValue) {
            return formatSparklineHoverText(spark, index, sampleValue);
        });
        spark->setDoubleClickHandler([this, spark](int index, double sampleValue) {
            showSparklineDetailsDialog(spark, index, sampleValue);
        });
        m_metricBoxes.push_back(box);
        m_metricGrid->addWidget(box, row, col, Qt::AlignLeft);
        if (++col >= kMetricGridColumns) {
            col = 0;
            ++row;
        }
    };

    addMetric(tr("Block Height"), m_chainTipHeightValue, m_chainTipHeightSpark);
    addMetric(tr("Difficulty"), m_chainTipDifficultyValue, m_chainTipDifficultySpark);
    addMetric(tr("Chain Tip Time"), m_chainTipTimeValue, m_chainTipTimeSpark);
    addMetric(tr("Bits (hex)"), m_chainTipBitsValue, m_chainTipBitsSpark);

    addMetric(tr("Mempool TX"), m_mempoolTxCountValue, m_mempoolTxCountSpark);
    addMetric(tr("Mempool Bytes"), m_mempoolTotalBytesValue, m_mempoolTotalBytesSpark);
    addMetric(tr("P2PKH Count"), m_mempoolP2pkhValue, m_mempoolP2pkhSpark);
    addMetric(tr("P2SH Count"), m_mempoolP2shValue, m_mempoolP2shSpark);
    addMetric(tr("Multisig Count"), m_mempoolMultisigValue, m_mempoolMultisigSpark);
    addMetric(tr("OP_RETURN Count"), m_mempoolOpReturnValue, m_mempoolOpReturnSpark);
    addMetric(tr("Nonstandard Count"), m_mempoolNonstandardValue, m_mempoolNonstandardSpark);
    addMetric(tr("Total Outputs"), m_mempoolOutputCountValue, m_mempoolOutputCountSpark);

    addMetric(tr("Transactions"), m_statsTransactionsValue, m_statsTransactionsSpark);
    addMetric(tr("TPS"), m_statsTpsValue, m_statsTpsSpark);
    addMetric(tr("Volume (DOGE)"), m_statsVolumeValue, m_statsVolumeSpark);
    addMetric(tr("Outputs"), m_statsOutputsValue, m_statsOutputsSpark);
    addMetric(tr("Bytes"), m_statsBytesValue, m_statsBytesSpark);
    addMetric(tr("Median Fee/Block"), m_statsMedianFeeValue, m_statsMedianFeeSpark);
    addMetric(tr("Avg Fee/Block"), m_statsAvgFeeValue, m_statsAvgFeeSpark);

    addMetric(tr("Uptime"), m_uptimeValue, m_uptimeSpark);

    outer->addLayout(m_metricGrid, 1);
    relayoutMetricBoxes();

    scrollArea->setWidget(scrollContent);

    QVBoxLayout* mainLayout = new QVBoxLayout(this);
    mainLayout->setContentsMargins(0, 0, 0, 0);
    mainLayout->addWidget(scrollArea);

    connect(m_pollTimer, SIGNAL(timeout()), this, SLOT(pollStats()));
    connect(m_statsWindowSpinBox, SIGNAL(valueChanged(int)), this, SLOT(setStatsWindow(int)));
    m_pollTimer->setInterval(kPollIntervalMs);
    m_pollTimer->start();

    pollStats();
}

Dashb0rdPage::~Dashb0rdPage() = default;

void Dashb0rdPage::setClientModel(ClientModel* model)
{
    m_clientModel = model;
    pollStats();
}

void Dashb0rdPage::setWalletModel(WalletModel* model)
{
    m_walletModel = model;
    (void)m_walletModel;
    pollStats();
}

void Dashb0rdPage::setStatsWindow(int blocks)
{
    m_statsWindowBlocks = std::max(1, blocks);
    pollStats();
}

QWidget* Dashb0rdPage::createMetricBox(const QString& label, QLabel*& valueLabel, SparklineWidget*& spark)
{
    QFrame* box = new QFrame(this);
    box->setFrameStyle(QFrame::StyledPanel | QFrame::Raised);
    const int boxWidth = MetricBoxMaxWidthPx(this);
    box->setMinimumWidth(boxWidth);
    box->setMaximumWidth(boxWidth);
    box->setSizePolicy(QSizePolicy::Fixed, QSizePolicy::Expanding);

    QPalette pal = box->palette();
    pal.setColor(QPalette::Window, palette().color(QPalette::AlternateBase));
    box->setAutoFillBackground(true);
    box->setPalette(pal);

    QVBoxLayout* layout = new QVBoxLayout(box);
    layout->setContentsMargins(8, 8, 8, 8);
    layout->setSpacing(6);

    QLabel* title = new QLabel(label, box);
    QFont titleFont = title->font();
    titleFont.setBold(true);
    title->setFont(titleFont);
    title->setAlignment(Qt::AlignCenter);
    title->setToolTip(MetricDefinitionForLabel(label));
    title->setProperty(kMetricDefinitionProperty, MetricDefinitionForLabel(label));
    title->setMouseTracking(true);
    title->setAttribute(Qt::WA_Hover, true);
    title->installEventFilter(this);

    valueLabel = MakeValueLabel();
    spark = new SparklineWidget(box);
    spark->setMinimumHeight(kSparklineMinHeight);

    layout->addWidget(title);
    layout->addWidget(valueLabel);
    layout->addWidget(spark);
    layout->setStretch(2, 1);

    return box;
}

void Dashb0rdPage::relayoutMetricBoxes()
{
    // Rebuild grid positions from the current ordering/visibility state.
    while (QLayoutItem* item = m_metricGrid->takeAt(0)) {
        delete item;
    }

    int visibleCount = 0;
    for (QWidget* box : m_metricBoxes) {
        if (box && !box->isHidden()) {
            ++visibleCount;
        }
    }
    int availableWidth = 0;
    if (m_metricsContainer) {
        QWidget* parentWidget = m_metricsContainer->parentWidget();
        // Prefer parent width (scroll viewport/container), fallback to content width.
        availableWidth = parentWidget ? parentWidget->width() : m_metricsContainer->width();
        if (m_metricsContainer->layout()) {
            const QMargins margins = m_metricsContainer->layout()->contentsMargins();
            availableWidth -= (margins.left() + margins.right());
        }
    }
    if (availableWidth <= 0) {
        availableWidth = this->width();
    }
    int metricBoxWidth = MetricBoxMaxWidthPx(m_metricsContainer);
    if (!m_metricBoxes.isEmpty() && m_metricBoxes[0]) {
        metricBoxWidth = std::max(kMetricBoxMinWidth, m_metricBoxes[0]->maximumWidth());
    }
    int dynamicColumns = 1;
    if (availableWidth > 0) {
        int columnsByWidth = (availableWidth + kMetricGridSpacing) / (metricBoxWidth + kMetricGridSpacing);
        dynamicColumns = std::max(1, columnsByWidth);
    }
    const int columns = std::max(1, std::min(dynamicColumns, visibleCount));

    int visibleIndex = 0;
    for (QWidget* box : m_metricBoxes) {
        if (!box || box->isHidden()) {
            continue;
        }
        const int row = visibleIndex / columns;
        const int col = visibleIndex % columns;
        m_metricGrid->addWidget(box, row, col, Qt::AlignLeft);
        ++visibleIndex;
    }
}

void Dashb0rdPage::resizeEvent(QResizeEvent* event)
{
    QWidget::resizeEvent(event);
    relayoutMetricBoxes();
}

void Dashb0rdPage::showEvent(QShowEvent* event)
{
    QWidget::showEvent(event);
    if (m_pollTimer) {
        m_pollTimer->start();
    }
    relayoutMetricBoxes();
    pollStats();
}

void Dashb0rdPage::hideEvent(QHideEvent* event)
{
    QWidget::hideEvent(event);
    if (m_pollTimer && m_pollTimer->isActive()) {
        m_pollTimer->stop();
    }
}

bool Dashb0rdPage::eventFilter(QObject* watched, QEvent* event)
{
    QWidget* watchedWidget = qobject_cast<QWidget*>(watched);
    const bool isMetricBox = watchedWidget && m_metricBoxes.contains(watchedWidget);
    const bool isMetricsContainer = (watched == m_metricsContainer);
    const bool isMetricTitle = watchedWidget && watchedWidget->property(kMetricDefinitionProperty).isValid();

    if (isMetricTitle && event->type() == QEvent::ToolTip) {
        QHelpEvent* helpEvent = static_cast<QHelpEvent*>(event);
        QToolTip::showText(helpEvent->globalPos(), watchedWidget->property(kMetricDefinitionProperty).toString(), watchedWidget);
        return true;
    }

    if ((isMetricBox || isMetricsContainer) && event->type() == QEvent::MouseButtonPress) {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (mouseEvent->button() == Qt::LeftButton) {
            if (isMetricBox) {
                // Record drag origin for drag threshold + source index lookup.
                m_dragStartPos = mouseEvent->pos();
                m_dragSourceBox = watchedWidget;
            }
        } else if (mouseEvent->button() == Qt::RightButton) {
            // Right-click opens metric visibility toggles.
            QMenu menu(this);
            for (int i = 0; i < m_metricBoxes.size(); ++i) {
                QWidget* box = m_metricBoxes[i];
                QAction* action = menu.addAction(box->property("metricLabel").toString());
                action->setCheckable(true);
                action->setChecked(!box->isHidden());
                action->setData(i);
            }
            const QAction* selectedAction = menu.exec(mouseEvent->globalPos());
            if (selectedAction) {
                const int boxIndex = selectedAction->data().toInt();
                if (boxIndex >= 0 && boxIndex < m_metricBoxes.size()) {
                    QWidget* box = m_metricBoxes[boxIndex];
                    box->setHidden(!box->isHidden());
                }
                relayoutMetricBoxes();
            }
            return true;
        }
    }

    if (isMetricBox && event->type() == QEvent::MouseMove) {
        QMouseEvent* mouseEvent = static_cast<QMouseEvent*>(event);
        if (!(mouseEvent->buttons() & Qt::LeftButton) || m_dragSourceBox != watchedWidget) {
            return QWidget::eventFilter(watched, event);
        }
        // Ignore tiny mouse movement so normal clicks do not trigger drag mode.
        if ((mouseEvent->pos() - m_dragStartPos).manhattanLength() < QApplication::startDragDistance()) {
            return QWidget::eventFilter(watched, event);
        }

        const int sourceIndex = m_metricBoxes.indexOf(m_dragSourceBox);
        if (sourceIndex < 0) {
            return QWidget::eventFilter(watched, event);
        }

        QDrag* drag = new QDrag(watchedWidget);
        QMimeData* mimeData = new QMimeData();
        mimeData->setData(kMetricMimeType, QByteArray::number(sourceIndex));
        drag->setMimeData(mimeData);

        // Show a translucent preview of the metric tile while dragging.
        QPixmap dragPixmap = watchedWidget->grab();
        if (!dragPixmap.isNull()) {
            QPixmap ghost(dragPixmap.size());
            ghost.fill(Qt::transparent);
            QPainter painter(&ghost);
            painter.setOpacity(0.65);
            painter.drawPixmap(0, 0, dragPixmap);
            painter.end();
            drag->setPixmap(ghost);
            drag->setHotSpot(mouseEvent->pos());
        }

        drag->exec(Qt::MoveAction);
        return true;
    }

    if ((isMetricBox || isMetricsContainer) && event->type() == QEvent::DragEnter) {
        QDragEnterEvent* dragEvent = static_cast<QDragEnterEvent*>(event);
        if (dragEvent->mimeData()->hasFormat(kMetricMimeType)) {
            dragEvent->acceptProposedAction();
            return true;
        }
    }

    if ((isMetricBox || isMetricsContainer) && event->type() == QEvent::Drop) {
        QDropEvent* dropEvent = static_cast<QDropEvent*>(event);
        if (!dropEvent->mimeData()->hasFormat(kMetricMimeType)) {
            return QWidget::eventFilter(watched, event);
        }

        const int sourceIndex = QString::fromLatin1(dropEvent->mimeData()->data(kMetricMimeType)).toInt();
        if (sourceIndex < 0 || sourceIndex >= m_metricBoxes.size()) {
            return QWidget::eventFilter(watched, event);
        }

        QWidget* targetBox = isMetricBox ? watchedWidget : nullptr;
        if (!targetBox && isMetricsContainer) {
            targetBox = m_metricsContainer->childAt(dropEvent->pos());
            while (targetBox && !m_metricBoxes.contains(targetBox)) {
                targetBox = targetBox->parentWidget();
            }
        }

        int targetIndex = targetBox ? m_metricBoxes.indexOf(targetBox) : (m_metricBoxes.size() - 1);
        if (targetIndex < 0) {
            targetIndex = m_metricBoxes.size() - 1;
        }

        if (sourceIndex != targetIndex) {
            // Reorder metric list and reflow visible tiles back into grid form.
            QWidget* box = m_metricBoxes.takeAt(sourceIndex);
            m_metricBoxes.insert(targetIndex, box);
            relayoutMetricBoxes();
        }

        dropEvent->setDropAction(Qt::MoveAction);
        dropEvent->accept();
        return true;
    }

    return QWidget::eventFilter(watched, event);
}

void Dashb0rdPage::pushSample(QVector<double>& series, SparklineWidget* spark, double value, const QString& txid, const QString& blockHash)
{
    series.push_back(value);
    if (series.size() > kMaxSparkPoints) {
        const int extra = series.size() - kMaxSparkPoints;
        series.erase(series.begin(), series.begin() + extra);
    }
    if (spark) {
        PointContext pointContext;
        pointContext.timestamp = static_cast<qint64>(QDateTime::currentDateTime().toTime_t());
        pointContext.txid = txid;
        pointContext.blockHash = blockHash;
        QVector<PointContext>& contexts = m_pointContexts[spark];
        contexts.push_back(pointContext);
        if (contexts.size() > kMaxSparkPoints) {
            const int extra = contexts.size() - kMaxSparkPoints;
            contexts.erase(contexts.begin(), contexts.begin() + extra);
        }
        spark->setData(series);
    }
}

QString Dashb0rdPage::formatSparklineHoverText(SparklineWidget* spark, int index, double value) const
{
    if (!spark || !m_pointContexts.contains(spark)) {
        return QString();
    }
    const QVector<PointContext>& contexts = m_pointContexts[spark];
    if (index < 0 || index >= contexts.size()) {
        return QString();
    }
    const PointContext& ctx = contexts[index];
    const QString tsStr = DateTimeFromEpochCompat(ctx.timestamp).toString(Qt::ISODate);
    const QString valueStr = FormatValueForKind(spark->property("tooltipValueKind").toString(), value);
    if (!ctx.txid.isEmpty()) {
        return tr("Time: %1\nValue: %2\nTxID: %3").arg(tsStr).arg(valueStr).arg(ctx.txid);
    }
    return tr("Time: %1\nValue: %2\nBlock: %3").arg(tsStr).arg(valueStr).arg(!ctx.blockHash.isEmpty() ? ctx.blockHash : tr("n/a"));
}

void Dashb0rdPage::showSparklineDetailsDialog(SparklineWidget* spark, int index, double value)
{
    if (!spark || !m_pointContexts.contains(spark)) {
        return;
    }
    const QVector<PointContext>& contexts = m_pointContexts[spark];
    if (index < 0 || index >= contexts.size()) {
        return;
    }
    const PointContext& ctx = contexts[index];
    const QString tsStr = DateTimeFromEpochCompat(ctx.timestamp).toString(Qt::ISODate);
    const QString valueStr = FormatValueForKind(spark->property("tooltipValueKind").toString(), value);

    UniValue decoded;
    QString decodeError;
    const bool decodedOk = DecodeContextToUniValue(ctx.txid, ctx.blockHash, decoded, decodeError);

    QDialog details(this);
    details.setWindowTitle(tr("Metric Point Details"));
    QVBoxLayout* detailsLayout = new QVBoxLayout(&details);
    detailsLayout->addWidget(new QLabel(tr("Time: %1").arg(tsStr), &details));
    detailsLayout->addWidget(new QLabel(tr("Value: %1").arg(valueStr), &details));
    if (!ctx.txid.isEmpty()) {
        detailsLayout->addWidget(new QLabel(tr("TxID: %1").arg(ctx.txid), &details));
    } else if (!ctx.blockHash.isEmpty()) {
        detailsLayout->addWidget(new QLabel(tr("Block: %1").arg(ctx.blockHash), &details));
    }

    QTreeWidget* tree = new QTreeWidget(&details);
    tree->setColumnCount(2);
    tree->setHeaderLabels(QStringList() << tr("Field") << tr("Value"));
    tree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
    tree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
    PopulateDecodedTree(tree, decodedOk, decoded, decodeError);
    HighlightScriptAsmForType(tree, scriptTypeFilterForSpark(spark));

    QObject::connect(tree, &QTreeWidget::itemDoubleClicked, &details, [this, ctx](QTreeWidgetItem* item, int /*column*/) {
        if (!item) return;
        QString txid = item->text(1).trimmed();
        if (!IsLikelyTxid(txid)) return;
        if (txid.size() >= 2 && txid.startsWith('"') && txid.endsWith('"')) {
            txid = txid.mid(1, txid.size() - 2);
        }

        UniValue nestedDecoded;
        QString nestedError;
        const bool nestedOk = DecodeContextToUniValue(txid, ctx.blockHash, nestedDecoded, nestedError);

        QDialog nested(this);
        nested.setWindowTitle(tr("Decoded Transaction"));
        QVBoxLayout* nestedLayout = new QVBoxLayout(&nested);
        nestedLayout->addWidget(new QLabel(tr("TxID: %1").arg(txid), &nested));
        QTreeWidget* nestedTree = new QTreeWidget(&nested);
        nestedTree->setColumnCount(2);
        nestedTree->setHeaderLabels(QStringList() << tr("Field") << tr("Value"));
        nestedTree->header()->setSectionResizeMode(0, QHeaderView::ResizeToContents);
        nestedTree->header()->setSectionResizeMode(1, QHeaderView::Stretch);
        PopulateDecodedTree(nestedTree, nestedOk, nestedDecoded, nestedError);
        nestedLayout->addWidget(nestedTree);
        QDialogButtonBox* closeNested = new QDialogButtonBox(QDialogButtonBox::Close, &nested);
        QObject::connect(closeNested, &QDialogButtonBox::rejected, &nested, &QDialog::reject);
        nestedLayout->addWidget(closeNested);
        nested.resize(760, 500);
        nested.exec();
    });

    detailsLayout->addWidget(tree);
    QDialogButtonBox* closeBox = new QDialogButtonBox(QDialogButtonBox::Close, &details);
    QObject::connect(closeBox, &QDialogButtonBox::rejected, &details, &QDialog::reject);
    detailsLayout->addWidget(closeBox);
    details.resize(760, 500);
    details.exec();
}

QString Dashb0rdPage::scriptTypeFilterForSpark(SparklineWidget* spark) const
{
    if (spark == m_mempoolP2pkhSpark) return "pubkeyhash";
    if (spark == m_mempoolP2shSpark) return "scripthash";
    if (spark == m_mempoolMultisigSpark) return "multisig";
    if (spark == m_mempoolOpReturnSpark) return "nulldata";
    if (spark == m_mempoolNonstandardSpark) return "nonstandard";
    return QString();
}

void Dashb0rdPage::pollStats()
{
    if (!isVisible()) {
        return;
    }

    const QDateTime now = QDateTime::currentDateTime();
    m_lastUpdated->setText(tr("Last updated: %1").arg(now.toString(Qt::ISODate)));

    if (!m_clientModel) {
        return;
    }

    try {
        // Pull all dashboard values in one core RPC call.
        JSONRPCRequest req;
        req.strMethod = "getdashboardmetrics";
        req.params = UniValue(UniValue::VARR);
        req.params.push_back(m_statsWindowBlocks);
        const UniValue result = tableRPC.execute(req);
        const QString chainBlockHash = GetString(result, "chain_tip_blockhash");

        const int64_t chainTipHeight = GetInt64(result, "chain_tip_height");
        m_chainTipHeightValue->setText(QString::number(chainTipHeight));
        pushSample(m_chainTipHeightSeries, m_chainTipHeightSpark, static_cast<double>(chainTipHeight), QString(), chainBlockHash);

        const double chainTipDifficulty = GetDouble(result, "chain_tip_difficulty");
        m_chainTipDifficultyValue->setText(QString::number(chainTipDifficulty, 'f', 2));
        pushSample(m_chainTipDifficultySeries, m_chainTipDifficultySpark, chainTipDifficulty, QString(), chainBlockHash);

        const QString chainTipTime = GetString(result, "chain_tip_time");
        m_chainTipTimeValue->setText(chainTipTime);
        const qint64 chainTipTimeEpoch = static_cast<qint64>(QDateTime::fromString(chainTipTime, Qt::ISODate).toTime_t());
        pushSample(m_chainTipTimeSeries, m_chainTipTimeSpark, static_cast<double>(chainTipTimeEpoch), QString(), chainBlockHash);

        const QString chainTipBits = GetString(result, "chain_tip_bits_hex");
        m_chainTipBitsValue->setText(chainTipBits);
        bool bitsOk = false;
        const quint64 bitsValue = chainTipBits.toULongLong(&bitsOk, 0);
        pushSample(m_chainTipBitsSeries, m_chainTipBitsSpark, bitsOk ? static_cast<double>(bitsValue) : 0.0, QString(), chainBlockHash);

        const int64_t mempoolTxCount = GetInt64(result, "mempool_tx_count");
        const QString mempoolTxid = GetString(result, "mempool_latest_txid");
        if (m_prevMempoolTxCount >= 0) {
            // Show per-poll direction so users can quickly see churn (+/-).
            const int64_t mempoolDelta = mempoolTxCount - m_prevMempoolTxCount;
            QString deltaText = QString::number(mempoolDelta);
            if (mempoolDelta > 0) {
                deltaText.prepend("+");
            }
            m_mempoolTxCountValue->setText(QString("%1 (%2)").arg(mempoolTxCount).arg(deltaText));
        } else {
            m_mempoolTxCountValue->setText(QString::number(mempoolTxCount));
        }
        m_prevMempoolTxCount = mempoolTxCount;
        pushSample(m_mempoolTxCountSeries, m_mempoolTxCountSpark, static_cast<double>(mempoolTxCount), mempoolTxid);

        const int64_t mempoolTotalBytes = GetInt64(result, "mempool_total_bytes");
        m_mempoolTotalBytesValue->setText(GUIUtil::formatBytes(mempoolTotalBytes));
        pushSample(m_mempoolTotalBytesSeries, m_mempoolTotalBytesSpark, static_cast<double>(mempoolTotalBytes), mempoolTxid);

        const int64_t mempoolP2pkhCount = GetInt64(result, "mempool_p2pkh_count");
        m_mempoolP2pkhValue->setText(QString::number(mempoolP2pkhCount));
        pushSample(m_mempoolP2pkhSeries, m_mempoolP2pkhSpark, static_cast<double>(mempoolP2pkhCount), mempoolTxid);

        const int64_t mempoolP2shCount = GetInt64(result, "mempool_p2sh_count");
        m_mempoolP2shValue->setText(QString::number(mempoolP2shCount));
        pushSample(m_mempoolP2shSeries, m_mempoolP2shSpark, static_cast<double>(mempoolP2shCount), mempoolTxid);

        const int64_t mempoolMultisigCount = GetInt64(result, "mempool_multisig_count");
        m_mempoolMultisigValue->setText(QString::number(mempoolMultisigCount));
        pushSample(m_mempoolMultisigSeries, m_mempoolMultisigSpark, static_cast<double>(mempoolMultisigCount), mempoolTxid);

        const int64_t mempoolOpReturnCount = GetInt64(result, "mempool_op_return_count");
        m_mempoolOpReturnValue->setText(QString::number(mempoolOpReturnCount));
        pushSample(m_mempoolOpReturnSeries, m_mempoolOpReturnSpark, static_cast<double>(mempoolOpReturnCount), mempoolTxid);

        const int64_t mempoolNonstandardCount = GetInt64(result, "mempool_nonstandard_count");
        m_mempoolNonstandardValue->setText(QString::number(mempoolNonstandardCount));
        pushSample(m_mempoolNonstandardSeries, m_mempoolNonstandardSpark, static_cast<double>(mempoolNonstandardCount), mempoolTxid);

        const int64_t mempoolOutputCount = GetInt64(result, "mempool_output_count");
        m_mempoolOutputCountValue->setText(QString::number(mempoolOutputCount));
        pushSample(m_mempoolOutputCountSeries, m_mempoolOutputCountSpark, static_cast<double>(mempoolOutputCount), mempoolTxid);

        const int64_t statsTransactions = GetInt64(result, "stats_transactions");
        const QString statsBlockHash = GetString(result, "stats_reference_blockhash");
        m_statsTransactionsValue->setText(QString::number(statsTransactions));
        pushSample(m_statsTransactionsSeries, m_statsTransactionsSpark, static_cast<double>(statsTransactions), QString(), statsBlockHash);

        const double statsTps = GetDouble(result, "stats_tps");
        m_statsTpsValue->setText(QString::number(statsTps, 'f', 3));
        pushSample(m_statsTpsSeries, m_statsTpsSpark, statsTps, QString(), statsBlockHash);

        const double statsVolume = GetDouble(result, "stats_volume");
        m_statsVolumeValue->setText(QString::number(statsVolume, 'f', 2));
        pushSample(m_statsVolumeSeries, m_statsVolumeSpark, statsVolume, QString(), statsBlockHash);

        const int64_t statsOutputs = GetInt64(result, "stats_outputs");
        m_statsOutputsValue->setText(QString::number(statsOutputs));
        pushSample(m_statsOutputsSeries, m_statsOutputsSpark, static_cast<double>(statsOutputs), QString(), statsBlockHash);

        const int64_t statsBytes = GetInt64(result, "stats_bytes");
        // Show formatted and exact byte totals to make small changes obvious.
        m_statsBytesValue->setText(QString("%1 (%2 B)").arg(GUIUtil::formatBytes(statsBytes)).arg(QString::number(statsBytes)));
        pushSample(m_statsBytesSeries, m_statsBytesSpark, static_cast<double>(statsBytes), QString(), statsBlockHash);

        const double statsMedianFeePerBlock = GetDouble(result, "stats_median_fee_per_block");
        m_statsMedianFeeValue->setText(QString::number(statsMedianFeePerBlock, 'f', 8));
        pushSample(m_statsMedianFeeSeries, m_statsMedianFeeSpark, statsMedianFeePerBlock, QString(), statsBlockHash);

        const double statsAvgFeePerBlock = GetDouble(result, "stats_avg_fee_per_block");
        m_statsAvgFeeValue->setText(QString::number(statsAvgFeePerBlock, 'f', 8));
        pushSample(m_statsAvgFeeSeries, m_statsAvgFeeSpark, statsAvgFeePerBlock, QString(), statsBlockHash);

        const int64_t uptimeSec = GetInt64(result, "uptime_sec");
        if (uptimeSec > std::numeric_limits<int>::max()) {
            m_uptimeValue->setText(QString::number(uptimeSec) + tr(" s"));
        } else {
            m_uptimeValue->setText(GUIUtil::formatDurationStr(static_cast<int>(uptimeSec)));
        }
        pushSample(m_uptimeSeries, m_uptimeSpark, static_cast<double>(uptimeSec));
    } catch (const UniValue& objError) {
        LogPrintf("Dashboard RPC error: %s\n", objError.write().c_str());
    } catch (const std::exception& e) {
        LogPrintf("Dashboard metrics error: %s\n", e.what());
    }
}
