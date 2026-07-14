// src/domain/LogParser.cpp
// 容错解析单行 kellect JSON 日志。
// 策略:event/pid/pname 始终先用正则抽取(即便整行 JSON 非法,前三列仍能对齐);
// detail:整行可被 QJsonDocument 解析时按"优先级 + 文档序"拼 key=value;
//       解析失败时(kellect 路径反斜杠未转义等)改用全局正则抽所有 "key":value
//       (嵌套 args 内字段也能抽到,因为正则不分层级),同样按优先级 + 隐藏名单拼,
//       避免非法 JSON 行回退成整行原文。
#include "LogParser.h"
#include <QHash>
#include <QJsonArray>
#include <QJsonDocument>
#include <QJsonObject>
#include <QJsonValue>
#include <QPair>
#include <QRegularExpression>
#include <QSet>
#include <QStringList>
#include <QVector>
#include <cmath>

// JSON 值 → 字符串。对象/数组序列化为紧凑 JSON,使嵌套 args 以 args={...} 呈现而非空。
static QString jsonValueToString(const QJsonValue& v) {
    switch (v.type()) {
    case QJsonValue::String: return v.toString();
    case QJsonValue::Bool:   return v.toBool() ? QStringLiteral("true") : QStringLiteral("false");
    case QJsonValue::Null:   return QStringLiteral("null");
    case QJsonValue::Double: {
        const double d = v.toDouble();
        // 整数等价值按 qint64 格式化,避免 PID/size 等出现小数尾
        if (std::floor(d) == d) return QString::number(static_cast<qint64>(d));
        return QString::number(d);
    }
    case QJsonValue::Object:
        return QString::fromUtf8(QJsonDocument(v.toObject()).toJson(QJsonDocument::Compact));
    case QJsonValue::Array:
        return QString::fromUtf8(QJsonDocument(v.toArray()).toJson(QJsonDocument::Compact));
    case QJsonValue::Undefined:
    default:
        return {};
    }
}

// 隐藏名单:这些噪音字段不进 detail(仅在双击详情对话框的原始 JSON 中可见)。
// 精确名 + 3 条通配规则(startsWith("Reserved") / endsWith("Handle") / == "Flags")。
static bool isHiddenKey(const QString& key) {
    static const QSet<QString> exact = {
        QStringLiteral("PPID"), QStringLiteral("PPName"), QStringLiteral("Host-UUID"),
        QStringLiteral("TimeStamp"), QStringLiteral("TID"), QStringLiteral("TTID"),
        QStringLiteral("TThreadId"), QStringLiteral("ProcessId"), QStringLiteral("IrpPtr"),
        QStringLiteral("FileObject"), QStringLiteral("FileKey"), QStringLiteral("connid"),
        QStringLiteral("seqnum"), QStringLiteral("UniqueProcessKey"),
        QStringLiteral("DirectoryTableBase"), QStringLiteral("UserSID"),
        QStringLiteral("SessionId"), QStringLiteral("ExitStatus"), QStringLiteral("StackBase"),
        QStringLiteral("StackLimit"), QStringLiteral("UserStackBase"),
        QStringLiteral("UserStackLimit"), QStringLiteral("TebBase"), QStringLiteral("Affinity"),
        QStringLiteral("BasePriority"), QStringLiteral("PagePriority"), QStringLiteral("IoPriority"),
        QStringLiteral("ThreadFlags"), QStringLiteral("PageFaultCount"),
        QStringLiteral("HandleCount"), QStringLiteral("PeakVirtualSize"),
        QStringLiteral("PeakWorkingSetSize"), QStringLiteral("PeakPagefileUsage"),
        QStringLiteral("VirtualSize"), QStringLiteral("WorkingSetSize"),
        QStringLiteral("PrivatePageCount"), QStringLiteral("DiskNumber"), QStringLiteral("IrpFlags"),
        QStringLiteral("ByteOffset"), QStringLiteral("Reserved"), QStringLiteral("SpareByte"),
        QStringLiteral("PreviousState"), QStringLiteral("NewThreadWaitTime"),
        QStringLiteral("OldThreadState")
    };
    if (exact.contains(key)) return true;
    if (key.startsWith(QStringLiteral("Reserved"))) return true;
    if (key.endsWith(QStringLiteral("Handle"))) return true;
    if (key == QStringLiteral("Flags")) return true;
    return false;
}

// 详情字段显示优先级(从高到低):命中字段按此序在前,其余非隐藏字段按文档序在后。
static const QVector<QString> kDetailPriority = {
    QStringLiteral("CommandLine"), QStringLiteral("OpenPath"), QStringLiteral("FileName"),
    QStringLiteral("ImageFileName"), QStringLiteral("KeyName"), QStringLiteral("PortName"),
    QStringLiteral("daddr"), QStringLiteral("dport"), QStringLiteral("saddr"),
    QStringLiteral("sport"), QStringLiteral("size"), QStringLiteral("IoSize"),
    QStringLiteral("TransferSize"), QStringLiteral("InfoClass"), QStringLiteral("CreateOptions"),
    QStringLiteral("MajorFunction"), QStringLiteral("FailureCode"), QStringLiteral("NtStatus")
};

// 判定某键是否排除出 detail(列字段 Event/PID/PName + 命中的 pid 键 + 隐藏名单)。
static bool isDetailExcluded(const QString& key, const QString& pidKey) {
    if (key == QLatin1String("Event")) return true;
    if (key == QLatin1String("PID")) return true;
    if (key == QLatin1String("PName")) return true;
    if (!pidKey.isEmpty() && key == pidKey) return true;
    return isHiddenKey(key);
}

ParsedLine parseKellectLine(const QString& raw) {
    ParsedLine out;

    // 1. 始终用正则抽取 event/pid/pname(对非法 JSON 同样有效)。
    static const QRegularExpression eventRe(QStringLiteral("\"Event\"\\s*:\\s*\"([^\"]*)\""));
    static const QRegularExpression pidRe(QStringLiteral("\"(?:PID|ProcessId|TTID|TThreadId)\"\\s*:\\s*(\\d+)"));
    static const QRegularExpression pnameRe(QStringLiteral("\"PName\"\\s*:\\s*\"([^\"]*)\""));

    if (const QRegularExpressionMatch m = eventRe.match(raw); m.hasMatch())
        out.event = m.captured(1);

    QString pidKey; // 记下命中的 pid 键名,以便从 detail 中排除
    if (const QRegularExpressionMatch m = pidRe.match(raw); m.hasMatch()) {
        out.pid = m.captured(1);
        const QString full = m.captured(0);
        const int colon = full.indexOf(QLatin1Char(':'));
        if (colon > 0) {
            QString k = full.left(colon).trimmed();
            if (k.size() >= 2 && k.startsWith(QLatin1Char('"')) && k.endsWith(QLatin1Char('"')))
                pidKey = k.mid(1, k.size() - 2);
        }
    }

    if (const QRegularExpressionMatch m = pnameRe.match(raw); m.hasMatch())
        out.pname = m.captured(1);

    // 2. detail:优先整体解析(可解析时得到完整字段 + 正确类型 + 嵌套序列化)。
    const auto doc = QJsonDocument::fromJson(raw.toUtf8());
    if (doc.isObject()) {
        const QJsonObject obj = doc.object();
        QStringList parts;
        QSet<QString> used;
        for (const QString& p : kDetailPriority) {
            if (obj.contains(p) && !isDetailExcluded(p, pidKey)) {
                parts << p + QLatin1Char('=') + jsonValueToString(obj.value(p));
                used.insert(p);
            }
        }
        for (const QString& key : obj.keys()) {
            if (used.contains(key) || isDetailExcluded(key, pidKey)) continue;
            parts << key + QLatin1Char('=') + jsonValueToString(obj.value(key));
        }
        out.detail = parts.join(QLatin1Char(' '));
        return out;
    }

    // 3. 整行解析失败(kellect 路径反斜杠未转义等):全局正则抽所有 "key":value
    //    (字符串/数字/bool/null;嵌套 args 内字段也会被抽到,因为正则不分层级),
    //    同样按优先级 + 隐藏名单拼,使非法 JSON 行也显示成解析后的 key=value。
    static const QRegularExpression pairRe(
        QStringLiteral("\"([^\"]+)\"\\s*:\\s*(\"[^\"]*\"|-?\\d+(?:\\.\\d+)?|true|false|null)"));
    QVector<QPair<QString, QString>> pairs;
    auto it = pairRe.globalMatch(raw);
    while (it.hasNext()) {
        const QRegularExpressionMatch m = it.next();
        QString val = m.captured(2);
        if (val.startsWith(QLatin1Char('"'))) val = val.mid(1, val.size() - 2); // 去首尾引号
        pairs.append({m.captured(1), val});
    }
    if (pairs.isEmpty()) { out.detail = raw; return out; } // 连一对都没(非 JSON 行)→ 整行回退

    QHash<QString, QString> byKey;
    QStringList docOrder;
    for (const auto& pr : pairs) {
        if (byKey.contains(pr.first)) continue; // 重复键取首个
        byKey.insert(pr.first, pr.second);
        docOrder << pr.first;
    }
    QStringList parts;
    QSet<QString> used;
    for (const QString& p : kDetailPriority) {
        if (byKey.contains(p) && !isDetailExcluded(p, pidKey)) {
            parts << p + QLatin1Char('=') + byKey.value(p);
            used.insert(p);
        }
    }
    for (const QString& key : docOrder) {
        if (used.contains(key) || isDetailExcluded(key, pidKey)) continue;
        parts << key + QLatin1Char('=') + byKey.value(key);
    }
    out.detail = parts.join(QLatin1Char(' '));
    return out;
}
