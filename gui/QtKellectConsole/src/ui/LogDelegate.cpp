// src/ui/LogDelegate.cpp
// 5 列绘制:先画书签背景,再逐列裁剪绘制文本,长文本不溢出到下一列。
#include "LogDelegate.h"
#include "LogModel.h"
#include "EventColor.h"
#include <QPainter>
#include <QFontMetrics>
#include <QLocale>
#include <algorithm>

void LogDelegate::paint(QPainter* p, const QStyleOptionViewItem& o, const QModelIndex& idx) const {
    p->save();

    // 书签行:先铺满背景(在设置任何裁剪之前)
    const bool marked = idx.data(LogModel::MarkedRole).toBool();
    if (marked) p->fillRect(o.rect, markBackground());

    // 从 model 各 role 取已解析字段(不再在委托里解析 JSON)
    const QDateTime time       = idx.data(LogModel::TimeRole).toDateTime();
    const QString eventStr     = idx.data(LogModel::EventRole).toString();
    const QString pidStr       = idx.data(LogModel::PidRole).toString();
    const QString pnameStr     = idx.data(LogModel::PNameRole).toString();
    const QString detail       = idx.data(LogModel::DetailRole).toString();

    const EventDomain domain   = domainOfEvent(eventStr);
    const QColor eventColor    = textColor(domain);   // 事件列用域色
    const QColor detailColor   = textColor(domain);   // 详情列同域色
    const QColor timeColor("#7A7A7A");
    const QColor pidColor("#9CDCFE");
    const QColor pnameColor("#CE9178"); // 棕色,与 PID/详情区分

    const QFont mono("Consolas", 9);
    p->setFont(mono);
    const QFontMetrics fm(mono);

    const int x0  = o.rect.left() + kLeftMargin;
    const int top = o.rect.top();
    const int h   = o.rect.height();

    // 画一列:固定宽度 + 裁剪 + 右侧省略号,防止溢出到下一列
    auto drawCol = [&](int x, int w, const QString& text, const QColor& color) {
        if (w <= 0) return;
        const QRect col(x, top, w, h);
        const QRect clip = col.adjusted(0, 0, -4, 0); // 右留 4px 间距
        p->setClipRect(clip);
        p->setPen(color);
        const QString shown = fm.elidedText(text, Qt::ElideRight, clip.width());
        p->drawText(col, Qt::AlignLeft | Qt::AlignVCenter, shown);
    };

    // 时间(去掉毫秒,更紧凑);C locale 保证 ASCII 数字,不随系统区域格式漂移
    const QString ts = "[" + QLocale::c().toString(time, "HH:mm:ss") + "]";
    drawCol(x0, kColTimeW, ts, timeColor);

    // 事件
    const int xEvent = x0 + kColTimeW;
    drawCol(xEvent, kColEventW, eventStr, eventColor);

    // PID(空则按灰色占位绘制,保持对齐)
    const int xPid = xEvent + kColEventW;
    drawCol(xPid, kColPidW, pidStr, pidStr.isEmpty() ? timeColor : pidColor);

    // 进程名(空则按灰色占位绘制,保持对齐)
    const int xPname = xPid + kColPidW;
    drawCol(xPname, kColPnameW, pnameStr, pnameStr.isEmpty() ? timeColor : pnameColor);

    // 详情(取剩余宽度)
    const int xDetail = xPname + kColPnameW;
    const int detailW = o.rect.right() - xDetail + 1 - 4; // 4px 右边距
    drawCol(xDetail, std::max(0, detailW), detail, detailColor);

    p->setClipping(false);
    p->restore();
}

QSize LogDelegate::sizeHint(const QStyleOptionViewItem& o, const QModelIndex&) const {
    QFontMetrics fm(QFont("Consolas", 9));
    return { o.rect.width(), std::max(18, fm.height() + 4) };
}
