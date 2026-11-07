// src/ui/LogDelegate.h
#pragma once
#include <QStyledItemDelegate>

// 日志行委托:把每行画成 5 列(时间 / 事件 / PID / 进程名 / 详情)。
// 列宽常量与 LogHeader 共享,确保表头与数据列严格对齐。
class LogDelegate : public QStyledItemDelegate {
    Q_OBJECT
public:
    using QStyledItemDelegate::QStyledItemDelegate;

    // 共享列宽(像素)。detail 列取剩余宽度。
    static constexpr int kLeftMargin = 6;   // 与表头布局的左留白一致
    static constexpr int kColTimeW   = 90;  // 时间列宽(去掉毫秒后 [HH:mm:ss] 更窄)
    static constexpr int kColEventW  = 150; // 事件列宽
    static constexpr int kColPidW    = 76;  // PID 列宽
    static constexpr int kColPnameW  = 140; // 进程名列宽

    void paint(QPainter* p, const QStyleOptionViewItem& o, const QModelIndex& idx) const override;
    QSize sizeHint(const QStyleOptionViewItem& o, const QModelIndex& idx) const override;
};
