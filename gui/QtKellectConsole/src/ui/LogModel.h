// src/ui/LogModel.h
#pragma once
#include <QAbstractListModel>
#include <QVector>
#include "../domain/LogEntry.h"

inline constexpr int kMaxLines  = 50000;
inline constexpr int kTrimBatch = 5000;

class LogModel : public QAbstractListModel {
    Q_OBJECT
public:
    enum Roles { TextRole = Qt::UserRole + 1, TimeRole, MarkedRole,
                 EventRole, PidRole, DetailRole, PNameRole, SearchRole };

    int rowCount(const QModelIndex& = {}) const override { return rows_.size(); }
    QVariant data(const QModelIndex& idx, int role) const override;

    void append(const LogEntry& e);
    void trimIfFull();
    void toggleMark(int row);
    void clear();
    const QVector<LogEntry>& rows() const { return rows_; }
private:
    QVector<LogEntry> rows_;
};
