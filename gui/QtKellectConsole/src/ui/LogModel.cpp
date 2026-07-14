// src/ui/LogModel.cpp
#include "LogModel.h"

QVariant LogModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() < 0 || idx.row() >= rows_.size()) return {};
    const auto& e = rows_[idx.row()];
    switch (role) {
        case TextRole:        return e.text;
        case TimeRole:        return e.time;
        case DecodeErrorsRole:return e.decodeErrors;
        case MarkedRole:      return e.marked;
        case EventRole:       return e.event;
        case PidRole:         return e.pid;
        case DetailRole:      return e.detail;
        case PNameRole:       return e.pname;
    }
    return {};
}

void LogModel::append(const LogEntry& e) {
    const int n = rows_.size();
    beginInsertRows({}, n, n);
    rows_.append(e);
    totalErrors_ += e.decodeErrors;
    endInsertRows();
}

void LogModel::trimIfFull() {
    if (rows_.size() <= kMaxLines) return;
    const int cut = kTrimBatch;
    beginRemoveRows({}, 0, cut - 1);
    for (int i = 0; i < cut; ++i) totalErrors_ -= rows_[i].decodeErrors;
    rows_.remove(0, cut);
    endRemoveRows();
}

void LogModel::toggleMark(int row) {
    if (row < 0 || row >= rows_.size()) return;
    rows_[row].marked = !rows_[row].marked;
    emit dataChanged(index(row), index(row), {MarkedRole});
}

void LogModel::clear() {
    beginResetModel();
    rows_.clear();
    totalErrors_ = 0;
    endResetModel();
}

int LogModel::totalDecodeErrors() const { return totalErrors_; }
