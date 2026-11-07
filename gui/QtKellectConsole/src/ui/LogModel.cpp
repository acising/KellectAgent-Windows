// src/ui/LogModel.cpp
#include "LogModel.h"

QVariant LogModel::data(const QModelIndex& idx, int role) const {
    if (!idx.isValid() || idx.row() < 0 || idx.row() >= rows_.size()) return {};
    const auto& e = rows_[idx.row()];
    switch (role) {
        case TextRole:        return e.text;
        case TimeRole:        return e.time;
        case MarkedRole:      return e.marked;
        case EventRole:       return e.event;
        case PidRole:         return e.pid;
        case DetailRole:      return e.detail;
        case PNameRole:       return e.pname;
        case SearchRole:
            // 拼接显示列(事件/PID/进程名/详情)供搜索匹配;刻意不含原始 JSON,
            // 避免输入 "PID"/"Event" 等 key 名命中所有行。时间列不含(不按时间搜索)。
            return e.event + ' ' + e.pid + ' ' + e.pname + ' ' + e.detail;
    }
    return {};
}

void LogModel::append(const LogEntry& e) {
    const int n = rows_.size();
    beginInsertRows({}, n, n);
    rows_.append(e);
    endInsertRows();
}

void LogModel::trimIfFull() {
    if (rows_.size() <= kMaxLines) return;
    const int cut = kTrimBatch;
    beginRemoveRows({}, 0, cut - 1);
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
    endResetModel();
}
