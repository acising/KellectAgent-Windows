// src/ui/LogHeader.h
#pragma once
#include <QFrame>

// 日志视图上方的列标题条。列宽取自 LogDelegate 常量,确保表头与数据列对齐。
// 无自定义信号,故无需额外 Q_OBJECT(qApp 翻译用 QObject::tr 即可)。
class LogHeader : public QFrame {
public:
    explicit LogHeader(QWidget* parent = nullptr);
};
