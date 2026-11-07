// src/ui/LogHeader.cpp
#include "LogHeader.h"
#include "LogDelegate.h"
#include <QHBoxLayout>
#include <QLabel>
#include <QFont>

LogHeader::LogHeader(QWidget* parent) : QFrame(parent) {
    auto* lay = new QHBoxLayout(this);
    // 左留白 = 委托的 kLeftMargin,使标题左缘与数据列左缘对齐
    lay->setContentsMargins(LogDelegate::kLeftMargin, 0, 0, 0);
    lay->setSpacing(0);

    const QFont mono("Consolas", 9);

    auto makeCol = [this, &mono](const QString& title, int fixedW) {
        auto* lbl = new QLabel(title, this);
        lbl->setFixedWidth(fixedW);
        lbl->setFont(mono);
        return lbl;
    };

    lay->addWidget(makeCol(QObject::tr("时间"), LogDelegate::kColTimeW));
    lay->addWidget(makeCol(QObject::tr("事件"), LogDelegate::kColEventW));
    lay->addWidget(makeCol(QObject::tr("PID"),  LogDelegate::kColPidW));
    lay->addWidget(makeCol(QObject::tr("进程名"), LogDelegate::kColPnameW));

    auto* detailLbl = new QLabel(QObject::tr("详情"), this);
    detailLbl->setFont(mono);
    lay->addWidget(detailLbl, 1); // 详情列拉伸占满剩余
}
