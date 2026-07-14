#include <QtTest>
#include "ui/LogModel.h"
#include "domain/LogEntry.h"

class TestModel : public QObject { Q_OBJECT
private slots:
    void appendGrowsRowCount();
    void trimRemovesOldestBatch();
    void toggleMark();
    void totalDecodeErrors();
};

void TestModel::appendGrowsRowCount() {
    LogModel m;
    QCOMPARE(m.rowCount(), 0);
    m.append({ QDateTime::currentDateTime(), "x", 0, false });
    QCOMPARE(m.rowCount(), 1);
}
void TestModel::trimRemovesOldestBatch() {
    LogModel m;
    for (int i = 0; i < kMaxLines + 1; ++i)
        m.append({ QDateTime::currentDateTime(), QString::number(i), 0, false });
    m.trimIfFull();
    QCOMPARE(m.rowCount(), kMaxLines + 1 - kTrimBatch); // 45001
}
void TestModel::toggleMark() {
    LogModel m;
    m.append({ QDateTime::currentDateTime(), "a", 0, false });
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), true);
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), false);
}
void TestModel::totalDecodeErrors() {
    LogModel m;
    m.append({ QDateTime::currentDateTime(), "a", 2, false });
    m.append({ QDateTime::currentDateTime(), "b", 3, false });
    QCOMPARE(m.totalDecodeErrors(), 5);
}

QTEST_GUILESS_MAIN(TestModel)
#include "tst_logmodel.moc"
