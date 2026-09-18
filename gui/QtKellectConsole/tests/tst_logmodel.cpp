#include <QtTest>
#include "ui/LogModel.h"
#include "domain/LogEntry.h"

class TestModel : public QObject { Q_OBJECT
private slots:
    void appendGrowsRowCount();
    void trimRemovesOldestBatch();
    void toggleMark();
    void searchRoleConcatenatesDisplayFields();
};

void TestModel::appendGrowsRowCount() {
    LogModel m;
    QCOMPARE(m.rowCount(), 0);
    m.append({ QDateTime::currentDateTime(), "x", false });
    QCOMPARE(m.rowCount(), 1);
}
void TestModel::trimRemovesOldestBatch() {
    LogModel m;
    for (int i = 0; i < kMaxLines + 1; ++i)
        m.append({ QDateTime::currentDateTime(), QString::number(i), false });
    m.trimIfFull();
    QCOMPARE(m.rowCount(), kMaxLines + 1 - kTrimBatch); // 45001
}
void TestModel::toggleMark() {
    LogModel m;
    m.append({ QDateTime::currentDateTime(), "a", false });
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), true);
    m.toggleMark(0);
    QCOMPARE(m.data(m.index(0), LogModel::MarkedRole).toBool(), false);
}
void TestModel::searchRoleConcatenatesDisplayFields() {
    LogModel m;
    LogEntry e;
    e.text = QStringLiteral(R"({"Event":"Process","PID":1234,"PName":"chrome.exe","OpenPath":"C:\\x"})");
    e.event = QStringLiteral("Process");
    e.pid = QStringLiteral("1234");
    e.pname = QStringLiteral("chrome.exe");
    e.detail = QStringLiteral("OpenPath=C:\\x");
    m.append(e);
    const QString search = m.data(m.index(0), LogModel::SearchRole).toString();
    // 显示四字段都进搜索串
    QVERIFY(search.contains("Process"));
    QVERIFY(search.contains("1234"));
    QVERIFY(search.contains("chrome.exe"));
    QVERIFY(search.contains("OpenPath"));
    // 关键契约:不含原始 JSON 文本/key 名,避免输入 "PID"/"Event" 命中所有行
    QVERIFY(!search.contains("\"PID\""));
    QVERIFY(!search.contains("\"Event\""));
    QVERIFY(!search.contains(e.text));
}

QTEST_GUILESS_MAIN(TestModel)
#include "tst_logmodel.moc"
