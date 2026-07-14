#include <QtTest>
#include "domain/Utf8Accumulator.h"

class TestUtf8 : public QObject { Q_OBJECT
private slots:
    void asciiLine();
    void validMultibyte();
    void invalidBytesCounted();
    void splitMultibyteAcrossFeeds();
    void skipsBom();
};

void feedLine(Utf8Accumulator& a, const QByteArray& bytes, QString& got) {
    a.feed(bytes);
    QString line;
    while (a.takeLine(line)) got = line;
}

void TestUtf8::asciiLine() {
    Utf8Accumulator a; QString line;
    feedLine(a, "hello\n", line);
    QCOMPARE(line, QString("hello"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::validMultibyte() {
    Utf8Accumulator a; QString line;
    // "中文" in valid UTF-8
    feedLine(a, QString("中文").toUtf8() + "\n", line);
    QCOMPARE(line, QString("中文"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::invalidBytesCounted() {
    Utf8Accumulator a; QString line;
    // 0xC4 0xE3 = "你" in GBK, illegal as UTF-8 lead/continuation mix
    feedLine(a, QByteArray("\xC4\xE3\n"), line);
    QVERIFY(line.contains(QChar(0xFFFD)));
    QCOMPARE(a.errorCount(), 2); // each stray byte is one replacement
}
void TestUtf8::splitMultibyteAcrossFeeds() {
    Utf8Accumulator a; QString line;
    QByteArray whole = QString("中").toUtf8() + "\n"; // 3 bytes + \n
    a.feed(whole.left(2));      // partial
    QVERIFY(!a.takeLine(line));
    a.feed(whole.mid(2));       // remainder + newline
    while (a.takeLine(line)) {}
    QCOMPARE(line, QString("中"));
    QCOMPARE(a.errorCount(), 0);
}
void TestUtf8::skipsBom() {
    Utf8Accumulator a; QString line;
    feedLine(a, QByteArray("\xEF\xBB\xBF") + "x\n", line);
    QCOMPARE(line, QString("x"));
    QCOMPARE(a.errorCount(), 0);
}

QTEST_GUILESS_MAIN(TestUtf8)
#include "tst_utf8accumulator.moc"
