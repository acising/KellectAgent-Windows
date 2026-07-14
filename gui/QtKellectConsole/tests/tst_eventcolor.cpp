#include <QtTest>
#include <QColor>
#include "ui/EventColor.h"

class TestColor : public QObject { Q_OBJECT
private slots:
    void prefixMapping();
    void unknownIsNone();
    void decodeErrorOverridesColor();
};

void TestColor::prefixMapping() {
    QCOMPARE(domainOfEvent("ProcessStart"),  EventDomain::Process);
    QCOMPARE(domainOfEvent("ThreadStart"),   EventDomain::Thread);
    QCOMPARE(domainOfEvent("ImageLoad"),     EventDomain::Image);
    QCOMPARE(domainOfEvent("FileIOCreate"),  EventDomain::File);
    QCOMPARE(domainOfEvent("DiskIORead"),    EventDomain::Disk);
    QCOMPARE(domainOfEvent("RegistryCreate"),EventDomain::Registry);
    QCOMPARE(domainOfEvent("TcpIpConnect"),  EventDomain::TcpIp);
}
void TestColor::unknownIsNone() {
    QCOMPARE(domainOfEvent(""),            EventDomain::None);
    QCOMPARE(domainOfEvent("WeirdEvent"),  EventDomain::None);
}
void TestColor::decodeErrorOverridesColor() {
    QColor normal = textColor(EventDomain::File, false);
    QColor errored = textColor(EventDomain::File, true);
    QCOMPARE(errored, QColor("#E07070")); // 解码异常固定红
    QVERIFY(normal != errored);
}

QTEST_GUILESS_MAIN(TestColor)
#include "tst_eventcolor.moc"
