#include <QtTest>
#include <QColor>
#include "ui/EventColor.h"

class TestColor : public QObject { Q_OBJECT
private slots:
    void prefixMapping();
    void unknownIsNone();
    void domainColorsDiffer();
};

void TestColor::prefixMapping() {
    QCOMPARE(domainOfEvent("ProcessStart"),  EventDomain::Process);
    QCOMPARE(domainOfEvent("ThreadStart"),   EventDomain::Thread);
    QCOMPARE(domainOfEvent("ImageLoad"),     EventDomain::Image);
    QCOMPARE(domainOfEvent("FileIOCreate"),  EventDomain::File);
    QCOMPARE(domainOfEvent("DiskIORead"),    EventDomain::Disk);
    QCOMPARE(domainOfEvent("RegistryCreate"),EventDomain::Registry);
    QCOMPARE(domainOfEvent("TcpIpConnect"),  EventDomain::TcpIp);
    QCOMPARE(domainOfEvent("CallStack"),     EventDomain::CallStack);
}
void TestColor::unknownIsNone() {
    QCOMPARE(domainOfEvent(""),            EventDomain::None);
    QCOMPARE(domainOfEvent("WeirdEvent"),  EventDomain::None);
}
void TestColor::domainColorsDiffer() {
    QVERIFY(textColor(EventDomain::File) != textColor(EventDomain::Process));
}

QTEST_GUILESS_MAIN(TestColor)
#include "tst_eventcolor.moc"
