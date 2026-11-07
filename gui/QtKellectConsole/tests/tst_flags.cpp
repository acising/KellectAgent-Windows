// tests/tst_flags.cpp
#include <QtTest>
#include "domain/Flags.h"

using namespace kellect; // 局部 using,安全(不污染其他 TU);Flags.h 本身不含 using namespace

class TestFlags : public QObject { Q_OBJECT
private slots:
    void buildMaskCombinesBits();
    void buildMaskEmptyIsZero();
    void maskToHexFormat();
    void buildKellectArgsFormat();
};

void TestFlags::buildMaskCombinesBits() {
    QCOMPARE(buildMask({EventFlag::Process, EventFlag::File}), quint8(0x01 | 0x08));
}
void TestFlags::buildMaskEmptyIsZero() {
    QCOMPARE(buildMask({}), quint8(0));
}
void TestFlags::maskToHexFormat() {
    QCOMPARE(maskToHex(0x1F), QString("0x1F"));
    QCOMPARE(maskToHex(0x00), QString("0x00"));
}
void TestFlags::buildKellectArgsFormat() {
    QCOMPARE(buildKellectArgs(0x1F), QStringList({"-e", "0x1F", "-c"}));
}

QTEST_GUILESS_MAIN(TestFlags)
#include "tst_flags.moc"
