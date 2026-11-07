#include <QtTest>
#include "domain/Preset.h"
#include "domain/Flags.h"

using namespace kellect; // 局部 using,安全(不污染其他 TU);Preset.h/Flags.h 本身不含 using namespace

class TestPreset : public QObject { Q_OBJECT
private slots:
    void defaultsNonEmpty();
    void allPresetCoversEveryFlag();
    void minimalPresetMask();
};

void TestPreset::defaultsNonEmpty() {
    QVERIFY(!defaultPresets().isEmpty());
}
void TestPreset::allPresetCoversEveryFlag() {
    Preset all;
    for (const auto& p : defaultPresets())
        if (p.name == "全部") all = p;
    quint8 m = buildMask(all.flags);
    QCOMPARE(m, quint8(0xFF));
}
void TestPreset::minimalPresetMask() {
    Preset p;
    for (const auto& x : defaultPresets())
        if (x.name == "精简") p = x;
    QCOMPARE(buildMask(p.flags), quint8(EventFlag::Process | EventFlag::File));
}

QTEST_GUILESS_MAIN(TestPreset)
#include "tst_preset.moc"
