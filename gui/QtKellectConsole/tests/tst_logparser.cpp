#include <QtTest>
#include "domain/LogParser.h"

class TestLogParser : public QObject { Q_OBJECT
private slots:
    void processLine();                 // (a) ProcessId 键 + PName + 优先级字段
    void fileIoNestedArgs();            // (b) 嵌套 args 对象被字符串化为 args={...}
    void malformedUnescapedBackslash(); // (c) 非法 JSON:正则仍取 event/pid/pname,detail=raw
    void hideNoiseFields();             // (d) PPID/PPName/Host-UUID/TimeStamp 不出现
    void nonJsonGarbage();              // (e) 非 JSON:event/pid/pname 空,detail=raw
    void emptyString();                 // (f) 空串不崩
    void pidKeyPriority();              // (g) 回归:"PID" 键(TcpIp 类)
};

// (a) 进程类事件:pid 来自 ProcessId;CommandLine/ImageFileName 按优先级出现,PPID/PPName 隐藏。
void TestLogParser::processLine() {
    const QString raw = "{\"Event\":\"ProcessStart\",\"ProcessId\":1234,"
                        "\"PName\":\"cmd.exe\",\"CommandLine\":\"notepad\","
                        "\"ImageFileName\":\"C:\\\\windows\\\\notepad.exe\","
                        "\"PPID\":5678,\"PPName\":\"explorer.exe\"}";
    const auto p = parseKellectLine(raw);
    QCOMPARE(p.event, QStringLiteral("ProcessStart"));
    QCOMPARE(p.pid,  QStringLiteral("1234"));          // 来自 ProcessId
    QCOMPARE(p.pname, QStringLiteral("cmd.exe"));
    QVERIFY(p.detail.contains(QStringLiteral("CommandLine=notepad")));
    QVERIFY(p.detail.contains(QStringLiteral("ImageFileName=C:\\windows\\notepad.exe")));
    QVERIFY(!p.detail.contains(QStringLiteral("PPID=")));     // 隐藏
    QVERIFY(!p.detail.contains(QStringLiteral("PPName=")));   // 隐藏
    // 优先级:CommandLine 排在 ImageFileName 之前
    QVERIFY(p.detail.indexOf(QStringLiteral("CommandLine")) >= 0);
    QVERIFY(p.detail.indexOf(QStringLiteral("CommandLine"))
            < p.detail.indexOf(QStringLiteral("ImageFileName")));
}

// (b) FileIO 类带嵌套 args 对象 → 字符串化为 args={...},而非空串。
void TestLogParser::fileIoNestedArgs() {
    const QString raw = "{\"Event\":\"FileIOCreate\",\"PID\":2744,\"PName\":\"x.exe\","
                        "\"args\":{\"OpenPath\":\"C:\\\\x\",\"ShareAccess\":3}}";
    const auto p = parseKellectLine(raw);
    QCOMPARE(p.event, QStringLiteral("FileIOCreate"));
    QCOMPARE(p.pid,  QStringLiteral("2744"));
    QCOMPARE(p.pname, QStringLiteral("x.exe"));
    QVERIFY(p.detail.contains(QStringLiteral("args={")));
    QVERIFY(p.detail.contains(QStringLiteral("OpenPath")));
    QVERIFY(p.detail.contains(QStringLiteral("ShareAccess")));
}

// (c) kellect 真实缺陷:Windows 路径反斜杠未转义 → 整体 JSON 非法。
//     正则仍取 event/pid/pname(前三列对齐);detail 走全局正则容错抽取,
//     显示成解析后的 key=value(OpenPath/ShareAccess),而非整行原文。
void TestLogParser::malformedUnescapedBackslash() {
    const QString raw = "{\"Event\":\"FileIOCreate\",\"PID\":2744,\"PName\":\"x.exe\","
                        "\"args\":{\"OpenPath\":\"C:\\\",\"ShareAccess\":3}}";
    const auto p = parseKellectLine(raw);
    QCOMPARE(p.event, QStringLiteral("FileIOCreate"));   // 正则抽取
    QCOMPARE(p.pid,  QStringLiteral("2744"));
    QCOMPARE(p.pname, QStringLiteral("x.exe"));
    QVERIFY(p.detail.contains(QStringLiteral("OpenPath=")));    // 容错抽到,非整行原文
    QVERIFY(p.detail.contains(QStringLiteral("ShareAccess=")));
    QVERIFY(p.detail != raw);                              // 不再回退整行
}

// (d) 噪音字段不进 detail(仅在双击详情对话框的原始 JSON 里可见)。
void TestLogParser::hideNoiseFields() {
    const QString raw = "{\"Event\":\"ProcessStart\",\"PID\":1,\"PName\":\"a.exe\","
                        "\"PPID\":2,\"PPName\":\"b.exe\",\"Host-UUID\":\"uuid\","
                        "\"TimeStamp\":\"2024-01-01\"}";
    const auto p = parseKellectLine(raw);
    QCOMPARE(p.event, QStringLiteral("ProcessStart"));
    QVERIFY(!p.detail.contains(QStringLiteral("PPID=")));
    QVERIFY(!p.detail.contains(QStringLiteral("PPName=")));
    QVERIFY(!p.detail.contains(QStringLiteral("Host-UUID=")));
    QVERIFY(!p.detail.contains(QStringLiteral("TimeStamp=")));
}

// (e) 非 JSON 行:event/pid/pname 为空,整行作为 detail。
void TestLogParser::nonJsonGarbage() {
    const QString raw = QStringLiteral("this is not json at all");
    const auto p = parseKellectLine(raw);
    QVERIFY(p.event.isEmpty());
    QVERIFY(p.pid.isEmpty());
    QVERIFY(p.pname.isEmpty());
    QCOMPARE(p.detail, raw);
}

// (f) 空串:不崩溃,优雅返回。
void TestLogParser::emptyString() {
    const auto p = parseKellectLine(QString());
    QVERIFY(p.event.isEmpty());
    QVERIFY(p.pid.isEmpty());
    QVERIFY(p.pname.isEmpty());
    QVERIFY(p.detail.isEmpty());
}

// (g) 回归:TcpIp 类带 "PID" 键。
void TestLogParser::pidKeyPriority() {
    const QString raw = "{\"Event\":\"TcpIpConnect\",\"PID\":4321,\"Remote\":\"1.2.3.4\"}";
    const auto p = parseKellectLine(raw);
    QCOMPARE(p.event, QStringLiteral("TcpIpConnect"));
    QCOMPARE(p.pid,  QStringLiteral("4321"));
    QVERIFY(p.detail.contains(QStringLiteral("Remote=1.2.3.4")));
}

QTEST_GUILESS_MAIN(TestLogParser)
#include "tst_logparser.moc"
