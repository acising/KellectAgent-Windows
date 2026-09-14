// src/process/WindowsServiceClient.h
// Qt-friendly wrapper around the Windows Service Control Manager for the
// "KellectService" host. When the GUI's "Run as Windows Service" mode is on,
// MainWindow uses this instead of spawning kellect.exe directly:
//   start: installRegistryConfig() pushes the chosen output settings to
//          HKLM\SOFTWARE\Kellect\Service, then start() brings the service up.
//   stop:  stop() sends SERVICE_CONTROL_STOP.
// The service binary's ServiceConfig::Load reads the same registry keys, so the
// GUI and the service share one configuration contract.
//
// Handles are opened/closed per operation (cheap, avoids lifecycle bugs), so
// this header needs no <windows.h>. A 1 s QTimer polls state -> stateChanged.
#pragma once
#include <QObject>
#include <QString>
#include <QTimer>
#include <QtGlobal>
#include <functional>

namespace kellect {

class WindowsServiceClient : public QObject {
    Q_OBJECT
public:
    enum class State {
        NotInstalled,
        Stopped,
        StartPending,
        Running,
        StopPending,
        Unknown
    };
    Q_ENUM(State)

    // Output configuration pushed to the registry so the service picks it up.
    // outputMode is "file" | "socket" | "kafka" (the service rejects "console").
    struct OutputConfig {
        QString outputMode;
        QString eventMask   = QStringLiteral("0xFF");
        QString outputFile;
        QString socketHost;
        quint16 socketPort  = 0;
        QString kafkaBroker;   // "host:port"
        QString kafkaTopic;
        QString exePath;       // optional override (empty -> beside service exe)
        QString workDir;       // optional override
    };

    explicit WindowsServiceClient(QString serviceName =
                                      QStringLiteral("KellectService"),
                                  QObject* parent = nullptr);
    ~WindowsServiceClient() override;

    // Update the target service name (e.g. after settings load). Safe to call
    // any time — handles are opened per operation, never cached.
    void setServiceName(const QString& name) { serviceName_ = name; }

    WindowsServiceClient(const WindowsServiceClient&) = delete;
    WindowsServiceClient& operator=(const WindowsServiceClient&) = delete;

    // Quiet probe (no signals). True if the service is registered with the SCM.
    bool isInstalled();

    // Synchronous state query (quiet; emits nothing). NotInstalled if absent.
    State state();

    // Pure helpers exposed for unit testing the SCM polling control flow.
    // mapDwordState: SERVICE_* DWORD -> State.
    static State mapDwordState(unsigned long dwCurrentState);
    // pollStates: drive a state provider until target is reached, abortState is
    // hit (abortState==0 disables the abort check), or timeoutMs elapses. On
    // timeout returns the last queried state (the service's real current state).
    // Spins the event loop between checks so callers stay responsive.
    static State pollStates(const std::function<unsigned long()>& nextDwordState,
                            unsigned long targetState, unsigned long abortState,
                            int timeoutMs, int pollMs = 200);

    // Drive the service to Running / Stopped, polling (spinning the event loop
    // so the UI stays responsive) until the target is reached or timeoutMs.
    // Returns the final state; may emit stateChanged / errorOccurred.
    State start(int timeoutMs = 15000);
    State stop(int timeoutMs = 15000);

    // Periodic state-poll timer (default 1 s) -> stateChanged.
    void startPolling(int intervalMs = 1000);
    void stopPolling();

    // Registry config push (static — independent of any service instance).
    static bool installRegistryConfig(const OutputConfig& cfg);
    static bool clearRegistryConfig();

signals:
    void stateChanged(kellect::WindowsServiceClient::State newState);
    void errorOccurred(const QString& message);

private slots:
    void poll();

private:
    void emitIfChanged(State s);

    QString serviceName_;
    QTimer   pollTimer_;
    State    lastState_ = State::Unknown;
};

} // namespace kellect
