#include "channel/probe_channel.h"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <ctime>
#include <fstream>
#include <map>
#include <random>

#include "channel/msgpack.h"
#include "runtime/collector.h"
#include "schema/schema.h"
#include "tools/stats.h"

namespace kellect {
namespace channel {

const char* const kAgentVersion = "1.0.0";

namespace {

using nlohmann::json;

std::string Trim(const std::string& s) {
    size_t b = s.find_first_not_of(" \t\r\n");
    if (b == std::string::npos) return std::string();
    size_t e = s.find_last_not_of(" \t\r\n");
    return s.substr(b, e - b + 1);
}

std::string Lower(const std::string& s) {
    std::string out = s;
    std::transform(out.begin(), out.end(), out.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// Trailing "; comment" / "# comment" after a value, as used in the sample ini.
std::string StripInlineComment(const std::string& v) {
    for (size_t i = 1; i < v.size(); ++i) {
        if (v[i] == ';' || v[i] == '#') {
            const char prev = v[i - 1];
            if (prev == ' ' || prev == '\t')
                return Trim(v.substr(0, i));
        }
    }
    return v;
}

size_t ToSize(const std::string& v, size_t fallback) {
    try {
        const long long parsed = std::stoll(v);
        return parsed > 0 ? static_cast<size_t>(parsed) : fallback;
    } catch (...) {
        return fallback;
    }
}

int ToInt(const std::string& v, int fallback) {
    try { return std::stoi(v); } catch (...) { return fallback; }
}

bool ToBool(const std::string& v) {
    const std::string lower = Lower(Trim(v));
    return lower == "1" || lower == "true" || lower == "yes" || lower == "on";
}

std::string IsoNow() {
    SYSTEMTIME st;
    GetSystemTime(&st);   // UTC
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%04u-%02u-%02uT%02u:%02u:%02u.%03u+00:00",
             static_cast<unsigned>(st.wYear), static_cast<unsigned>(st.wMonth),
             static_cast<unsigned>(st.wDay), static_cast<unsigned>(st.wHour),
             static_cast<unsigned>(st.wMinute), static_cast<unsigned>(st.wSecond),
             static_cast<unsigned>(st.wMilliseconds));
    return buffer;
}

// The kernel session uses Wnode.ClientContext = 2, so EventHeader.TimeStamp is
// a FILETIME (100ns units since 1601-01-01Z). Convert it to the protocol's
// preferred ISO 8601 UTC form so range queries and daily shards line up with
// the backend's string comparison.
std::string FileTimeToIso(uint64_t fileTime) {
    constexpr uint64_t kEpochDiff = 116444736000000000ull;   // 1601 -> 1970
    if (fileTime <= kEpochDiff)
        return IsoNow();

    const uint64_t delta = fileTime - kEpochDiff;
    const time_t seconds = static_cast<time_t>(delta / 10000000ull);
    const unsigned fraction = static_cast<unsigned>((delta % 10000000ull) / 10000ull);

    struct tm utc;
    if (gmtime_s(&utc, &seconds) != 0)
        return IsoNow();

    char date[32];
    strftime(date, sizeof(date), "%Y-%m-%dT%H:%M:%S", &utc);
    char buffer[64];
    snprintf(buffer, sizeof(buffer), "%s.%03u+00:00", date, fraction);
    return buffer;
}

std::string RandomHex(size_t bytes) {
    static const char* digits = "0123456789abcdef";
    std::random_device device;
    std::mt19937_64 generator((static_cast<uint64_t>(device()) << 32) ^ device());
    std::string out;
    out.reserve(bytes * 2);
    for (size_t i = 0; i < bytes; ++i) {
        const unsigned char value = static_cast<unsigned char>(generator() & 0xff);
        out.push_back(digits[value >> 4]);
        out.push_back(digits[value & 0x0f]);
    }
    return out;
}

// Kellect strings come from ETW as raw bytes (ANSI/GBK paths, command lines).
// MessagePack `str` is decoded as UTF-8 by the backend, so invalid sequences
// would make the whole frame `bad_frame`. Replace bad bytes with U+FFFD rather
// than dropping the event.
std::string ToValidUtf8(const std::string& in) {
    std::string out;
    out.reserve(in.size());
    size_t i = 0;
    while (i < in.size()) {
        const unsigned char c = static_cast<unsigned char>(in[i]);
        size_t length = 0;
        if (c < 0x80) length = 1;
        else if ((c & 0xE0) == 0xC0) length = 2;
        else if ((c & 0xF0) == 0xE0) length = 3;
        else if ((c & 0xF8) == 0xF0) length = 4;

        bool valid = length != 0 && i + length <= in.size();
        if (valid) {
            for (size_t k = 1; k < length; ++k) {
                if ((static_cast<unsigned char>(in[i + k]) & 0xC0) != 0x80) {
                    valid = false;
                    break;
                }
            }
        }

        if (valid) {
            out.append(in, i, length);
            i += length;
        } else {
            out += "\xEF\xBF\xBD";
            ++i;
        }
    }
    return out;
}

std::string GetHostname() {
    char buffer[MAX_COMPUTERNAME_LENGTH + 1] = { 0 };
    DWORD size = static_cast<DWORD>(sizeof(buffer));
    if (!GetComputerNameA(buffer, &size))
        return "windows-host";
    return std::string(buffer, size);
}

// Kellect event name -> (category, type). Categories follow the backend's
// documented set: process / network / file / auth / system.
std::pair<std::string, std::string> MapEvent(const std::string& name) {
    static const std::map<std::string, std::pair<std::string, std::string>> table = {
        { "ProcessStart",       { "process", "exec" } },
        { "ProcessDCStart",     { "process", "exec" } },
        { "ProcessEnd",         { "process", "exit" } },
        { "ProcessDCEnd",       { "process", "exit" } },
        { "ProcessDefunct",     { "process", "exit" } },
        { "ProcessPerfCtr",     { "process", "perf" } },
        { "ProcessPerfCtrRundown", { "process", "perf" } },
        { "ThreadStart",        { "process", "thread_start" } },
        { "ThreadDCStart",      { "process", "thread_start" } },
        { "ThreadEnd",          { "process", "thread_exit" } },
        { "ThreadDCEnd",        { "process", "thread_exit" } },
        { "ThreadCSwitch",      { "process", "switch" } },
        { "ImageLoad",          { "system",  "image_load" } },
        { "ImageDCStart",       { "system",  "image_load" } },
        { "ImageUnload",        { "system",  "image_unload" } },
        { "ImageDCEnd",         { "system",  "image_unload" } },
        { "CallStack",          { "system",  "callstack" } },
        { "FileIOCreate",       { "file",    "open" } },
        { "FileIOFileCreate",   { "file",    "create" } },
        { "FileIOWrite",        { "file",    "write" } },
        { "FileIORead",         { "file",    "read" } },
        { "FileIORename",       { "file",    "rename" } },
        { "FileIODelete",       { "file",    "unlink" } },
        { "FileIOFileDelete",   { "file",    "unlink" } },
        { "FileIOClose",        { "file",    "close" } },
        { "FileIOCleanup",      { "file",    "close" } },
        { "FileIOFlush",        { "file",    "flush" } },
        { "FileIOSetInfo",      { "file",    "setinfo" } },
        { "FileIOQueryInfo",    { "file",    "queryinfo" } },
        { "FileIOFSControl",    { "file",    "fscontrol" } },
        { "FileIODirEnum",      { "file",    "direnum" } },
        { "FileIODirNotify",    { "file",    "dirnotify" } },
        { "FileIOName",         { "file",    "name" } },
        { "FileIOFileRundown",  { "file",    "rundown" } },
        { "FileIOOperationEnd", { "file",    "operation_end" } },
        { "TcpIpConnectIPV4",   { "network", "connect" } },
        { "TcpIpConnectIPV6",   { "network", "connect" } },
        { "TcpIpAcceptIPV4",    { "network", "accept" } },
        { "TcpIpAcceptIPV6",    { "network", "accept" } },
        { "TcpIpSendIPV4",      { "network", "send" } },
        { "TcpIpSendIPV6",      { "network", "send" } },
        { "TcpIpRecvIPV4",      { "network", "recv" } },
        { "TcpIpRecvIPV6",      { "network", "recv" } },
        { "TcpIpDisconnectIPV4",{ "network", "disconnect" } },
        { "TcpIpDisconnectIPV6",{ "network", "disconnect" } },
        { "TcpIpRetransmitIPV4",{ "network", "retransmit" } },
        { "TcpIpRetransmitIPV6",{ "network", "retransmit" } },
        { "TcpIpTCPCopyIPV4",   { "network", "copy" } },
        { "TcpIpTCPCopyIPV6",   { "network", "copy" } },
        { "TcpIpReconnectIPV4", { "network", "reconnect" } },
        { "TcpIpReconnectIPV6", { "network", "reconnect" } },
        { "TcpIpFailed",        { "network", "failed" } },
    };

    auto it = table.find(name);
    if (it != table.end())
        return it->second;
    if (name.compare(0, 8, "Registry") == 0)
        return std::make_pair(std::string("system"), "registry_" + Lower(name.substr(8)));
    if (name.compare(0, 6, "FileIO") == 0)
        return std::make_pair(std::string("file"), Lower(name.substr(6)));
    if (name.compare(0, 6, "TcpIp") == 0)
        return std::make_pair(std::string("network"), Lower(name.substr(6)));
    return std::make_pair(std::string("system"), Lower(name));
}

// MessagePack has no JSON object type: walk the JSON tree and encode primitives
// natively (the backend unpacks with raw=False and expects real maps/arrays).
void WriteJson(msgpack::Writer& w, const json& value) {
    if (value.is_null()) {
        w.Nil();
    } else if (value.is_boolean()) {
        w.Bool(value.get<bool>());
    } else if (value.is_number_unsigned()) {
        w.UInt(value.get<uint64_t>());
    } else if (value.is_number_integer()) {
        w.Int(value.get<int64_t>());
    } else if (value.is_number_float()) {
        w.Double(value.get<double>());
    } else if (value.is_string()) {
        w.Str(ToValidUtf8(value.get_ref<const std::string&>()));
    } else if (value.is_array()) {
        w.Array(static_cast<uint32_t>(value.size()));
        for (const auto& item : value)
            WriteJson(w, item);
    } else if (value.is_object()) {
        w.Map(static_cast<uint32_t>(value.size()));
        for (auto it = value.begin(); it != value.end(); ++it) {
            w.Str(it.key());
            WriteJson(w, it.value());
        }
    } else {
        w.Nil();
    }
}

json BuildPayload(const json& ev, const std::string& name, const std::string& category) {
    json payload = json::object();
    payload["event"] = name;
    if (ev.contains("PID")) payload["pid"] = ev["PID"];
    if (ev.contains("PPID")) payload["ppid"] = ev["PPID"];
    if (ev.contains("PName")) payload["comm"] = ev["PName"];
    if (ev.contains("TID")) payload["tid"] = ev["TID"];
    if (ev.contains("Host-UUID")) payload["host_uuid"] = ev["Host-UUID"];

    if (!ev.contains("args") || !ev["args"].is_object())
        return payload;

    const json& args = ev["args"];
    payload["args"] = args;

    // Curated aliases so backend consumers do not have to know the Windows
    // MOF field names. Everything is still available under payload.args.
    if (category == "process") {
        if (args.contains("ImageFileName")) payload["image"] = args["ImageFileName"];
        if (args.contains("CommandLine")) payload["argv"] = args["CommandLine"];
        if (args.contains("UserSID")) payload["user"] = args["UserSID"];
        if (args.contains("SessionId")) payload["session_id"] = args["SessionId"];
        if (args.contains("ExitStatus")) payload["exit_status"] = args["ExitStatus"];
    } else if (category == "file") {
        if (args.contains("FileName")) payload["path"] = args["FileName"];
        else if (args.contains("OpenPath")) payload["path"] = args["OpenPath"];
        if (args.contains("IoSize")) payload["size"] = args["IoSize"];
        else if (args.contains("Length")) payload["size"] = args["Length"];
        else if (args.contains("TransferSize")) payload["size"] = args["TransferSize"];
    } else if (category == "network") {
        payload["protocol"] = "tcp";
        if (args.contains("saddr")) payload["src_addr"] = args["saddr"];
        if (args.contains("sport")) payload["src_port"] = args["sport"];
        if (args.contains("daddr")) payload["dst_addr"] = args["daddr"];
        if (args.contains("dport")) payload["dst_port"] = args["dport"];
        if (args.contains("size")) payload["bytes"] = args["size"];
    } else if (category == "system") {
        if (args.contains("KeyName")) payload["key"] = args["KeyName"];
        if (args.contains("Status")) payload["status"] = args["Status"];
        if (args.contains("FileName") && name.find("Image") != std::string::npos)
            payload["image"] = args["FileName"];
        if (args.contains("ImageBase")) payload["image_base"] = args["ImageBase"];
        if (args.contains("ImageSize")) payload["image_size"] = args["ImageSize"];
    }
    return payload;
}

} // namespace

bool LoadProbeConfig(const std::string& path, ProbeConfig& cfg, std::string& error) {
    cfg.configPath = path;

    std::ifstream in(path);
    if (!in.is_open())
        return true;   // CLI flags may supply everything

    std::string line;
    int lineNo = 0;
    while (std::getline(in, line)) {
        ++lineNo;
        line = Trim(line);
        if (line.empty() || line[0] == '#' || line[0] == ';')
            continue;
        if (line[0] == '[')
            continue;   // sections are documentation sugar for this small file

        const size_t eq = line.find('=');
        if (eq == std::string::npos) {
            error = "line " + std::to_string(lineNo) + ": expected key=value";
            return false;
        }
        const std::string key = Lower(Trim(line.substr(0, eq)));
        const std::string value = StripInlineComment(Trim(line.substr(eq + 1)));

        if (key == "url") cfg.url = value;
        else if (key == "probe_id" || key == "probeid") cfg.probeId = value;
        else if (key == "token") cfg.token = value;
        else if (key == "hostname") cfg.hostname = value;
        else if (key == "platform") cfg.platform = value;
        else if (key == "queue") cfg.queueCapacity = ToSize(value, cfg.queueCapacity);
        else if (key == "batch") cfg.batchEvents = ToSize(value, cfg.batchEvents);
        else if (key == "batch_bytes") cfg.batchBytes = ToSize(value, cfg.batchBytes);
        else if (key == "rate") cfg.ratePerSecond = ToInt(value, cfg.ratePerSecond);
        else if (key == "verbose") cfg.verbose = ToBool(value);
    }

    if (cfg.batchEvents == 0) cfg.batchEvents = 200;
    if (cfg.batchEvents > 500) cfg.batchEvents = 500;          // protocol hard limit
    if (cfg.queueCapacity == 0) cfg.queueCapacity = 20000;
    return true;
}

ProbeChannel::ProbeChannel(const ProbeConfig& cfg) : cfg_(cfg) {
    if (cfg_.batchEvents == 0) cfg_.batchEvents = 200;
    if (cfg_.batchEvents > 500) cfg_.batchEvents = 500;
    if (cfg_.queueCapacity == 0) cfg_.queueCapacity = 20000;
    if (cfg_.batchBytes == 0) cfg_.batchBytes = 512 * 1024;
    batchEvents_.store(cfg_.batchEvents);
}

ProbeChannel::~ProbeChannel() {
    requestStop();
    client_.Close();
    if (worker_.joinable())
        worker_.join();
}

STATUS ProbeChannel::init() {
    startedAt_ = std::chrono::steady_clock::now();
    rateWindowStart_ = startedAt_;
    rate_.store(cfg_.ratePerSecond);

    hostname_ = cfg_.hostname.empty() ? GetHostname() : cfg_.hostname;
    osVersion_ = kellect::schema::DetectOs().displayName;
    bootId_ = RandomHex(6);

    // The worker owns connect/hello/send/reconnect; the base Output thread only
    // feeds the bounded queue through output().
    worker_ = std::thread(&ProbeChannel::Worker, this);
    setInit(true);
    return STATUS_SUCCESS;
}

void ProbeChannel::output(std::string outputString) {
    size_t start = 0;
    while (start < outputString.size()) {
        const size_t newline = outputString.find('\n', start);
        std::string line = outputString.substr(
            start, (newline == std::string::npos ? outputString.size() : newline) - start);
        start = (newline == std::string::npos) ? outputString.size() : newline + 1;
        if (line.empty())
            continue;

        if (paused_.load()) {
            droppedPaused_.fetch_add(1);
            continue;
        }

        std::lock_guard<std::mutex> lock(queueMutex_);
        if (!TakeRateTokenLocked()) {
            droppedRate_.fetch_add(1);
            continue;
        }
        Enqueue(std::move(line));
    }
}

bool ProbeChannel::TakeRateTokenLocked() {
    const int rate = rate_.load();
    if (rate <= 0)
        return true;

    const auto now = std::chrono::steady_clock::now();
    const double elapsed =
        std::chrono::duration<double>(now - rateWindowStart_).count();
    rateWindowStart_ = now;

    rateTokens_ = (std::min)(static_cast<double>(rate), rateTokens_ + elapsed * rate);
    if (rateTokens_ >= 1.0) {
        rateTokens_ -= 1.0;
        return true;
    }
    return false;
}

void ProbeChannel::Enqueue(std::string line) {
    // caller holds queueMutex_
    if (queue_.size() >= cfg_.queueCapacity) {
        queue_.pop_front();
        droppedQueue_.fetch_add(1);
    }
    queue_.push_back(std::move(line));
    queueCv_.notify_one();
}

void ProbeChannel::RequeueFront(std::deque<std::string>& leftovers) {
    if (leftovers.empty())
        return;
    std::lock_guard<std::mutex> lock(queueMutex_);
    // Put the unsent tail back in order, in front of newer events.
    for (auto it = leftovers.rbegin(); it != leftovers.rend(); ++it) {
        if (queue_.size() >= cfg_.queueCapacity) {
            droppedQueue_.fetch_add(1);
            continue;
        }
        queue_.push_front(std::move(*it));
    }
    queueCv_.notify_one();
}

std::vector<std::string> ProbeChannel::TakeBatch() {
    std::vector<std::string> batch;

    std::unique_lock<std::mutex> lock(queueMutex_);
    if (queue_.empty()) {
        queueCv_.wait_for(lock, std::chrono::milliseconds(200), [this] {
            return !queue_.empty() || ShouldStop();
        });
    }

    const size_t maxEvents = (std::min)(batchEvents_.load(), serverMaxEvents_);
    const size_t maxBytes = (std::min)(cfg_.batchBytes, serverMaxBytes_);

    size_t bytes = 0;
    while (!queue_.empty() && batch.size() < maxEvents) {
        const std::string& front = queue_.front();
        if (!batch.empty() && bytes + front.size() > maxBytes)
            break;
        bytes += front.size();
        batch.push_back(std::move(queue_.front()));
        queue_.pop_front();
    }
    return batch;
}

bool ProbeChannel::EncodeBatch(const std::vector<std::string>& raw, std::string& frame,
                               size_t& usedEvents, size_t& consumed) {
    std::vector<std::string> encoded;
    encoded.reserve(raw.size());

    const size_t maxEvents = (std::min)(batchEvents_.load(), serverMaxEvents_);
    const size_t budget = (std::min)(cfg_.batchBytes, serverMaxBytes_);

    size_t total = 0;
    consumed = 0;
    for (; consumed < raw.size(); ++consumed) {
        if (encoded.size() >= maxEvents)
            break;

        json ev = json::parse(raw[consumed], nullptr, false);
        if (ev.is_discarded() || !ev.is_object()) {
            parseErrors_.fetch_add(1);
            continue;   // consumed, but contributes no event
        }

        const std::string name = ev.value("Event", std::string("Unknown"));
        const auto mapping = MapEvent(name);

        json payload = BuildPayload(ev, name, mapping.first);

        std::string ts = IsoNow();
        if (ev.contains("TimeStamp") && ev["TimeStamp"].is_number_unsigned())
            ts = FileTimeToIso(ev["TimeStamp"].get<uint64_t>());

        const std::string eventId = cfg_.probeId + "-" + bootId_ + "-" +
                                    std::to_string(eventCounter_.fetch_add(1));

        msgpack::Writer w;
        w.Map(5);
        w.Str("event_id"); w.Str(eventId);
        w.Str("ts");       w.Str(ts);
        w.Str("category"); w.Str(mapping.first);
        w.Str("type");     w.Str(mapping.second);
        w.Str("payload");  WriteJson(w, payload);

        if (!encoded.empty() && total + w.Size() > budget)
            break;

        total += w.Size();
        encoded.push_back(w.Buffer());
    }

    if (encoded.empty()) {
        usedEvents = 0;
        return false;
    }

    msgpack::Writer frameWriter;
    frameWriter.Map(7);
    frameWriter.Str("v");          frameWriter.UInt(1);
    frameWriter.Str("probe_id");   frameWriter.Str(cfg_.probeId);
    frameWriter.Str("session_id"); frameWriter.Str(sessionId_);
    frameWriter.Str("seq");        frameWriter.UInt(seq_.load());
    frameWriter.Str("type");       frameWriter.Str("events");
    frameWriter.Str("sent_at");    frameWriter.Str(IsoNow());
    frameWriter.Str("events");     frameWriter.Array(static_cast<uint32_t>(encoded.size()));
    for (const std::string& bytes : encoded)
        frameWriter.Append(bytes);

    frame = frameWriter.Buffer();
    usedEvents = encoded.size();
    return true;
}

bool ProbeChannel::Hello(std::string& error) {
    json hello = {
        { "type", "hello" },
        { "protocol", 1 },
        { "probe_id", cfg_.probeId },
        { "token", cfg_.token },
        { "hostname", hostname_ },
        { "platform", cfg_.platform },
        { "os_version", osVersion_ },
        { "agent_version", kAgentVersion },
        { "boot_id", bootId_ },
        { "capabilities", json::array({ "process", "network", "file", "system" }) },
        { "backlog", static_cast<long long>(QueueDepth()) },
    };

    if (!client_.SendText(hello.dump(-1, ' ', false, json::error_handler_t::replace), error))
        return false;

    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(10);
    while (std::chrono::steady_clock::now() < deadline) {
        std::string payload;
        const ws::RxStatus status = client_.Receive(payload, error);
        if (status == ws::RxStatus::Timeout)
            continue;
        if (status != ws::RxStatus::Message) {
            if (error.empty()) error = "connection closed before hello_ack";
            return false;
        }

        json ack = json::parse(payload, nullptr, false);
        if (ack.is_discarded() || !ack.is_object())
            continue;

        const std::string type = ack.value("type", std::string());
        if (type == "hello_ack") {
            sessionId_ = ack.value("session_id", std::string());
            if (sessionId_.empty()) {
                error = "hello_ack without session_id";
                return false;
            }
            serverMaxEvents_ = static_cast<size_t>(ack.value("max_events_per_batch", 500));
            serverMaxBytes_ = static_cast<size_t>(ack.value("max_batch_bytes", 1048576));
            serverMaxEvents_ = (std::max)(static_cast<size_t>(1), (std::min)(serverMaxEvents_, static_cast<size_t>(500)));
            serverMaxBytes_ = (std::max)(static_cast<size_t>(4096), (std::min)(serverMaxBytes_, static_cast<size_t>(4 * 1024 * 1024)));
            seq_.store(0);
            return true;
        }
        if (type == "error") {
            error = ack.value("code", std::string("error")) + ": " +
                    ack.value("message", std::string());
            return false;
        }
    }

    error = "hello_ack timeout";
    return false;
}

void ProbeChannel::ReaderLoop() {
    while (!readerStop_.load() && client_.IsOpen()) {
        std::string payload;
        std::string error;
        const ws::RxStatus status = client_.Receive(payload, error);
        if (status == ws::RxStatus::Timeout)
            continue;
        if (status == ws::RxStatus::Message) {
            HandleControl(payload);
            continue;
        }
        if (!error.empty())
            RecordError(error);
        break;
    }
    // The socket is closed by the worker (sole owner); signalling here is what
    // makes the sender loop exit its 200 ms wait promptly.
    connectionLost_.store(true);
}

void ProbeChannel::HandleControl(const std::string& text) {
    json frame = json::parse(text, nullptr, false);
    if (frame.is_discarded() || !frame.is_object())
        return;

    const std::string type = frame.value("type", std::string());
    if (type == "ping") {
        std::string error;
        client_.SendText("{\"type\":\"pong\"}", error);
        return;
    }
    if (type == "command") {
        HandleCommand(frame);
        return;
    }
    if (type == "error") {
        const std::string code = frame.value("code", std::string());
        RecordError(code + ": " + frame.value("message", std::string()));
        // These codes mean the session is gone; the worker will reconnect.
        if (code == "unauthorized" || code == "probe_unknown" ||
            code == "protocol_unsupported" || code == "replaced" ||
            code == "heartbeat_timeout") {
            client_.Close();
        }
        return;
    }
    // ack / throttle / heartbeat are informational; delivery is fire-and-forget
    // per the protocol (ack does not mean persisted).
}

void ProbeChannel::HandleCommand(const json& frame) {
    const std::string commandId = frame.value("command_id", std::string());
    const std::string name = frame.value("name", std::string());
    json args = frame.contains("args") && frame["args"].is_object() ? frame["args"] : json::object();

    bool ok = true;
    json result = json::object();
    std::string errorText;

    if (name == "probe.info") {
        const auto uptime = std::chrono::duration_cast<std::chrono::seconds>(
            std::chrono::steady_clock::now() - startedAt_).count();
        result = {
            { "probe_id", cfg_.probeId },
            { "hostname", hostname_ },
            { "platform", cfg_.platform },
            { "os_version", osVersion_ },
            { "agent_version", kAgentVersion },
            { "protocol", 1 },
            { "boot_id", bootId_ },
            { "session_id", sessionId_ },
            { "uptime_s", static_cast<long long>(uptime) },
            { "queue_depth", static_cast<long long>(QueueDepth()) },
            { "sent_events", static_cast<long long>(sentEvents_.load()) },
            { "dropped", static_cast<long long>(DroppedTotal()) },
            { "paused", paused_.load() },
            { "rate", rate_.load() },
            { "events_received", static_cast<long long>(kellect::stats::eventsReceived.load()) },
            { "events_filtered", static_cast<long long>(kellect::stats::eventsFiltered.load()) },
            { "events_parsed", static_cast<long long>(kellect::stats::eventsParsed.load()) },
            { "events_queued", static_cast<long long>(kellect::stats::eventsQueued.load()) },
            { "etw_events_lost", static_cast<long long>(kellect::stats::etwEventsLost.load()) },
            { "schema_drift", static_cast<long long>(kellect::stats::schemaDrift.load()) },
        };
    } else if (name == "collect.set_rate") {
        const int rate = args.value("rate", 0);
        if (rate < 0) {
            ok = false;
            errorText = "rate must be >= 0";
        } else {
            rate_.store(rate);
            result = { { "rate", rate } };
        }
    } else if (name == "collect.start") {
        paused_.store(false);
        result = { { "paused", false } };
    } else if (name == "collect.stop") {
        paused_.store(true);
        result = { { "paused", true } };
    } else if (name == "probe.ping") {
        result = {
            { "pong", IsoNow() },
            { "queue_depth", static_cast<long long>(QueueDepth()) },
            { "paused", paused_.load() },
        };
    } else if (name == "config.update") {
        json applied = json::object();
        json ignored = json::array();
        for (auto it = args.begin(); it != args.end(); ++it) {
            if (it.key() == "rate" && it.value().is_number_integer()) {
                rate_.store(it.value().get<int>());
                applied["rate"] = it.value();
            } else if (it.key() == "paused" && it.value().is_boolean()) {
                paused_.store(it.value().get<bool>());
                applied["paused"] = it.value();
            } else if (it.key() == "batch" && it.value().is_number_integer()) {
                size_t batch = static_cast<size_t>(it.value().get<int>());
                batch = (std::max)(static_cast<size_t>(1), (std::min)(batch, static_cast<size_t>(500)));
                batchEvents_.store(batch);
                applied["batch"] = batch;
            } else {
                ignored.push_back(it.key());
            }
        }
        result = { { "applied", applied }, { "ignored", ignored } };
    } else {
        ok = false;
        errorText = "unsupported command: " + name;
    }

    json reply = {
        { "type", "command_result" },
        { "command_id", commandId },
        { "status", ok ? "ok" : "failed" },
    };
    if (ok)
        reply["result"] = result;
    else
        reply["error"] = errorText;

    std::string error;
    client_.SendText(reply.dump(-1, ' ', false, json::error_handler_t::replace), error);
}

void ProbeChannel::Worker() {
    int backoffMs = 1000;

    while (!ShouldStop()) {
        std::string error;
        if (!client_.Connect(cfg_.url, error)) {
            RecordError("connect: " + error);
            SleepBackoff(backoffMs);
            backoffMs = (std::min)(backoffMs * 2, 30000);
            continue;
        }

        if (!Hello(error)) {
            RecordError("hello: " + error);
            client_.Close();
            SleepBackoff(backoffMs);
            backoffMs = (std::min)(backoffMs * 2, 30000);
            continue;
        }

        backoffMs = 1000;
        connectionLost_.store(false);
        readerStop_.store(false);
        reconnects_.fetch_add(1);

        std::thread reader(&ProbeChannel::ReaderLoop, this);

        while (!ShouldStop() && client_.IsOpen() && !connectionLost_.load()) {
            if (paused_.load()) {
                SleepBackoff(100);
                continue;
            }

            std::vector<std::string> raw = TakeBatch();
            if (raw.empty())
                continue;

            std::string frame;
            size_t usedEvents = 0;
            size_t consumed = 0;
            if (!EncodeBatch(raw, frame, usedEvents, consumed)) {
                if (consumed < raw.size()) {
                    std::deque<std::string> leftovers;
                    for (size_t i = consumed; i < raw.size(); ++i)
                        leftovers.push_back(std::move(raw[i]));
                    RequeueFront(leftovers);
                }
                continue;
            }

            if (!client_.SendBinary(frame, error)) {
                RecordError("send: " + error);
                // Nothing reached the backend: keep the whole batch for the
                // next session (a full queue drops the oldest, which is honest).
                std::deque<std::string> leftovers;
                for (std::string& item : raw)
                    leftovers.push_back(std::move(item));
                RequeueFront(leftovers);
                break;
            }

            sentEvents_.fetch_add(usedEvents);
            seq_.fetch_add(1);

            // Anything that did not fit the batch goes back to the queue head.
            if (consumed < raw.size()) {
                std::deque<std::string> leftovers;
                for (size_t i = consumed; i < raw.size(); ++i)
                    leftovers.push_back(std::move(raw[i]));
                RequeueFront(leftovers);
            }
        }

        // A stop request should still flush what is already buffered; the
        // session is only closed afterwards.
        if (ShouldStop() && client_.IsOpen())
            FinalDrain();

        readerStop_.store(true);
        client_.Close();
        if (reader.joinable())
            reader.join();

        if (ShouldStop())
            break;
    }
}

void ProbeChannel::FinalDrain() {
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::milliseconds(1500);
    int emptyStreak = 0;

    while (std::chrono::steady_clock::now() < deadline) {
        if (QueueDepth() == 0) {
            // Give the base output thread's own final flush a moment to enqueue
            // the last events (it runs concurrently with requestStop()).
            if (++emptyStreak >= 2)
                break;
            SleepBackoff(200);
            continue;
        }
        emptyStreak = 0;

        std::vector<std::string> raw = TakeBatch();
        if (raw.empty())
            continue;

        std::string frame;
        size_t usedEvents = 0;
        size_t consumed = 0;
        if (!EncodeBatch(raw, frame, usedEvents, consumed)) {
            if (consumed < raw.size()) {
                std::deque<std::string> leftovers;
                for (size_t i = consumed; i < raw.size(); ++i)
                    leftovers.push_back(std::move(raw[i]));
                RequeueFront(leftovers);
            }
            continue;
        }

        std::string error;
        if (!client_.IsOpen() || !client_.SendBinary(frame, error)) {
            droppedQueue_.fetch_add(raw.size());
            break;
        }
        sentEvents_.fetch_add(usedEvents);
        seq_.fetch_add(1);

        if (consumed < raw.size()) {
            std::deque<std::string> leftovers;
            for (size_t i = consumed; i < raw.size(); ++i)
                leftovers.push_back(std::move(raw[i]));
            RequeueFront(leftovers);
        }
    }
}

bool ProbeChannel::ShouldStop() const {
    return IsStopRequested() || isStopRequested();
}

void ProbeChannel::waitFlushed(int timeoutMs) {
    const auto deadline = std::chrono::steady_clock::now() +
                          std::chrono::milliseconds(timeoutMs);
    while (std::chrono::steady_clock::now() < deadline && QueueDepth() > 0)
        std::this_thread::sleep_for(std::chrono::milliseconds(20));
}

void ProbeChannel::SleepBackoff(int ms) {
    const auto end = std::chrono::steady_clock::now() + std::chrono::milliseconds(ms);
    while (std::chrono::steady_clock::now() < end) {
        if (ShouldStop())
            return;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
}

void ProbeChannel::RecordError(const std::string& text) {
    {
        std::lock_guard<std::mutex> lock(lastErrorMutex_);
        lastError_ = text;
    }
    if (cfg_.verbose)
        fprintf(stderr, "[probe] %s\n", text.c_str());
}

size_t ProbeChannel::QueueDepth() {
    std::lock_guard<std::mutex> lock(queueMutex_);
    return queue_.size();
}

unsigned long long ProbeChannel::DroppedTotal() {
    return droppedQueue_.load() + droppedRate_.load() + droppedPaused_.load();
}

} // namespace channel
} // namespace kellect
