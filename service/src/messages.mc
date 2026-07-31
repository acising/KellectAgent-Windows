;/* service/src/messages.mc
; * Windows Event Log message table for KellectService. Each event carries one
; * insertion string (the message text passed to ReportEventW) via "%1".
; * The MessageId values below (1/2/3) MUST match the kEvt* constants in
; * EventLog.cpp and the EVT_* symbolic names here.
; */
MessageIdTypedef=DWORD
LanguageNames=(English=0x409:MSG00409)

MessageId=1
SymbolicName=EVT_INFO
Language=English
%1
.

MessageId=2
SymbolicName=EVT_WARN
Language=English
%1
.

MessageId=3
SymbolicName=EVT_ERROR
Language=English
%1
.
