# Local PC Executor — WebSocket Protocol Spec

> **Status**: Draft v0.1 — subject to change

## Transport

- **Protocol**: WebSocket over TLS (`wss://`)
- **Endpoint**: `wss://platform.autogpt.net/ws/local-executor/{session_id}`
- **Direction**: Outbound from shim (NAT/firewall friendly — no inbound ports needed)
- **Auth**: Bearer token in `Authorization` header on WebSocket upgrade request

## Message Format

All messages are JSON with this envelope:

```json
{
  "type": "MESSAGE_TYPE",
  "id": "uuid-v4",
  "ts": 1712345678.123,
  "payload": { ... }
}
```

`id` is used for request/response correlation. Every request gets a response with the same `id`.

---

## Message Types

### Handshake

#### `HELLO` (shim → platform, on connect)
```json
{
  "type": "HELLO",
  "id": "uuid",
  "ts": 1234567890.0,
  "payload": {
    "shim_version": "0.1.0",
    "machine_id": "hostname-uuid4",
    "platform": "darwin",          // "linux" | "darwin" | "win32"
    "arch": "arm64",
    "screen_resolution": [2560, 1440],   // null if computer_use not available
    "capabilities": [
      "shell",                     // always present
      "files",                     // always present
      "computer_use",              // optional: pyautogui available
      "local_llm",                 // optional: ollama running
      "hardware_serial",           // optional: pyserial available
      "hardware_usb",              // optional: pyusb available
      "hardware_gpio"              // optional: RPi.GPIO available
    ],
    "allowed_root": "/Users/alice/autogpt-workspace",
    "local_llm_models": ["llama3.2:3b", "mistral:7b"],   // empty if no local_llm cap
    "hardware_devices": [
      {"type": "serial", "port": "/dev/ttyUSB0", "desc": "Arduino Uno"},
      {"type": "usb",    "vid": "2341", "pid": "0043", "desc": "Arduino Uno"}
    ]
  }
}
```

#### `HELLO_ACK` (platform → shim)
```json
{
  "type": "HELLO_ACK",
  "id": "same-uuid-as-HELLO",
  "ts": 1234567890.1,
  "payload": {
    "session_id": "session-uuid",
    "granted_capabilities": ["shell", "files"],  // subset platform approved
    "max_file_size_bytes": 10485760,
    "command_timeout_seconds": 30
  }
}
```

---

### Shell Execution

#### `EXECUTE_COMMAND` (platform → shim)
```json
{
  "type": "EXECUTE_COMMAND",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "command": "ls -la /tmp",
    "cwd": "/Users/alice/autogpt-workspace",
    "timeout_seconds": 30,
    "env": {"MY_VAR": "value"}    // merged with shim's safe env
  }
}
```

#### `COMMAND_RESULT` (shim → platform)
```json
{
  "type": "COMMAND_RESULT",
  "id": "req-uuid",
  "ts": 1234567890.5,
  "payload": {
    "stdout": "total 48\n...",
    "stderr": "",
    "exit_code": 0,
    "timed_out": false,
    "duration_seconds": 0.12
  }
}
```

---

### File Operations

#### `FILE_READ` (platform → shim)
```json
{
  "type": "FILE_READ",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "path": "/Users/alice/autogpt-workspace/data.csv",
    "encoding": "utf-8",    // "utf-8" | "base64" for binary
    "offset": 0,
    "length": null          // null = whole file
  }
}
```

#### `FILE_CONTENTS` (shim → platform)
```json
{
  "type": "FILE_CONTENTS",
  "id": "req-uuid",
  "ts": 1234567890.1,
  "payload": {
    "content": "col1,col2\n1,2\n",
    "encoding": "utf-8",
    "size_bytes": 16,
    "truncated": false
  }
}
```

#### `FILE_WRITE` (platform → shim)
```json
{
  "type": "FILE_WRITE",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "path": "/Users/alice/autogpt-workspace/output.txt",
    "content": "hello world\n",
    "encoding": "utf-8",
    "create_parents": true
  }
}
```

#### `ACK` (shim → platform, for writes and fire-and-forget ops)
```json
{
  "type": "ACK",
  "id": "req-uuid",
  "ts": 1234567890.1,
  "payload": { "ok": true }
}
```

---

### Computer Use

#### `SCREENSHOT_REQUEST` (platform → shim)
```json
{
  "type": "SCREENSHOT_REQUEST",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "monitor": 0,           // 0 = primary, -1 = all monitors stitched
    "quality": 75           // JPEG quality 1-100
  }
}
```

#### `SCREENSHOT_RESPONSE` (shim → platform)
```json
{
  "type": "SCREENSHOT_RESPONSE",
  "id": "req-uuid",
  "ts": 1234567890.2,
  "payload": {
    "image_base64": "...",
    "mime_type": "image/jpeg",
    "width": 2560,
    "height": 1440,
    "monitor": 0
  }
}
```

#### `INPUT_ACTION` (platform → shim)
```json
{
  "type": "INPUT_ACTION",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "action": "left_click",     // "left_click" | "right_click" | "double_click"
                                // | "mouse_move" | "type" | "key" | "scroll"
    "coordinate": [500, 300],   // for click/move/scroll
    "text": null,               // for "type"
    "key": null,                // for "key" e.g. "ctrl+s"
    "direction": null,          // for "scroll": "up" | "down"
    "clicks": null              // for "scroll": number of clicks
  }
}
```

---

### Error

#### `ERROR` (either direction)
```json
{
  "type": "ERROR",
  "id": "req-uuid",
  "ts": 1234567890.0,
  "payload": {
    "code": "PATH_OUTSIDE_ALLOWED_ROOT",
    "message": "Path /etc/passwd is outside allowed root /Users/alice/autogpt-workspace",
    "fatal": false
  }
}
```

Error codes:
- `PATH_OUTSIDE_ALLOWED_ROOT` — file op tried to escape allowed_root
- `COMMAND_TIMEOUT` — command exceeded timeout
- `CAPABILITY_NOT_GRANTED` — requested capability not in granted_capabilities
- `AUTH_FAILED` — token invalid or expired
- `SHIM_OVERLOADED` — too many concurrent requests
- `INTERNAL_ERROR` — unexpected shim error

---

### Keepalive

#### `PING` / `PONG`
```json
{ "type": "PING", "id": "uuid", "ts": 1234567890.0, "payload": {} }
{ "type": "PONG", "id": "same-uuid", "ts": 1234567890.01, "payload": {} }
```

Platform sends `PING` every 30s. Shim must respond with `PONG` within 10s or connection is dropped.

---

## Concurrency

The platform may send multiple requests before receiving responses (pipelined). The shim
assigns each request its own async task and responds with matching `id` when complete.
Max concurrent requests: `HELLO_ACK.max_concurrent` (default 4).

## Reconnection

Shim uses exponential backoff: `min(2^attempt * 1s, 60s) + jitter(0-5s)`.
On reconnect, shim sends a new `HELLO`. Platform re-issues `HELLO_ACK` with same session.
Any in-flight requests at disconnect time are considered failed; platform retries if safe.
