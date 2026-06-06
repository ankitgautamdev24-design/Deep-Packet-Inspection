# DPI Engine - Deep Packet Inspection System

Multi-threaded DPI engine that classifies network traffic, extracts domain names from encrypted connections (SNI), and enforces content filtering rules.

---

## ⚡ Quick Start

```powershell
# Set UTF-8 encoding
[Console]::OutputEncoding = [System.Text.Encoding]::UTF8

# Navigate to project
cd "Deep Packet Inspection Project"

# Run engine
.\dpi_engine.exe test_dpi.pcap output.pcap
```

---

## Table of Contents

1. [What is DPI?](#1-what-is-dpi)
2. [How It Works](#how-it-works)
3. [Architecture](#architecture)
4. [Blocking Code (Thread-Safe Queue)](#blocking-code-thread-safe-queue)
5. [Building & Running](#building--running)

---

## 1. What is DPI?

**Deep Packet Inspection** examines packet contents (not just headers) to identify applications and enforce policies. Uses cases: ISP throttling, enterprise content filtering, parental controls.

**Our engine:**

- Reads PCAP capture files → Parses packets → Extracts SNI (domain names) from HTTPS → Applies blocking rules → Writes filtered output

---

## How It Works

### The Five-Tuple (Connection ID)

```
Source IP + Dest IP + Source Port + Dest Port + Protocol = Connection
```

All packets with the same 5-tuple belong to one connection/flow.

### Server Name Indication (SNI)

HTTPS traffic leaks the domain name in the TLS Client Hello (before encryption). We extract it to identify apps:

```
Client Hello → [SNI: www.youtube.com] → Identify as YouTube → Check rules → Block if needed
```

### Packet Structure

```
Ethernet Header (MACs) → IP Header (IPs) → TCP/UDP Header (Ports) → Payload (SNI data)
```

---

## Architecture

### Multi-Threaded Design

```
Reader Thread → Load Balancers (2) → Fast Paths (4) → Output Writer
```

**Why multiple threads?**

- Reader: Reads PCAP file
- Load Balancers: Distribute packets to Fast Paths using consistent hashing
- Fast Paths: Extract SNI, check rules, classify traffic
- Output Writer: Write allowed packets to output file

**Consistent hashing:** Same 5-tuple always goes to same Fast Path so it can track flow state.

---

## Blocking Code (Thread-Safe Queue)

## Blocking Code (Thread-Safe Queue)

**Thread-safe blocking queue** passes packets between threads efficiently. It blocks (sleeps) instead of busy-waiting when empty/full.

```cpp
template<typename T>
class ThreadSafeQueue {
private:
    std::queue<T> queue_;
    std::mutex mutex_;
    std::condition_variable not_empty_, not_full_;
    size_t max_size_;

public:
    void push(T value) {
        std::unique_lock<std::mutex> lock(mutex_);
        not_full_.wait(lock, [this] { return queue_.size() < max_size_; });
        queue_.push(value);
        not_empty_.notify_one();
    }

    T pop() {
        std::unique_lock<std::mutex> lock(mutex_);
        not_empty_.wait(lock, [this] { return !queue_.empty(); });
        T value = queue_.front();
        queue_.pop();
        not_full_.notify_one();
        return value;
    }
};
```

**Why it matters:**

- `push()`: Blocks if queue full (producer waits)
- `pop()`: Blocks if queue empty (consumer waits)
- `mutex`: Thread-safe access
- `condition_variable`: Wake threads when condition changes
- **No busy-waiting** → Low CPU usage + Same performance

**Example: Blocking YouTube Traffic**

```
Packet 1-3 (TCP handshake): Forwarded (no SNI yet)
Packet 4 (TLS Client Hello): SNI="www.youtube.com" → Check rules → BLOCKED
Packet 5+ (same flow): All dropped (flow marked as blocked)
```

---

## Building & Running

### Build

```bash
# Simple version
g++ -std=c++17 -O2 -I include -o dpi_simple \
    src/main_working.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp

# Multi-threaded version
g++ -std=c++17 -pthread -O2 -I include -o dpi_engine \
    src/dpi_mt.cpp src/pcap_reader.cpp src/packet_parser.cpp \
    src/sni_extractor.cpp src/types.cpp
```

### Run

```bash
# Basic
./dpi_engine test_dpi.pcap output.pcap

# With blocking rules
./dpi_engine input.pcap output.pcap \
    --block-app YouTube \
    --block-domain facebook \
    --block-ip 192.168.1.50
```

### Output Example

```
╔══════════════════════════════════════════════════════════════╗
║              DPI ENGINE v2.0 (Multi-threaded)                 ║
╠══════════════════════════════════════════════════════════════╣
║ Load Balancers:  2    FPs per LB:  2    Total FPs:  4        ║
╚══════════════════════════════════════════════════════════════╝

[Reader] Done reading 77 packets

╔══════════════════════════════════════════════════════════════╗
║                      PROCESSING REPORT                        ║
╠══════════════════════════════════════════════════════════════╣
║ Total Packets:                77                              ║
║ Forwarded:                    69                              ║
║ Dropped:                       8                              ║
╠══════════════════════════════════════════════════════════════╣
║                   APPLICATION BREAKDOWN                       ║
╠══════════════════════════════════════════════════════════════╣
║ HTTPS                39  50.6%                                ║
║ Unknown              16  20.8%                                ║
║ YouTube               4   5.2% (BLOCKED)                      ║
║ DNS                   4   5.2%                                ║
║ ...                                                           ║
╚══════════════════════════════════════════════════════════════╝

[Detected Domains/SNIs]
  - www.youtube.com -> YouTube
  - www.facebook.com -> Facebook
  - github.com -> GitHub
  ...

Output written to: output.pcap
```

---

## Summary

- **DPI**: Inspect packet contents to identify apps and enforce policies
- **SNI**: Leaks domain names in HTTPS handshake before encryption
- **Five-Tuple**: Uniquely identifies a connection/flow
- **Multi-threaded**: Reader → Load Balancers → Fast Paths → Output Writer
- **Blocking Queue**: Thread-safe, efficient packet passing (sleeps instead of spins)
- **Flow-based blocking**: All packets of a blocked flow are dropped
