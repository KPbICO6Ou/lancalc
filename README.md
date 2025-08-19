# LanCalc

[![CI](https://github.com/lancalc/lancalc/actions/workflows/ci.yml/badge.svg)](https://github.com/lancalc/lancalc/actions/workflows/ci.yml)
[![PyPI](https://img.shields.io/pypi/v/lancalc.svg)](https://pypi.org/project/lancalc/)
[![Python](https://img.shields.io/pypi/pyversions/lancalc.svg)](https://pypi.org/project/lancalc/)

LanCalc is a desktop application built with PyQt5, designed to calculate network configurations for Windows, macOS, and Linux systems.

![image](https://github.com/user-attachments/assets/a7d1779f-d138-4819-84c6-4df876efc292)

[Download](https://github.com/lancalc/lancalc/releases)

It provides a user-friendly interface to compute essential network parameters such as network address, broadcast address, the minimum and maximum host addresses, and the number of hosts within a given subnet. 

Support IPv4 address formats, subnet masks and prefixes. This tool is particularly useful for network administrators and IT professionals who require quick calculations of network parameters.

## Новые возможности (v2.0+)

### 🚀 Оптимизации производительности
- **Кэширование результатов** - автоматическое кэширование вычислений для ускорения повторных операций
- **Асинхронные операции** - неблокирующие вычисления для улучшенной отзывчивости GUI
- **ThreadPoolExecutor** - параллельная обработка тяжелых операций
- **Оптимизированное логирование** - условное логирование с измерением времени выполнения

### 🔧 Дебаг режим
- **Подробное логирование** - детальная информация о каждом действии
- **Измерение производительности** - время выполнения операций
- **Статистика кэша** - информация о состоянии кэша
- **CLI флаг `--debug`** - включение дебаг режима в командной строке

### 📊 Расширенная аналитика
- **Статистика кэша** - `lancalc --cache-stats`
- **Очистка кэша** - `lancalc --clear-cache`
- **Асинхронный режим** - `lancalc --async`
- **Сетевая диагностика** - проверка подключения и доступности сервисов

### 🎯 Улучшенная совместимость
- **Обратная совместимость** - все старые вызовы работают без изменений
- **Graceful fallbacks** - автоматическое восстановление после сбоев
- **Улучшенная обработка ошибок** - детальные сообщения об ошибках

## Quick Start

### Installation

Python 3.9+ is required.

- Default (with GUI):

```bash
pip3 install lancalc
```

- CLI-only / headless (avoid installing PyQt5):

```bash
# Install package without dependencies, then only required CLI deps
pip3 install --no-deps lancalc
pip3 install -r requirements.txt
```

- Install without GUI dependencies:

```bash
# Install with nogui extras (excludes PyQt5)
pip3 install 'lancalc[nogui]'
```

- Install from GitHub:

```bash
# With GUI (default)
pip3 install 'git+https://github.com/lancalc/lancalc.git'

# CLI-only / headless
pip3 install --no-deps 'git+https://github.com/lancalc/lancalc.git'
pip3 install -r requirements.txt

# Without GUI dependencies
pip3 install 'git+https://github.com/lancalc/lancalc.git#egg=lancalc[nogui]'
```

If pip is missing:

```bash
curl https://bootstrap.pypa.io/get-pip.py -o /tmp/get-pip.py
python3 /tmp/get-pip.py
```

If the `lancalc` command is not found after installation, add the local packages path to PATH:

```bash
export PATH="$HOME/.local/bin:$PATH"
```

To permanently add to PATH, add this line to your `~/.bashrc` or `~/.zshrc`:

```bash
echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc
source ~/.bashrc
```

Notes:
- On Linux, PyQt5 may require system Qt libraries (xcb plugin). If GUI fails to start, ensure a desktop environment is available and try installing system packages (e.g. Debian/Ubuntu: `sudo apt install python3-pyqt5`), or use the CLI-only steps above.
- In CI/headless environments, prefer the CLI-only steps above to skip GUI dependencies.

## Running the Application

### GUI Mode

After installation (default with GUI), launch the application with the command:

```bash
lancalc
```

LanCalc auto-detects the environment. If GUI dependencies are unavailable or you are in a headless session, the launcher falls back to CLI help. In such cases, use the CLI examples below.

### CLI Mode

LanCalc also supports command-line interface for automation and scripting:

```bash
# Basic usage
lancalc 192.168.1.1/24

# JSON output for parsing
lancalc 192.168.1.1/24 --json

# Debug mode with timing information
lancalc 192.168.1.1/24 --debug

# Async computation mode
lancalc 192.168.1.1/24 --async-mode

# Cache management
lancalc --cache-stats          # Show cache statistics
lancalc --clear-cache          # Clear computation cache

# Network information
lancalc --internal             # Show internal IP
lancalc --external             # Show external IP
lancalc --internal --external  # Show both IPs

# Examples
lancalc 10.0.0.1/8
lancalc 172.16.0.1/16
lancalc 192.168.1.100/31  # Point-to-point network
lancalc 192.168.1.1/32    # Single host
```

You can also run via module:

```bash
python3 -m lancalc 192.168.1.1/24 --json
```

### Output Format

**Text mode** (default):
```
Network: 192.168.1.0
Prefix: /24
Netmask: 255.255.255.0
Broadcast: 192.168.1.255
Hostmin: 192.168.1.1
Hostmax: 192.168.1.254
Hosts: 254
```

**JSON mode** (`--json`):
```json
{
  "network": "192.168.1.0",
  "prefix": "/24",
  "netmask": "255.255.255.0",
  "broadcast": "192.168.1.255",
  "hostmin": "192.168.1.1",
  "hostmax": "192.168.1.254",
  "hosts": "254",
  "comment": ""
}
```

**Debug mode** (`--debug`):
```
⏱️  Computation time: 2.345ms
📋 Cache hit: false

Network: 192.168.1.0
Prefix: /24
Netmask: 255.255.255.0
Broadcast: 192.168.1.255
Hostmin: 192.168.1.1
Hostmax: 192.168.1.254
Hosts: 254
```

**JSON with debug info** (`--json --debug`):
```json
{
  "network": "192.168.1.0",
  "prefix": "/24",
  "netmask": "255.255.255.0",
  "broadcast": "192.168.1.255",
  "hostmin": "192.168.1.1",
  "hostmax": "192.168.1.254",
  "hosts": "254",
  "_timing": {
    "computation_time": 2.345,
    "cache_hit": false,
    "cache_stats": {
      "size": 5,
      "enabled": true,
      "max_workers": 4
    }
  }
}
```

### Uninstall

```bash
pip3 uninstall -y lancalc
```

That's it! The application will start and automatically detect your current network settings.

## For Developers

### Prerequisites

Python 3.9+ is required. GUI development requires PyQt5 (installed by default).

- Production (CLI only):
```bash
pip3 install -r requirements.txt
```

- Editable install with GUI (default):
```bash
pip3 install -e .
```

- Editable install without GUI:
```bash
pip3 install --no-deps -e .
pip3 install -r requirements.txt
```

- Full dev setup (with GUI):
```bash
pip3 install -e '.[dev]'
```

- Dev without GUI:
```bash
pip3 install --no-deps -e .
pip3 install -r requirements.txt
pip3 install pytest pytest-qt pre-commit flake8
```

- Reinstall 
```bash
pip3 install -e . --force-reinstall
```

### Installation for Development

Clone the repository and install in development mode:

```bash
git clone https://github.com/lancalc/lancalc.git
```

### Running from Source

```bash
# GUI (requires PyQt5)
python3 lancalc/main.py

# CLI
python3 -m lancalc 192.168.1.1/24
```

### Development Tools

```bash
pip3 install pre-commit flake8 pytest pytest-qt
pre-commit install
pre-commit run --all-files
pre-commit autoupdate
```

### Running Tests
```bash
pytest -v
```

### Test Build
```bash
pip3 install -e .
~/.local/bin/lancalc
```

### Test Build Linux
```bash
pip3 install git+file://$(pwd) 
export PATH="$HOME/.local/bin:$PATH" 
lancalc
```

### Test Build Windows
```powershell
pip3 install "git+file://$(Get-Location)"
lancalc
```

## License

Distributed under the MIT License. See LICENSE for more information.

## Contact

[GitHub](https://github.com/lancalc/lancalc) [Telegram](https://t.me/wachawo)

## Notes

A /31 mask allows the use of 2 addresses. The first will be the network address, the last the broadcast address, and for connecting hosts we use these same addresses.
Limitations when using a /31 prefix:
Protocols that use L3 broadcast stop working.
In fact, at present there are almost no protocols left that rely on L3 broadcast in their operation. The main currently relevant protocols, such as OSPF, IS-IS, EIGRP, and BGP, use multicast or unicast addresses instead.
This limitation can even be seen as an advantage, because it increases resistance to DoS attacks based on broadcast traffic distribution.
But not all devices support /31 prefixes.
On Juniper and Cisco devices, you can safely use a /31 mask, although Cisco will issue a warning (% Warning: use /31 mask on non point-to-point interface cautiously).
ZyXEL, however, does not allow you to select a /31 mask at all.
As a result, there are additional limitations in network operation — from using equipment of different manufacturers to even using equipment from the same vendor but with different firmware versions.
If you are not concerned by the above limitations, you can confidently save addresses by using the /31 prefix.

The use of the /31 prefix is described in detail in RFC 3021 — Using 31-Bit Prefixes on IPv4 Point-to-Point Links.


## Special IPv4 Ranges and Cases

### Special Network Types

- **/31 networks**: Show `2*` in Hosts field - both addresses are usable (RFC 3021)
- **/32 networks**: Show `1*` in Hosts field - single host network
- The asterisk (*) indicates special network types where all addresses are usable

### Special IPv4 Address Ranges

LanCalc automatically detects and handles special IPv4 address ranges according to RFC specifications. For these ranges, host-related fields show "*" and a message field indicates the range type with RFC reference.

#### Supported Special Ranges

| Range | Type | RFC | Description |
|-------|------|-----|-------------|
| **127.0.0.0/8** | Loopback | [RFC 3330](docs/RFC.md#rfc-3330---loopback-addresses) | Loopback addresses - not routable on the Internet |
| **169.254.0.0/16** | Link-local | [RFC 3927](docs/RFC.md#rfc-3927---link-local-addresses) | Link-local addresses - not routable |
| **224.0.0.0/4** | Multicast | [RFC 5771](docs/RFC.md#rfc-5771---multicast-addresses) | Multicast addresses - not for host addressing |
| **0.0.0.0/8** | Unspecified | [RFC 1122](docs/RFC.md#rfc-1122---unspecified-addresses) | Unspecified addresses - not for host addressing |
| **255.255.255.255/32** | Broadcast | [RFC 919](docs/RFC.md#rfc-919---broadcast-address) | Limited broadcast address - not for host addressing |

#### Special Range Behavior

When you enter an address from a special range:

**CLI Text Mode:**
```bash
lancalc 127.0.0.1/8
```
```
Network: 127.0.0.0
Prefix: /8
Netmask: 255.0.0.0
Broadcast: *
Hostmin: 127.0.0.1
Hostmax: 127.255.255.254
Hosts: 16777214
Comment: RFC 3330 Loopback (https://github.com/lancalc/lancalc/blob/main/docs/RFC.md#rfc-3330---loopback-addresses)
```

**CLI JSON Mode:**
```bash
lancalc 224.0.0.1/4 --json
```
```json
{
  "network": "224.0.0.0",
  "prefix": "/4",
  "netmask": "240.0.0.0",
  "broadcast": "*",
  "hostmin": "*",
  "hostmax": "*",
  "hosts": "*",
  "comment": "RFC 5771 Multicast (https://github.com/lancalc/lancalc/blob/main/docs/RFC.md#rfc-5771---multicast-addresses)"
}
```

**GUI Mode:**
- Host fields (Hostmin, Hostmax, Broadcast, Hosts) show "*"
- Status bar displays the special range message instead of version
- No special styling or warnings needed

#### JSON Fields

The JSON output includes the following fields:

- **`comment`**: Description and RFC reference for special ranges (empty for normal unicast addresses)
- **`hosts`**: Number of available host addresses in the specified subnet

These fields are always present, making the JSON output format consistent regardless of address type.

## Usage

### Command Line Interface

```bash
# Basic subnet calculation
lancalc 192.168.1.1/24

# JSON output
lancalc 192.168.1.1/24 --json

# Show internal/private IP address
lancalc --internal
lancalc -i

# Show external/public IP address
lancalc --external
lancalc -e

# Use multiple info flags simultaneously
lancalc -i -e
lancalc -i -e --json

# Show version
lancalc --version
```

### Examples

**Basic calculation:**
```bash
$ lancalc 192.168.1.1/24
Network: 192.168.1.0
Prefix: /24
Netmask: 255.255.255.0
Broadcast: 192.168.1.255
Hostmin: 192.168.1.1
Hostmax: 192.168.1.254
Hosts: 254
```

**JSON output:**
```bash
$ lancalc 192.168.1.1/24 --json
{
  "network": "192.168.1.0",
  "prefix": "/24",
  "netmask": "255.255.255.0",
  "broadcast": "192.168.1.255",
  "hostmin": "192.168.1.1",
  "hostmax": "192.168.1.254",
  "hosts": "254"
}
```

**Interface information:**
```bash
$ lancalc -i
Address: 10.16.69.146
Prefix: /24

$ lancalc -i --json
{"address": "10.16.69.146", "prefix": "/24"}
```

**External IP detection:**
```bash
$ lancalc -e
External IP: 216.66.18.3

$ lancalc -e --json
{"external_ip": "216.66.18.3"}
```

**Multiple info flags:**
```bash
$ lancalc -i -e
Address: 10.16.69.146
Prefix: /24

External IP: 216.66.18.3

$ lancalc -i -e --json
{"address": "10.16.69.146", "prefix": "/24"}

{"external_ip": "216.66.18.3"}
```
