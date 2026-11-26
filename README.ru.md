# Cascade Control Overlay (`cco`)

[![CI](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay/actions/workflows/ci.yml/badge.svg)](https://github.com/Adaptive-Secure-Overlay/cascade-control-overlay/actions/workflows/ci.yml)
[![Org: Adaptive-Secure-Overlay](https://img.shields.io/badge/org-Adaptive--Secure--Overlay-166534.svg)](https://github.com/Adaptive-Secure-Overlay)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#лицензия)

> **[English documentation (README.md)](README.md)**

**Cascade Control Overlay** — открытая высокопроизводительная реализация на языке **Rust** программного комплекса диссертационного исследования (специальность **2.3.6 «Методы и системы защиты информации, информационная безопасность»**, автор — Зюзин Владислав Дмитриевич).

Проект реализует архитектуру гибридной маршрутизации виртуальных частных сетей, разделяющую **многоскачковую защищенную доставку установочного обмена** (control plane) и **прямую передачу пользовательских данных** (data plane) без модификации конечных VPN-протоколов (**IPsec/IKEv2** и **WireGuard**).

---

## Ключевые компоненты комплекса

1. **Алгоритм множественных стартовых соединений (МСС / MCC, Глава 2.1):**
   - Каскадное ветвление эквивалентных копий установочного обмена по схеме `A -> X1 -> X2 -> B` с бюджетом `(x1_fanout, x2_fanout, ike_fanout)`.
   - Четыре режима отбора ветви на получателе `B`: `first`, `window`, `adaptive` (`min_copies`, `quiet_ms`) и `wait-all`.
   - Сквозная аутентификация копий подписями `Ed25519` (`verify_strict`), пошаговая конфиденциальность капсул `X25519 + HKDF-SHA256 + AES-256-GCM`, непрозрачные маркеры продолжения (`opaque_token`, инициатор `A` не узнает выбранный узел `X2`), одноразовый токен доставки `LocalDeliveryProof` (move-only в Rust) и долговременный SQLite anti-replay журнал (семантика at-most-once).
2. **Оверлейный управляющий канал для IKEv2 и WireGuard (Глава 2.2):**
   - Прозрачный перехват только управляющего обмена: **IKEv2** (`IKE_SA_INIT`, `IKE_AUTH` на UDP/500 и UDP/4500 с Non-ESP Marker `00 00 00 00`) и **WireGuard handshake** (`type 1/2/3`, жесткий запрет на попадание `type 4` Transport Data в оверлей).
   - Прямой выход защищенного пользовательского трафика (**IPsec/ESP** или **WireGuard `type 4`**) между конечными узлами.
   - Linux-адаптер (`cco-linux-proxy`) на базе `nftables`, `IP_TRANSPARENT`, `IP_RECVORIGDSTADDR`, `SO_MARK` (`0x53`), `SOCK_RAW` (`IP_HDRINCL`) и обхода `ip xfrm policy`.
3. **Обобщенный `m`-скачковый приватный каскад (`UniversalCascade`):**
   - Подключен к живому UDP-транспорту (`cco-transport`), CLI (`cco node`, `cco wg-tunnel`), FFI (`cco-ffi`) и обоим протоколам (IPsec/IKEv2 и WireGuard): `--route-mode mcc2 | cascade --hops <m> --max-hops <M> --hop-model f3 | f4 --parallel-chains <K>`.
   - Строгая маскировка знаний (role-limited knowledge) для любого `m >= 3`: `X1` знает только `A` и `X2`, `Xm` знает только `X(m-1)` и `B`, внутренний узел `Xk` (`2 <= k <= m - 1`) знает только `X(k-1)` и `X(k+1)`, инициатор `A` не знает `X2..Xm`, получатель `B` не знает `X1..X(m-1)`.
   - Фиксированный размер всех `CASCADE_*` wire-пакетов (`3584 B`), отсутствие открытых полей `remaining`/`hops`/`visited`, непрозрачная хэш-цепочка `hop_token`/`stop_tag`, Ed25519-подпись капсулы и линейный бюджет `K` параллельных цепочек `O(K * m)` с дедупликацией на `B` (вместо экспоненциального `2^m`).
   - Поддержка обеих моделей выбора следующего узла: `F3` (без повторов через локальный `CASCADE_REJECT`) и `F4` (стохастическая с разрешенными несмежными повторами, работает даже на 4-узловом стенде `{A, X1, X2, B}` при `m = 3, 5, 10`).
4. **Аутентифицированный реестр доверенных узлов (`Trust Registry v2`):**
   - Схема `ipsec-ike-cascade-trust-registry/v2`: раздельные ключи `X25519` (шифрование) и `Ed25519` (подпись) на каждый узел, внешний закрепленный корень доверия (`pinned root`), строгий парсинг JSON без дубликатов, монотонный антиоткатный счетчик версий, атомарное обновление (`fsync + rename`) и восстановление `last-valid`.
   - Режим fail-closed: узел не открывает UDP-сокет без пройденной криптографической проверки реестра. Любые парольные fallback-механизмы полностью исключены.
5. **Аналитический и Монте-Карло движок (Главы 3 и 4):**
   - Точная арифметика большой разрядности (`BigUint`) для расчета пространства маршрутов (`F1/Tor`, `I2P`, модель `F3` без повторений, модель `F4` с несмежными повторениями и транзитным участием конечной пары).
   - Расчет вероятности компрометации маршрута, точного порога размера сети `n50` (например, `m=2, j=5`: `n50(F4) = 17` против `n50(F1) = 20`, сокращение требуемого пула на 15 %).
   - Многопоточная верификация Монте-Карло на `rayon` (`800 000` маршрутов на модель за ~2 мс с отклонением от аналитики `<= 0.0004`, что на порядок строже допуска `<= 0.004` из п. 4.4 диссертации).

---

## Архитектура Cargo Workspace и кроссплатформенных GUI-клиентов (`v0.2.0`)

Во всех крейтах действует `#![forbid(unsafe_code)]`, кроме минимальных Linux syscall-оберток в `cco-linux-proxy` и тонкой FFI-границы в `cco-ffi` (ядро `cco-ffi/src/core.rs` также защищено `#![forbid(unsafe_code)]`). Все мобильные и настольные клиенты работают поверх **единого Rust-ядра** без переписывания на Go и без неподписанных драйверов ядра (`cargo audit`: 0 уязвимостей).

```text
cascade-control-overlay/
├── crates/
│   ├── cco-crypto/        # X25519, HKDF-SHA256, AES-128/256-GCM, Ed25519, Zeroize
│   ├── cco-trust/         # Trust Registry v2 (pinned root, anti-rollback, atomic store)
│   ├── cco-proto/         # Wire-сообщения, LinkFrag (<= 1200 B), парсеры IKEv2 и WireGuard
│   ├── cco-cascade/       # Sans-I/O ядро: MCC + SQLite ledger, UniversalCascade, WG 27-matrix
│   ├── cco-transport/     # Async Tokio UDP mesh, 4-шаговый MGMT, SocketProtector, воркер сессий
│   ├── cco-wg-tunnel/     # Userspace WireGuard (boringtun 0.7.1): WG 1/2/3 через MCC, WG 4 напрямую
│   ├── cco-ffi/           # Единый C-ABI (include/cco_ffi.h) + нативный Android JNI (NativeBridge)
│   ├── cco-linux-proxy/   # Linux TPROXY / SO_MARK / RAW inject / /dev/net/tun + генератор nftables/xfrm
│   ├── cco-analytics/     # Комбинаторика Главы 3, n50, rayon Монте-Карло, бенчмарк Таблицы 4.6
│   └── cco-cli/           # Единый CLI-бинарник `cco` (`node`, `wg-tunnel`, `wg-keygen`, ...)
├── apps/
│   ├── android/           # Kotlin + Material 3 + нативный VpnService (без root) + libcco_ffi.so
│   ├── windows/           # Открытый C# .NET 9 WPF + cco_ffi.dll + подписанный wintun.dll (SHA-256)
│   └── macos/             # SwiftUI (SwiftPM) + libcco_ffi.a + utun / NEPacketTunnelProvider
├── lab/                   # Docker (~200 МБ) и автономные Linux ip netns стенды (strongSwan + userspace WG)
├── examples/              # Безопасные примеры конфигураций (только RFC 5737)
└── docs/                  # Архитектура, протокол, модель угроз, бенчмарки и план статьи Scopus
```

---

## Быстрый старт

```bash
# 1. Прогон всех тестов (L1 + L2 localhost UDP E2E + Rust<->Python wire cross-compat)
cargo test --workspace

# 2. Проверка примера подписанного Trust Registry v2
cargo run --release -p cco-cli -- trust-admin verify \
  --registry examples/trust-registry.example.json \
  --trust-root examples/trust-root.example.json \
  --required-nodes A,X1,X2,B

# 3. Расчет пространства маршрутов и вероятности компрометации (n=10, m=2, j=3)
cargo run --release -p cco-cli -- analytics routes --n 10 --j 3 --m 2

# 4. Расчет порога n50 (m=2, j=5 -> F1=20, F3=18, F4=17)
cargo run --release -p cco-cli -- analytics n50 --m 2 --j 5

# 5. Бенчмарк криптографии Таблицы 4.6 (X25519+HKDF+AES-GCM против RSA-3072 OAEP)
cargo run --release -p cco-cli -- bench crypto --iters 200 --rsa-iters 20 --include-rsa

# 6. Каноническая матрица 27 сценариев WireGuard Handshake Overlay
cargo run --release -p cco-cli -- wg-sim --format csv

# 7. Многоузловой локальный UDP-бенчмарк UniversalCascade (n=14, m=2,3,5,7,10, F3/F4, K=2, IPsec + WG)
cargo run --release -p cco-cli -- bench cascade --nodes 14 --hops 2,3,5,7,10 --compromised 2 --hop-model f4 --parallel-chains 2 --protocol both --trials 3
```

### Живая L3-проверка на Linux / WSL2 (strongSwan и userspace WireGuard)

```bash
cargo build --release -p cco-cli
# 1. Ядерный IPsec / strongSwan (IKEv2 через MCC или m-hop каскад F4, ESP напрямую)
sudo CCO_BIN=./target/release/cco bash lab/scripts/netns_e2e.sh
sudo CCO_BIN=./target/release/cco CCO_ROUTE_MODE=cascade CCO_HOPS=5 CCO_HOP_MODEL=f4 CCO_PARALLEL_CHAINS=2 bash lab/scripts/netns_e2e.sh
# 2. Userspace WireGuard boringtun (WG Type 1/2/3 через MCC или m-hop каскад F4, WG Type 4 напрямую)
sudo CCO_BIN=./target/release/cco bash lab/scripts/wg_userspace_e2e.sh
sudo CCO_BIN=./target/release/cco CCO_ROUTE_MODE=cascade CCO_HOPS=5 CCO_HOP_MODEL=f4 CCO_PARALLEL_CHAINS=2 bash lab/scripts/wg_userspace_e2e.sh
```

Оба стенда поднимают 5 изолированных сетевых пространств имен Linux (`cco-isp` с мостом и `tcpdump`, `cco-A`, `cco-X1`, `cco-X2`, `cco-B`), прогоняют ICMP-трафик через `198.51.100.10 <-> 198.51.100.13` и автоматически проверяют pcap:
- **strongSwan (`netns_e2e.sh`):** `direct_ike_total == 0`, `overlay_udp_packets == 324`, `direct_esp_proto50 == 10`, `5/5` ICMP-ответов (0% потерь, средний RTT `0.101 ms`);
- **userspace WireGuard (`wg_userspace_e2e.sh`):** `direct_wg_control_total == 0`, `direct_wg_type4_data == 14`, `overlay_udp_packets == 1735`, время рукопожатия через MCC `105 ms`, `5/5` ICMP-ответов (0% потерь, средний RTT `0.452 ms`).

Подробные таблицы замеров и план продолжения экспериментов для журнальной статьи: [docs/BENCHMARKS.md](docs/BENCHMARKS.md) и [docs/SCOPUS-EXPERIMENT-PLAN.md](docs/SCOPUS-EXPERIMENT-PLAN.md).

---

## Честные границы применимости

- Комплекс является **исследовательской open-source реализацией** алгоритмов диссертации и не проходил независимый внешний криптографический аудит.
- Модель угроз покрывает наблюдение за прямым управляющим обменом на участке провайдера и скомпрометированные/подменяющие пакеты промежуточные узлы (honest-but-curious и активная подмена на релеях обнаруживается криптографически).
- Архитектура **не защищает** от глобального пассивного противника, контролирующего все каналы и выполняющего временную корреляцию, и **не скрывает** последующий прямой обмен защищенными данными IPsec ESP / WireGuard между `A` и `B`. Подробнее: [SECURITY.md](SECURITY.md) и [docs/THREAT-MODEL.md](docs/THREAT-MODEL.md).

## Связанные репозитории организации `Adaptive-Secure-Overlay`

Этот Rust-репозиторий входит в исследовательскую экосистему [Adaptive Secure Overlay](https://github.com/Adaptive-Secure-Overlay) и дополняет соседние Python-прототипы и наборы экспериментов:

- [Adaptive-Secure-Overlay/adaptive-ipsec-overlay](https://github.com/Adaptive-Secure-Overlay/adaptive-ipsec-overlay) — исходное Python-ядро оверлейного управляющего канала IPsec/IKEv2 (`universal_cascade`, Trust Registry, strongSwan/nftables) и платформенные интеграции
- [Adaptive-Secure-Overlay/adaptive-wireguard-overlay](https://github.com/Adaptive-Secure-Overlay/adaptive-wireguard-overlay) — Python-реализация оверлейного рукопожатия WireGuard (`v0.2.0`), реестр доверия Ed25519 и треки аутентификации/приватности MCC E2E
- [Adaptive-Secure-Overlay/adaptive-overlay-experiments](https://github.com/Adaptive-Secure-Overlay/adaptive-overlay-experiments) — воспроизводимые стендовые сценарии EVE-NG, датасеты порогов и эмпирические замеры

## Связь с диссертацией и свидетельствами на программы для ЭВМ

Исследование выполнено в рамках кандидатской диссертации по специальности **2.3.6 «Методы и системы защиты информации, информационная безопасность»**.
Rust-версия является самостоятельным открытым переносом и развитием алгоритмов исходных Python-прототипов, ранее зарегистрированных в Роспатенте (свидетельства о государственной регистрации программ для ЭВМ № 2024610455 от 10.01.2024 и № 2025613326 от 11.02.2025).

## Лицензия

Двойная лицензия: [MIT](LICENSE-MIT) или [Apache-2.0](LICENSE-APACHE) на выбор пользователя.
