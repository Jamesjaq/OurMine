# ARES v3.4.1: Specialized Tradecraft Research (2026 Intel)

## 1. OT/SCADA & Industrial Control Systems
*   **Protocols**: Modbus/TCP (502), DNP3 (20000), BACnet (47808).
*   **Key Function Codes (Modbus)**:
    *   `5`: Force Single Coil (Impact: Toggle valve/pump).
    *   `15`: Force Multiple Coils.
    *   `6`: Write Single Register.
    *   `16`: Write Multiple Registers (Impact: Alter setpoints/safety limits).
*   **Vulnerabilities**: Authorization bypass in BASControl20, cleartext legacy DNP3 traffic, default PLC credentials.

## 2. Military & Telecom (SS7/SIGTRAN)
*   **Protocols**: SS7 (MTP, SCCP, TCAP), SIGTRAN (M3UA, SCTP).
*   **Techniques**:
    *   **Location Tracking**: `AnyTimeInterrogation` (ATI) messages to HLR/VLR.
    *   **SMS Interception**: `UpdateLocation` spoofing to redirect traffic to attacker-controlled MSC.
    *   **Tools**: SigPloit, SigTran Gateways.
*   **2026 Intel**: Active abuse of SS7 vulnerabilities by state actors to locate military personnel (Iran vs. US).

## 3. Hypervisor Escape (Ring -1)
*   **VMware ESXi**: **CVE-2026-47876** (Critical VM Escape, code execution on host).
*   **KVM (Linux Kernel)**: **CVE-2026-64561** (Use-After-Free CWE-416, CVSS 8.8, host escape).
*   **Tradecraft**: Multi-step guest breakout design targeting hypervisor memory management.

## 4. Financial Warfare & Crypto
*   **Flash Loan Attacks**: uncollateralized same-transaction borrowing to amplify precision errors (Bunni exploit $8.4M) or oracle manipulation (KiloEx $7.5M).
*   **Smart Contract Bugs**: Rounding errors in liquidity accounting, trusted forwarder bypass in price feeds.
*   **ATM Jackpotting**: Ploutus malware resurgence in 2026 targeting XFS (eXtensions for Financial Services) protocol command injection (`WFS_CMD_CDM_DISPENSE`).

## 5. 2026 Kernel Security
*   **Windows**: Microsoft legacy cross-signed driver trust change (April 2026) to reduce kernel attack surface.
*   **Mitigation**: KPTI (Kernel Page Table Isolation) for side-channel protection.
