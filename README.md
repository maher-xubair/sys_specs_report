# 🖥️ System Specs Report Generator

_A powerful, lightweight tool that generates detailed HTML reports of your system’s hardware and software_

## 🌟 Features

- **Comprehensive System Analysis** – CPU, GPU, RAM, Storage, Network, Battery, BIOS, TPM & more
- **Professional HTML Reports** – Clean, responsive, mobile-friendly layout
- **One-Click Execution** – No installation needed, single `.exe` file
- **Smart Admin/Non-Admin Support** – Adapts info depth based on privileges
- **Fast & Lightweight** – Generates reports in seconds
- **Fully Offline** – 100% privacy, never sends data online
- **HTML is Customizable** – Easily modify or theme the output
- **Automatic Browser Launch** – Opens report on completion
- **Failsafe Paths** – Automatically selects desktop/documents/temp if no write access

## 📥 Download & Run

1. Download the latest release from **[Releases Page](https://github.com/maher-xubair/sys_specs_report/releases)**
2. Double-click `sys_specs_report.exe`
3. The tool will start collecting your system information
4. Report is saved in the same folder (or fallback paths)
5. Press `Enter` when prompted to open the report

**Requirements** <br>
✔ Windows 7 or later <br>
✔ PowerShell 5.1+ (pre-installed) <br>
✔ Admin rights (optional, for extended info)

## 🖼️ Sample Report Preview

[![Report Preview](https://raw.githubusercontent.com/maher-xubair/sys_specs_report/main/demo.png)](https://htmlpreview.github.io/?https://raw.githubusercontent.com/maher-xubair/sys_specs_report/main/demo.html)

**[View Full Sample Report](https://htmlpreview.github.io/?https://raw.githubusercontent.com/maher-xubair/sys_specs_report/main/demo.html)**

## 🛠️ Command Line Usage

```powershell
# Run via PowerShell
# 1. Download script.ps1
# 2. Open PowerShell as Administrator
# 3. Navigate to the script directory
# 4. Run the script:
./script.ps1
```

## 🔍 Data Collected

| Category        | Details Collected                                                             |
| --------------- | ----------------------------------------------------------------------------- |
| **System**      | OS version, build, install date, uptime, device name, chassis type, time zone |
| **CPU**         | Model, architecture, core/thread count, cache sizes, virtualization, voltage  |
| **Memory**      | Total RAM, part numbers, module type, manufacturer, speed, form factor        |
| **Storage**     | Disk type (NVMe/SSD), health, capacity, interface, BitLocker, free space      |
| **Display/GPU** | Adapter, driver, resolution, color depth, refresh rate, external displays     |
| **Motherboard** | Manufacturer, model, serial, BIOS version and release date                    |
| **Network**     | Adapters, IP, DNS, MAC, speed, Wi-Fi version, Bluetooth version               |
| **Battery**     | Status, charge %, estimated runtime                                           |
| **Security**    | TPM status & version, Secure Boot, BitLocker                                  |
| **And more...** | Includes pen & touch support, Windows activation, and other system properties |

## ❓ FAQ

**Q: Is my data sent online?** <br>
A: No. This tool runs fully offline — no internet required.

**Q: Why admin rights?** <br>
A: Some data like disk health or TPM version may need elevated privileges.

**Q: Can I customize the report look?** <br>
A: Yes! The generated HTML file is standalone and fully editable.

## 📜 License

MIT License – Free for personal and commercial use

## 👨‍💻 Developer

Created with ❤️ by [Maher Zubair](https://maher-xubair.is-a.dev) <br>
[![Website](https://img.shields.io/badge/Visit-NexOracle-blue?style=flat-square)](https://nexoracle.com)
