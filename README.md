<div align="center">

# 🛡️ Performa Sec: Windows Registry Change Monitoring System

[![Python Version](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=for-the-badge&logo=python&logoColor=white)]()
[![UI Library](https://img.shields.io/badge/UI-CustomTkinter-4da6ff?style=for-the-badge)]()
[![Security](https://img.shields.io/badge/Focus-Blue_Team-1f538d?style=for-the-badge&logo=security&logoColor=white)]()
[![Status](https://img.shields.io/badge/Status-Completed-51cf66?style=for-the-badge)]()

<br>

<a href="https://github.com/akshatcore">
  <img src="https://readme-typing-svg.herokuapp.com?font=Fira+Code&weight=600&size=20&pause=1000&color=00FF99&center=true&vCenter=true&width=800&lines=Python-based+Blue+Team+Toolkit;Real-time+Registry+Integrity+Checking;Malware+Persistence+Detection" alt="Typing SVG" />
</a>

<br>

<img src="dashboard.png?v=2" alt="Performa Dashboard" width="800" style="border-radius: 10px; box-shadow: 0 4px 8px rgba(0,0,0,0.2);">

</div>

---

## 📖 Project Overview
This project focuses on designing a Windows Registry Monitoring System that tracks unauthorized or suspicious changes made to registry keys. Because malware often targets the registry to maintain persistence, modify system policies, or disable security tools, this tool acts as an early warning system. 

Developed by **Akshat Tiwari**, this system provides a complete monitoring toolkit that detects changes in sensitive registry paths, identifies malware-like modifications, and verifies registry integrity using baseline comparisons.

---

## ✨ Key Features

| Feature | Description |
| :--- | :--- |
| 🔍 **Registry Integrity Checker** | Captures a baseline registry snapshot, compares current registry state to the baseline, and detects additions, deletions, and value modifications. |
| 🛡️ **Autorun Key Monitoring** | Actively monitors `Run` and `RunOnce` keys in HKCU and HKLM to detect new startup entries added without authorization. |
| 🚨 **Malware Pattern Detection** | Flags malware-like registry changes, such as disabling security tools or executing scripts from hidden/temp directories. |
| 📊 **Modern Dashboard** | Built with `customtkinter` featuring real-time animated status gauges and professional data visualization. |
| 📄 **Automated PDF Reporting** | Generates a detailed registry change report for analysis, compiling session logs and critical incidents into a professional PDF. |

---

## ⚙️ Tools & Technologies Used
This toolkit was built entirely in **Python** utilizing the following core libraries:
* `winreg` - Python registry module for interacting with the Windows OS.
* `customtkinter` - For the responsive, dark-mode graphical user interface.
* `threading` - To allow continuous background polling without freezing the UI.
* `json` - For saving and loading the baseline integrity states.
* `fpdf` - For generating structured, forensic PDF reports.

---

## 🚀 Installation & Setup

<details>
<summary><b>🔥 Click here to view installation steps</b></summary>
<br>

1. **Clone the repository:**
```bash
git clone [https://github.com/akshatcore/Windows-Registry-Monitor.git](https://github.com/akshatcore/Windows-Registry-Monitor.git)
cd Windows-Registry-Monitor

```

2. **Install the required dependencies:**

```bash
pip install -r requirements.txt

```

</details>

---

## 💻 Usage Instructions

> ⚠️ **Important:** To successfully monitor `HKEY_LOCAL_MACHINE` (HKLM) paths, you must run this script or your terminal as an **Administrator**.

1. **Launch the app:** Run `python registry_monitor.py` in your terminal.
2. **Create Baseline:** Click the `Create Baseline` button to scan the system and save the safe state.
3. **Start Monitoring:** Click `Start Monitoring` to activate the background polling thread.
4. **Observe:** Any changes made to the targeted registry paths will instantly appear in the log console and visually update the dashboard gauges.
5. **Analyze:** Click `Generate Report` to export the session data to a structured PDF file, then click `Open PDF` to view it instantly.

---

## ⚠️ Disclaimer

This tool is intended for educational and defensive (Blue Team) purposes only. Modifying the Windows Registry without knowing what you are doing can cause system instability. Always proceed with caution.

<br>

<div align="center">
  <a href="https://github.com/akshatcore">
    <img src="https://img.shields.io/badge/Developed%20with%20❤️%20by-Akshat%20Tiwari-1f538d?style=for-the-badge&logo=github" alt="Developed by Akshat Tiwari" />
  </a>
</div>

