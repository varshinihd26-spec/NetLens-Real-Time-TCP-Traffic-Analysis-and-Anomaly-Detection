# NetLens – Real-Time TCP Traffic Analysis & Anomaly Detection

## 📌 Overview

NetLens is a real-time network monitoring system that captures and analyzes TCP traffic. It provides a web-based dashboard to monitor live packets, TCP connection flow, traffic statistics, network health, and detected anomalies.

The project is developed using Python, Flask, Scapy, HTML, CSS, and JavaScript.

## 🎯 Objectives

- Capture TCP packets in real time.
- Analyze TCP packet flags and connection stages.
- Display live network traffic through a web dashboard.
- Monitor TCP traffic statistics.
- Detect suspicious TCP activities.
- Calculate a TCP health score.
- Provide automatic diagnosis of detected anomalies.
- Visualize TCP connection flow and real-time traffic rate.

## ✨ Features

### 📡 Real-Time TCP Packet Capture

Captures TCP packets from the network using Scapy.

### 📊 Real-Time Dashboard

Displays continuously updated network information through a Flask web interface.

### 🔄 TCP Connection Flow

Visualizes TCP connection stages:

```text
SYN → SYN-ACK → ACK → DATA → FIN
```

### 🚨 Anomaly Detection

NetLens detects suspicious TCP activities such as:

- Possible SYN Flood
- Excessive Connection Resets
- NULL Flag Packets
- Xmas Scan
- Possible Port Scan

### ❤️ TCP Health Score

The system calculates a health score between 0 and 100 based on detected anomalies.

| Score | Status |
|---|---|
| 80–100 | NORMAL |
| 50–79 | WARNING |
| 0–49 | CRITICAL |

### 📈 Real-Time Traffic Rate

Displays the current TCP packet traffic rate in real time.

### 📋 Live Packet Table

Displays:

- Source IP
- Destination IP
- Source Port
- Destination Port
- TCP Flags
- Packet Size
- Connection Stage

## 🏗️ System Architecture

```text
Network Traffic
      ↓
Scapy Packet Capture
      ↓
Packet Processing
      ↓
TCP Flag Analysis
      ↓
Statistics Update
      ↓
Anomaly Detection
      ↓
Health Score Calculation
      ↓
Flask Backend
      ↓
Web API
      ↓
NetLens Dashboard
```

## 📁 Project Structure

```text
netlens/
│
├── app.py
├── sniffer.py
├── requirements.txt
│
└── templates/
    └── index.html
```

### app.py

Runs the Flask web server and provides the dashboard API.

### sniffer.py

Responsible for:

- Capturing TCP packets
- Processing packets
- Extracting TCP information
- Maintaining traffic statistics
- Detecting anomalies
- Calculating the health score
- Tracking TCP connection flow

### templates/index.html

Contains the web dashboard interface and real-time visualization.

### requirements.txt

Contains the Python packages required to run the project.

## 🛠️ Technologies Used

- Python
- Flask
- Scapy
- HTML
- CSS
- JavaScript
- Npcap

## ⚙️ Installation

### 1. Clone the Repository

```bash
git clone <your-repository-url>
cd netlens
```

### 2. Install Dependencies

Using Python:

```powershell
py -m pip install flask scapy
```

Or using the requirements file:

```powershell
py -m pip install -r requirements.txt
```

### 3. Install Npcap

On Windows, Scapy requires Npcap for packet capture.

Install Npcap using its default installation options.

## ▶️ Running the Project

Open PowerShell inside the project folder and run:

```powershell
py app.py
```

The Flask server will start at:

```text
http://127.0.0.1:5000
```

Open the address in your web browser.

## 🔍 Anomaly Detection

### SYN Flood

A high number of SYN packets within a short period can indicate a possible SYN flood.

### Excessive RST

A high number of TCP reset packets may indicate abnormal connection behavior.

### NULL Scan

TCP packets without any TCP flags can be identified as possible NULL scans.

### Xmas Scan

TCP packets containing FIN, PSH, and URG flags can be identified as possible Xmas scans.

### Port Scan

If a source attempts to connect to many different destination ports within a short period, NetLens can identify it as a possible port scan.

## 📊 TCP Statistics

NetLens monitors:

```text
Total Packets
SYN
SYN-ACK
ACK
DATA
FIN
RST
```

## ❤️ TCP Health Status

The dashboard displays the overall network status:

```text
NORMAL
WARNING
CRITICAL
```

The status is calculated using the recent detected anomalies and the TCP health score.

## 🔄 Working Flow

```text
TCP Packet
    ↓
Scapy Capture
    ↓
Packet Processing
    ↓
TCP Flag Analysis
    ↓
Statistics Update
    ↓
Anomaly Detection
    ↓
Health Score
    ↓
Flask API
    ↓
Web Dashboard
    ↓
Real-Time Monitoring
```

## 🚀 Future Enhancements

- Historical traffic graphs
- CSV packet export
- Machine learning-based anomaly detection
- IP-based filtering
- Protocol filtering
- Detailed packet inspection
- Network activity reports
- Email notifications
- Database storage
- Advanced TCP connection tracking

## ⚠️ Disclaimer

NetLens is developed for educational and network monitoring purposes. Packet capture and network analysis should only be performed on networks and devices that you own or have permission to monitor.

## 👩‍💻 Project Information

**Project Name:** NetLens  
**Project Type:** Computer Networks Mini Project  
**Domain:** Network Monitoring and Security  
**Focus:** Real-Time TCP Traffic Analysis and Anomaly Detection
