# TradeWire-AI 
> An intelligent packet analysis and reporting system that leverages LLMs to detect and explain network anomalies in PCAP files.

---
![Screenshot 2025-06-10 160001](https://github.com/user-attachments/assets/58b5564c-e36e-40b9-b87d-385ad2a57251)




## 📌 Overview

**TradeWire AI* is a Python-based tool that:
- Parses and analyzes PCAP (packet capture) files from network sessions
- Detects issues like packet loss, retransmissions, and malformed packets
- Uses **Microsoft Phi via Ollama** to generate plain-language explanations for anomalies
- Provides a user-friendly **Streamlit interface** with protocol filtering
- Generates downloadable reports in **JSON** and **PDF** formats

Originally designed for financial trading networks, it can be extended to support diagnostics in cybersecurity, enterprise networking, and developer operations.

---

## 🛠️ Tech Stack

- **Python 3.12**
- [Scapy](https://scapy.net/) / [PyShark](https://github.com/KimiNewt/pyshark)
- [Streamlit](https://streamlit.io/)
- [Ollama](https://ollama.com/) (local LLM host)
- Microsoft **Phi-2** language model
- PDF generation via `fpdf` 

---

## 🚀 Features

- 🧠 AI-powered packet diagnostics with **LLM explanations**
- 📦 Reads and parses PCAP files using Scapy or PyShark
- 🔎 Protocol-based filtering (TCP, UDP, ICMP)
- ⏱ Includes timestamps for latency analysis
- 🧾 JSON & PDF report generation
- 🌐 Simple, interactive Streamlit UI

---


