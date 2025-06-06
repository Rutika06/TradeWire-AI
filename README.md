# TradeWire-AI 
> An intelligent packet analysis and reporting system that leverages LLMs to detect and explain network anomalies in PCAP files.

---

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


