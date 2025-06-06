import streamlit as st
import pandas as pd
import altair as alt
from pcap_parser import parse_pcap
from llm_interface import query_phi
from report_generator import generate_report, generate_pdf_report  # ✅ added

st.title("📈 TradeWire AI – Intelligent PCAP Analysis")

# File uploader
uploaded_file = st.file_uploader("Upload a PCAP File", type=["pcap"])
if uploaded_file:
    with open("sample_data/temp.pcap", "wb") as f:
        f.write(uploaded_file.read())

    st.info("📤 Parsing packets...")
    packets = parse_pcap("sample_data/temp.pcap")

    # LLM analysis (only first 10 packets)
    explanations = []
    for pkt in packets[:10]:
        prompt = f"Analyze this network packet info and explain any possible issues: {pkt}"
        explanation = query_phi(prompt)
        explanations.append(explanation)

    # Report generation
    output_path = generate_report(packets[:10], explanations)
    pdf_path = generate_pdf_report(packets[:10], explanations)  # ✅ generate PDF

    st.success("✅ Report generated successfully!")
    st.download_button("📥 Download JSON Report", data=open(output_path, "rb").read(), file_name="pcap_report.json")
    st.download_button("📄 Download PDF Report", data=open(pdf_path, "rb").read(), file_name="pcap_report.pdf")  # ✅ download button
