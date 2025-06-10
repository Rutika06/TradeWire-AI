import streamlit as st
import pandas as pd
import altair as alt
from pcap_parser import parse_pcap
from llm_interface import query_phi
from report_generator import generate_report, generate_pdf_report
from spark_processing import spark_filter_packets  

st.set_page_config(page_title="TradeWire AI", layout="wide")
st.title("📈 TradeWire AI – Intelligent PCAP Analysis")

# Upload PCAP file
uploaded_file = st.file_uploader("Upload a PCAP File", type=["pcap"])

if uploaded_file:
    with open("sample_data/temp.pcap", "wb") as f:
        f.write(uploaded_file.read())

    st.info("📤 Parsing packets...")
    packets = parse_pcap("sample_data/temp.pcap")

    # --- Protocol Filter UI ---
    st.subheader("🔍 Filter Packets by Protocol")
    proto_map = {6: "TCP", 17: "UDP", 1: "ICMP"}
    protocol_options = ["All"] + list(proto_map.values())
    selected_proto = st.selectbox("Select protocol to analyze", protocol_options)

    # --- Use PySpark to filter packets ---
    selected_proto_num = None
    if selected_proto != "All":
        reverse_map = {v: k for k, v in proto_map.items()}
        selected_proto_num = reverse_map[selected_proto]

    # ✅ PySpark filtering
    filtered_packets = spark_filter_packets(packets, protocol=selected_proto_num)

    if not filtered_packets:
        st.warning("No packets matched the selected protocol.")
    else:
        st.success(f"✅ {len(filtered_packets)} packets ready for analysis.")

        # --- LLM Explanation (first 10 packets only) ---
        st.info("🔎 Analyzing packets using Microsoft Phi (via Ollama)...")
        explanations = []
        for pkt in filtered_packets[:10]:
            # **Fix: Add correct protocol labels before sending to LLM**
            proto_name = proto_map.get(pkt['proto'], 'Unknown')
            prompt = f"Analyze this network packet info and explain any possible issues: {pkt} (Protocol: {proto_name})"
            explanation = query_phi(prompt)
            explanations.append(explanation)

        # --- Reports ---
        output_path = generate_report(filtered_packets[:10], explanations)
        pdf_path = generate_pdf_report(filtered_packets[:10], explanations)

        # --- Downloads ---
        st.success("📄 Reports Generated Successfully!")
        st.download_button("📥 Download JSON Report", data=open(output_path, "rb").read(), file_name="pcap_report.json")
        st.download_button("📄 Download PDF Report", data=open(pdf_path, "rb").read(), file_name="pcap_report.pdf")

        # --- Optional: Visualization (timestamp vs. packet size) ---
        st.subheader("📊 Packet Size Over Time")
        df = pd.DataFrame(filtered_packets[:100])  # limit to 100 for performance
        if "timestamp" in df:
            df["timestamp"] = pd.to_datetime(df["timestamp"], unit="s")
            chart = alt.Chart(df).mark_line().encode(
                x="timestamp:T",
                y="len:Q",
                tooltip=["src", "dst", "proto", "len"]
            ).properties(height=300)
            st.altair_chart(chart, use_container_width=True)
