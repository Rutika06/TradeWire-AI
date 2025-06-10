import json
import os
from fpdf import FPDF
import datetime

def serialize_packet_data(obj):
    """Custom serializer for packet data objects"""
    if hasattr(obj, '__dict__'):
        return obj.__dict__
    elif hasattr(obj, 'isoformat'):  # datetime objects
        return obj.isoformat()
    elif isinstance(obj, bytes):
        return obj.hex()  # Convert bytes to hex string
    elif hasattr(obj, '__str__'):
        return str(obj)
    else:
        return repr(obj)

def safe_packet_to_dict(pkt):
    """Safely convert packet to dictionary with proper serialization"""
    pkt_dict = {}
    
    # Try different methods to extract packet data
    try:
        # Method 1: Direct dict conversion
        if hasattr(pkt, '__dict__'):
            raw_dict = pkt.__dict__
        else:
            raw_dict = dict(pkt)
        
        # Serialize each field safely
        for key, value in raw_dict.items():
            try:
                # Test if value is JSON serializable
                json.dumps(value)
                pkt_dict[key] = value
            except TypeError:
                # If not serializable, convert to string representation
                pkt_dict[key] = serialize_packet_data(value)
                
    except Exception as e:
        # Fallback: convert everything to string
        try:
            # Try to get packet summary info
            pkt_dict = {
                "summary": str(pkt),
                "type": type(pkt).__name__,
                "error": f"Serialization error: {str(e)}"
            }
            
            # Try to extract common packet fields
            common_fields = ['src', 'dst', 'sport', 'dport', 'proto', 'len', 'time']
            for field in common_fields:
                if hasattr(pkt, field):
                    try:
                        value = getattr(pkt, field)
                        pkt_dict[field] = serialize_packet_data(value)
                    except:
                        pass
                        
        except Exception:
            # Ultimate fallback
            pkt_dict = {
                "error": "Could not serialize packet data",
                "type": type(pkt).__name__,
                "repr": repr(pkt)
            }
    
    return pkt_dict

def generate_report(packet_data, explanations, output_path="reports/output.json"):
    """Generate JSON report with proper error handling"""
    report = []

    for i, (pkt, explanation) in enumerate(zip(packet_data, explanations)):
        try:
            # Safely convert packet to dict
            pkt_dict = safe_packet_to_dict(pkt)
            
            # Ensure explanation is serializable
            if not isinstance(explanation, (str, int, float, bool, list, dict, type(None))):
                explanation = str(explanation)
            
            report.append({
                "packet_id": i + 1,
                "packet_info": pkt_dict,
                "explanation": explanation,
                "timestamp": datetime.datetime.now().isoformat()
            })
            
        except Exception as e:
            # Add error entry if packet processing fails
            report.append({
                "packet_id": i + 1,
                "packet_info": {"error": f"Failed to process packet: {str(e)}"},
                "explanation": explanation if isinstance(explanation, str) else str(explanation),
                "timestamp": datetime.datetime.now().isoformat()
            })

    # Ensure output directory exists
    os.makedirs(os.path.dirname(output_path), exist_ok=True)

    try:
        with open(output_path, "w", encoding='utf-8') as f:
            json.dump(report, f, indent=4, ensure_ascii=False, default=serialize_packet_data)
        print(f"Report successfully saved to: {output_path}")
        
    except Exception as e:
        print(f"Error saving JSON report: {e}")
        # Try saving a simplified version
        simplified_report = []
        for item in report:
            simplified_report.append({
                "packet_id": item.get("packet_id", "unknown"),
                "packet_summary": str(item.get("packet_info", {})),
                "explanation": str(item.get("explanation", "")),
                "timestamp": item.get("timestamp", "")
            })
        
        try:
            with open(output_path, "w", encoding='utf-8') as f:
                json.dump(simplified_report, f, indent=4, ensure_ascii=False)
            print(f"Simplified report saved to: {output_path}")
        except Exception as e2:
            print(f"Failed to save even simplified report: {e2}")
            raise

    return output_path

def generate_pdf_report(packet_data, explanations, pdf_path="reports/pcap_report.pdf"):
    """Generate PDF report with error handling"""
    os.makedirs(os.path.dirname(pdf_path), exist_ok=True)

    pdf = FPDF()
    pdf.set_auto_page_break(auto=True, margin=15)
    pdf.add_page()
    pdf.set_font("Arial", size=12)

    # Title
    pdf.cell(200, 10, txt="TradeWire AI - PCAP Analysis Report", ln=True, align='C')
    pdf.ln(10)
    
    # Timestamp
    pdf.set_font("Arial", size=8)
    pdf.cell(200, 10, txt=f"Generated: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align='C')
    pdf.ln(10)

    for i, (pkt, explanation) in enumerate(zip(packet_data, explanations), 1):
        try:
            pdf.set_font("Arial", 'B', 12)
            pdf.cell(200, 10, txt=f"Packet {i}", ln=True)
            pdf.set_font("Arial", size=10)
            
            # Convert packet to dict safely
            pkt_dict = safe_packet_to_dict(pkt)
            
            # Display packet info
            for key, value in pkt_dict.items():
                try:
                    # Truncate very long values
                    str_value = str(value)
                    if len(str_value) > 100:
                        str_value = str_value[:97] + "..."
                    
                    # Handle special characters that might cause issues in PDF
                    display_text = f"{key}: {str_value}"
                    # Replace non-ASCII characters
                    display_text = display_text.encode('ascii', 'ignore').decode('ascii')
                    
                    pdf.multi_cell(0, 8, txt=display_text)
                except Exception as e:
                    pdf.multi_cell(0, 8, txt=f"{key}: [Error displaying value: {str(e)}]")
            
            # Add explanation
            try:
                explanation_text = f"LLM Explanation: {str(explanation)}"
                explanation_text = explanation_text.encode('ascii', 'ignore').decode('ascii')
                pdf.multi_cell(0, 8, txt=explanation_text)
            except Exception as e:
                pdf.multi_cell(0, 8, txt=f"LLM Explanation: [Error displaying explanation: {str(e)}]")
                
            pdf.ln(5)
            
        except Exception as e:
            pdf.set_font("Arial", size=10)
            pdf.multi_cell(0, 8, txt=f"Packet {i}: Error processing packet - {str(e)}")
            pdf.ln(5)

    try:
        pdf.output(pdf_path)
        print(f"PDF report successfully saved to: {pdf_path}")
    except Exception as e:
        print(f"Error saving PDF report: {e}")
        raise
        
    return pdf_path
