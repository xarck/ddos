import streamlit as st
import pickle
import numpy as np

with open('model/kmeans_model.pkl', 'rb') as file:
    loaded_kmeans = pickle.load(file)

with open('model/scaler.pkl', 'rb') as file:
    loaded_scaler = pickle.load(file)

def preprocess_data(input_data):
    input_data_scaled = loaded_scaler.transform(input_data.reshape(1, -1))
    return input_data_scaled


st.set_page_config(
    page_title="DDoS Attack Detection",
    page_icon="🛡️",
    layout="wide",
    initial_sidebar_state="expanded"
)

# Define app styles
app_styles = """
    <style>
        .title {
            font-size: 36px;
            font-weight: bold;
            text-align: center;
            margin-bottom: 30px;
        }
        .input-container {
            background-color: #f0f0f0;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .input-label {
            font-weight: bold;
            margin-bottom: 5px;
        }
        .predict-btn {
            background-color: #4CAF50;
            color: white;
            padding: 10px 20px;
            border: none;
            border-radius: 5px;
            font-size: 16px;
        }
        .prediction-result {
            font-size: 18px;
            font-weight: bold;
            margin-top: 20px;
        }
    </style>
"""

def app():
    # st.title("DDoS Attack Detection")
    st.markdown(f'<div class="title">DDoS Attack Detection</div>', unsafe_allow_html=True)
    st.markdown(app_styles, unsafe_allow_html=True)

    col1, col2, col3, col4, col5 = st.columns(5)

    with col1:
        dest_port = st.number_input("Destination Port", value=80.0)
        flow_duration = st.number_input("Flow Duration", value=1.29379200e+06)
        total_fwd_packets = st.number_input("Total Fwd Packets", value=3.0)
        total_length_fwd_packets = st.number_input("Total Length of Fwd Packets", value=26.0)
        fwd_packet_length_min = st.number_input("Fwd Packet Length Min", value=0.0)

    with col2:
        bwd_packet_length_max = st.number_input("Bwd Packet Length Max", value=584.0)
        bwd_packet_length_min = st.number_input("Bwd Packet Length Min", value=0.0)
        flow_bytes_per_sec = st.number_input("Flow Bytes/s", value=8.99139893e+03)
        flow_packets_per_sec = st.number_input("Flow Packets/s", value=7.72921768e+00)
        flow_iat_min = st.number_input("Flow IAT Min", value=2.0)

    with col3:
        fwd_iat_min = st.number_input("Fwd IAT Min", value=3.0)
        bwd_iat_total = st.number_input("Bwd IAT Total", value=1.29374600e+06)
        fwd_psh_flags = st.number_input("Fwd PSH Flags", value=0.0)
        bwd_psh_flags = st.number_input("Bwd PSH Flags", value=0.0)
        fwd_urg_flags = st.number_input("Fwd URG Flags", value=0.0)

    with col4:
        bwd_urg_flags = st.number_input("Bwd URG Flags", value=0.0)
        bwd_packets_per_sec = st.number_input("Bwd Packets/s", value=5.41045238e+00)
        min_packet_length = st.number_input("Min Packet Length", value=0.0)
        fin_flag_count = st.number_input("FIN Flag Count", value=0.0)
        rst_flag_count = st.number_input("RST Flag Count", value=0.0)

    with col5:
        ack_flag_count = st.number_input("ACK Flag Count", value=0.0)
        cwe_flag_count = st.number_input("CWE Flag Count", value=0.0)
        down_up_ratio = st.number_input("Down/Up Ratio", value=2.0)
        fwd_avg_bytes_per_bulk = st.number_input("Fwd Avg Bytes/Bulk", value=0.0)
        fwd_avg_packets_per_bulk = st.number_input("Fwd Avg Packets/Bulk", value=0.0)

    col6, col7, col8, col9, col10 = st.columns(5)

    with col6:
        fwd_avg_bulk_rate = st.number_input("Fwd Avg Bulk Rate", value=0.0)
        bwd_avg_bytes_per_bulk = st.number_input("Bwd Avg Bytes/Bulk", value=0.0)
        bwd_avg_packets_per_bulk = st.number_input("Bwd Avg Packets/Bulk", value=0.0)
        
    with col7:
        init_win_bytes_backward = st.number_input("Init_Win_bytes_backward", value=229.0)
        min_seg_size_forward = st.number_input("min_seg_size_forward", value=20.0)
        

    with col8:
        idle_min = st.number_input("Idle Min", value=0.0)
        active_mean = st.number_input("Active Mean", value=0.0)

    with col9:
        bwd_avg_bulk_rate = st.number_input("Bwd Avg Bulk Rate", value=0.0)
        init_win_bytes_forward = st.number_input("Init_Win_bytes_forward", value=8192.0)


    with col10:
        active_std = st.number_input("Active Std", value=0.0)
        idle_std = st.number_input("Idle Std", value=0.0)


    if st.button("Predict"):
        input_data = np.array([dest_port, flow_duration, total_fwd_packets, total_length_fwd_packets,
                                fwd_packet_length_min, bwd_packet_length_max, bwd_packet_length_min,
                                flow_bytes_per_sec, flow_packets_per_sec, flow_iat_min, fwd_iat_min,
                                bwd_iat_total, fwd_psh_flags, bwd_psh_flags, fwd_urg_flags,
                                bwd_urg_flags, bwd_packets_per_sec, min_packet_length, fin_flag_count,
                                rst_flag_count, ack_flag_count, cwe_flag_count, down_up_ratio,
                                fwd_avg_bytes_per_bulk, fwd_avg_packets_per_bulk, fwd_avg_bulk_rate,
                                bwd_avg_bytes_per_bulk, bwd_avg_packets_per_bulk, bwd_avg_bulk_rate,
                                init_win_bytes_forward, init_win_bytes_backward, min_seg_size_forward,
                                active_mean, active_std, idle_std, idle_min])

        input_data_scaled = preprocess_data(input_data)

        cluster_assignment = loaded_kmeans.predict(input_data_scaled)

        if cluster_assignment == 0:
            st.write("The input instance is classified as a DDoS attack.")
        else:
            st.write("The input instance is not classified as a DDoS attack.")

if __name__ == "__main__":
    app()