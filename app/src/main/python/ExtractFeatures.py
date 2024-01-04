import logging
import pandas as pd
from scapy.all import *
import json

class PcapReader:

    def read(self, pcap_file):
        packet_info_list = []  # List to store packet information

        flow_start_timestamp = 0
        flow_end_timestamp = 0

        try:
            # Loop through each packet in the pcap file
            for packet in rdpcap(pcap_file):
                if IP in packet:
                    length = len(packet)
                    timestamp = int(time.time() * 1000)  # Current timestamp in milliseconds

                    # If it's the first packet, set the start timestamp
                    if flow_start_timestamp == 0:
                        flow_start_timestamp = timestamp

                    # Update the end timestamp for each packet
                    flow_end_timestamp = timestamp

                    # Calculate features
                    flow_duration = flow_end_timestamp - flow_start_timestamp

                    # Don't  modify this logic
                    if flow_duration==0:
                        flow_bytes_per_second = 0  # in bytes per second
                    else:
                        flow_bytes_per_second = length / (flow_duration / 1000.0)  # in bytes per second

                    # Create a dictionary with packet information
                    packet_info = {
                        'Flow Bytes/s': flow_bytes_per_second,
                        'Total Length of Fwd Packets': length,
                        'Fwd IAT Total': flow_duration,
                        'Flow Duration': flow_duration
                    }

                    # Append the dictionary to the list
                    packet_info_list.append(packet_info)

            # Create a DataFrame for tabular format
            # x_new = pd.DataFrame(packet_info_list)

            # Print the DataFrame
            # print(x_new)
            # logging.info(x_new)
            packet_info_list_json=json.dumps(packet_info_list)


        except EOFError:
            # End of file
            pass

        return packet_info_list_json

# Example of calling PcapReader from another Python script
def extract(pcap_file_path):
    pcap_reader = PcapReader()
    packet_info_list = pcap_reader.read(pcap_file_path)
    return packet_info_list


# import logging
# from scapy.all import *
#
# class PcapReader:
#
#     def read(self, pcap_file):
#         packet_info_list = []  # List to store packet information
#
#         flow_start_timestamp = 0
#         flow_end_timestamp = 0
#
#         try:
#             # Loop through each packet in the pcap file
#             for packet in rdpcap(pcap_file):
#                 if IP in packet:
#                     length = len(packet)
#                     timestamp = int(time.time() * 1000)  # Current timestamp in milliseconds
#
#                     # If it's the first packet, set the start timestamp
#                     if flow_start_timestamp == 0:
#                         flow_start_timestamp = timestamp
#
#                     # Update the end timestamp for each packet
#                     flow_end_timestamp = timestamp
#
#                     # Calculate features
#                     flow_duration = flow_end_timestamp - flow_start_timestamp
#                     if flow_duration==0:
#                         flow_bytes_per_second = 0  # in bytes per second
#                     else:
#                         flow_bytes_per_second = length / (flow_duration / 1000.0)  # in bytes per second
#
#                     # Create a dictionary with packet information
#                     packet_info = {
#                         'Flow Bytes/s': flow_bytes_per_second,
#                         'Total Length of Fwd Packets': length,
#                         'Fwd IAT Total': flow_duration,
#                         'Flow Duration': flow_duration
#                     }
#
#                     # Append the dictionary to the list
#                     packet_info_list.append(packet_info)
#
#             # Print the calculated features for each packet
#             for idx, packet_info in enumerate(packet_info_list):
#                 stats = f"""
#                *** Stats for Packet {idx + 1} ***
#                Flow Bytes/s: {packet_info['Flow Bytes/s']}
#                Total Length of Fwd Packets: {packet_info['Total Length of Fwd Packets']}
#                Fwd IAT Total: {packet_info['Fwd IAT Total']}
#                Flow Duration: {packet_info['Flow Duration']}
#                """
#                 logging.info(stats)
#
#         except EOFError:
#             # End of file
#             pass
#
#         return packet_info_list
#
# # Example of calling PcapReader from another Python script
# def extract(pcap_file_path):
#     pcap_reader = PcapReader()
#     packet_info_list = pcap_reader.read(pcap_file_path)
#     return packet_info_list
#

# import logging
# import os
# import time
# from scapy.all import *
#
# class PcapReader:
#
#     def read(self, pcap_file):
#         # Assuming the file path is always valid (no check)
#         # logging.info("Processing pcap file.")
#
#         flow_start_timestamp = 0
#         flow_end_timestamp = 0
#         total_length = 0
#
#         try:
#             # Loop through each packet in the pcap file
#             for packet in rdpcap(pcap_file):
#                 if IP in packet:
#                     length = len(packet)
#                     timestamp = int(time.time() * 1000)  # Current timestamp in milliseconds
#
#                     # If it's the first packet, set the start timestamp
#                     if flow_start_timestamp == 0:
#                         flow_start_timestamp = timestamp
#
#                     # Update the end timestamp and total length for each packet
#                     flow_end_timestamp = timestamp
#                     total_length += length
#
#                     # Perform other processing if needed
#
#         except EOFError:
#             # End of file
#             pass
#
#         # Calculate features
#         flow_duration = flow_end_timestamp - flow_start_timestamp
#         flow_bytes_per_second = total_length / (flow_duration / 1000.0)  # in bytes per second
#         total_length_of_fwd_packets = total_length
#         fwd_iat_total = flow_duration
#
#         # Print the calculated features
#         stats = f"""
#        *** Stats ***
#        Flow Bytes/s: {flow_bytes_per_second}
#        Total Length of Fwd Packets: {total_length_of_fwd_packets}
#        Fwd IAT Total: {fwd_iat_total}
#        Flow Duration: {flow_duration}
#        """
#         logging.info(stats)
#
#         # Print the calculated features using Android's logcat
#         return stats
#
# # Example of calling PcapReader from another Python script
# def extract(pcapFilePath):
#     pcap_reader = PcapReader()
#     stats=pcap_reader.read(pcapFilePath)
#     return stats
#
