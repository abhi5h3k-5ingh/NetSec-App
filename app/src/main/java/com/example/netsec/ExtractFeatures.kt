package com.example.netsec

import android.util.Log
import org.pcap4j.core.PcapHandle
import java.io.File
import org.pcap4j.packet.IpV4Packet
import java.io.EOFException
import org.pcap4j.core.Pcaps


class ExtractFeatures {

    fun isFilePathValid(filePath: String): Boolean {
        val file = File(filePath)
        return file.exists() && file.isFile
    }

    fun extract() {
        // Replace this with the actual path to your pcap file
//        val pcapFile = "/storage/self/primary/Download/PCAPdroid/traffic2.pcap"
        val pcapFile = "/storage/self/primary/Download/PCAPdroid/traffic1.pcap"

        if (isFilePathValid(pcapFile)) {
            Log.d("file: ", "File path is valid.")
            // Your logic here
            // Using try-with-resources to ensure the handle is closed properly
            Pcaps.openOffline(pcapFile).use { handle ->
                var flowStartTimestamp: Long = 0
                var flowEndTimestamp: Long = 0
                var totalLength: Long = 0

                try {
                    // Loop through each packet in the pcap file
                    while (true) {
                        val packet = handle.nextPacketEx
//                        println("Packet: $packet")

                        if (packet is IpV4Packet) {
                            val length = packet.length().toLong()
                            val timestamp = System.currentTimeMillis()

                            // If it's the first packet, set the start timestamp
                            if (flowStartTimestamp == 0L) {
                                flowStartTimestamp = timestamp
                            }

                            // Update the end timestamp and total length for each packet
                            flowEndTimestamp = timestamp
                            totalLength += length

                            // Perform other processing if needed
                        }
                    }
                } catch (e: EOFException) {
                    // End of file
                }

                // Calculate features
                val flowDuration = flowEndTimestamp - flowStartTimestamp
                val flowBytesPerSecond =
                    totalLength.toDouble() / (flowDuration / 1000.0) // in bytes per second
                val totalLengthOfFwdPackets = totalLength
                val fwdIatTotal = flowDuration

                // Print the calculated features
                val stats = """
               *** Stats ***
               Flow Bytes/s: $flowBytesPerSecond
               Total Length of Fwd Packets: $totalLengthOfFwdPackets
               Fwd IAT Total: $fwdIatTotal
               Flow Duration: $flowDuration
               """
                Log.i("stats", stats)
            }
        } else {
            Log.d("File : ","File path is not valid.")
        }
    }
}
