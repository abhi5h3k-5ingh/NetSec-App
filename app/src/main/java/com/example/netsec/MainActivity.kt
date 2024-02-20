package com.example.netsec

import android.Manifest
import android.annotation.SuppressLint
import android.content.ActivityNotFoundException
import android.content.Intent
import android.content.pm.PackageManager
import android.os.Bundle
import android.util.Log
import android.view.View
import android.widget.Button
import android.widget.TextView
import android.widget.Toast
import androidx.activity.result.ActivityResult
import androidx.activity.result.contract.ActivityResultContracts.StartActivityForResult
import androidx.appcompat.app.AppCompatActivity
import androidx.core.app.ActivityCompat
import androidx.core.content.ContextCompat
import com.chaquo.python.PyObject
import com.chaquo.python.Python
import com.chaquo.python.android.AndroidPlatform
import com.example.netsec.ml.TensorflowModel
import org.pcap4j.packet.IpV4Packet
import org.tensorflow.lite.DataType
import org.tensorflow.lite.support.tensorbuffer.TensorBuffer
import java.io.File
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json


class MainActivity : AppCompatActivity() {
    var mStart: Button? = null
    var mDetect: Button? = null
    var mCapThread: CaptureThread? = null
    var mLog: TextView? = null
    var predict: TextView? = null
    var mCaptureRunning = false

    private val captureStartLauncher =
        registerForActivityResult(StartActivityForResult()) { result: ActivityResult ->
            handleCaptureStartResult(result)
        }
    private val captureStopLauncher =
        registerForActivityResult(StartActivityForResult()) { result: ActivityResult ->
            handleCaptureStopResult(result)
        }
    private val captureStatusLauncher =
        registerForActivityResult(StartActivityForResult()) { result: ActivityResult ->
            handleCaptureStatusResult(result)
        }


    private val STORAGE_PERMISSION_CODE = 1

    private val pcapFilePath = "/storage/emulated/0/Download/PCAPdroid/traffic1.pcap"

    @SuppressLint("MissingInflatedId")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)


        mLog = findViewById(R.id.pkts_log)
        predict = findViewById(R.id.predict)
        mStart = findViewById(R.id.start_btn)
        mStart?.setOnClickListener(View.OnClickListener { v: View? -> if (!mCaptureRunning) startCapture() else stopCapture() })
        if (savedInstanceState != null && savedInstanceState.containsKey("capture_running")) setCaptureRunning(
            savedInstanceState.getBoolean("capture_running")
        ) else queryCaptureStatus()


        // Initialize Python
        if (!Python.isStarted()) {
            Python.start(AndroidPlatform(this))
        }

        mDetect = findViewById(R.id.detect_btn)
        mDetect?.setOnClickListener {
            // Check if permission is not granted
            predict?.setText("")

            if (ContextCompat.checkSelfPermission(
                    this,
                    Manifest.permission.READ_EXTERNAL_STORAGE
                ) != PackageManager.PERMISSION_GRANTED
            ) {
                // Request the permission
                ActivityCompat.requestPermissions(
                    this,
                    arrayOf(Manifest.permission.READ_EXTERNAL_STORAGE),
                    STORAGE_PERMISSION_CODE
                )
            } else {
                // Permission already granted, call your Python code here
                Log.d("Success: ", "Permission Granted")
                val stats = readPcapFile()
                makePrediction(stats)
            }
        }
    }

    override fun onRequestPermissionsResult(
        requestCode: Int,
        permissions: Array<out String>,
        grantResults: IntArray
    ) {
        super.onRequestPermissionsResult(requestCode, permissions, grantResults)
        if (requestCode == STORAGE_PERMISSION_CODE) {
            if (grantResults.isNotEmpty() && grantResults[0] == PackageManager.PERMISSION_GRANTED) {
                // Permission granted, call your Python code here
                Log.d("Success: ", "Permission Granted")
                val stats = readPcapFile()
                if (stats == 0) {
                    Log.e("FilePathError", "File path is not valid.")
                } else {
                    makePrediction(stats)
                }

            } else {
                // Permission denied, handle accordingly
                Log.e("PermissionError", "Read storage permission denied.")
            }
        }
    }

    private fun readPcapFile(): Any? {

//        val csvFile="/storage/emulated/0/traf.csv"
        // Check if the file path is valid

        if (isFilePathValid(pcapFilePath)) {
            // Read the CSV file in Kotlin
//            readCsvFile(csvFile)

            // Your existing Python code here
            val python = Python.getInstance()
            val extractFeatures = python.getModule("ExtractFeatures")

            // Call the 'extract' function with the file path as an argument
//            Log.d("Success", "Able to access file from MainActivity")

            val stats = extractFeatures.callAttr("extract", pcapFilePath)
//            Log.d("Python working", "Python interpreter is working")
//            Log.d("Python Code Returns: ", stats.toString())
            return stats
        } else {
            Log.e("FilePathError", "File path is not valid.")
            return 0
        }

    }

    private fun isFilePathValid(filePath: String): Boolean {
        val file = File(filePath)
        return file.exists() && file.isFile
    }

    private fun makePrediction(stats: Any?) {
//        val model = TensorflowModel.newInstance(this)
//
//        // Assuming packet_info_list_json is a PyObject returned from Python
//        val packetInfoListJson: PyObject = stats as PyObject
//
//// Convert PyObject to a JSON string
//        val packetInfoListJsonString: String = packetInfoListJson.toString()
//
//// Parse the JSON string to a list of maps
//        val packetInfoList: List<Map<String, Float>> = Json.decodeFromString(packetInfoListJsonString)
//
//// Log the received packetInfoList
//        Log.d("PacketInfoList: ", "$packetInfoList")
//
//// Convert the packet_info_list to a TensorBuffer  Tensor input expected shape is [1,4]
//        val inputFeature0 =
//            TensorBuffer.createFixedSize(intArrayOf(packetInfoList.size, 4), DataType.FLOAT32)
//        val inputData = inputFeature0.floatArray
//
//// Ensure inputData has the correct size
//        if (inputData.size != packetInfoList.size * 4) {
//            throw IllegalArgumentException("Input data size mismatch")
//        }
//        Log.d("inputData: ", "$inputData")
//// Copy data into the input tensor
//        for (i in packetInfoList.indices) {
//            inputData[i * 4] = packetInfoList[i]["Flow Bytes/s"] ?: 0.0f
//            inputData[i * 4 + 1] = packetInfoList[i]["Total Length of Fwd Packets"] ?: 0.0f
//            inputData[i * 4 + 2] = packetInfoList[i]["Fwd IAT Total"] ?: 0.0f
//            inputData[i * 4 + 3] = packetInfoList[i]["Flow Duration"] ?: 0.0f
//        }
//
//// Run model inference
//        Log.d("inputFeature0: ", "$inputData")
//
//        val outputs = model.process(inputFeature0)
//        val outputFeature0 = outputs.outputFeature0AsTensorBuffer
//
//// Perform actions based on the inference result
//        val threshold = 0.7
//        val meanPrediction = outputFeature0.floatArray.average()
//
//        if (meanPrediction < threshold) {
//            // Malicious Network found
//            println("Malicious Network found, Disconnect quickly")
//        } else {
//            // Safe Network
//            println("Safe Network")
//        }
//
//    }

        // Assuming packet_info_list_json is a PyObject returned from Python
        val packetInfoListJson: PyObject =
            stats as PyObject/* your Python code to get packet_info_list_json */
        val model = TensorflowModel.newInstance(this)
        // Convert PyObject to a JSON string
        val packetInfoListJsonString: String = packetInfoListJson.toString()

        // Parse the JSON string to a list of maps
        val packetInfoList: List<Map<String, Float>> =
            Json.decodeFromString(packetInfoListJsonString)

//        Log.d("PacketInfoList: ", "$packetInfoList")

        val inputDataList = packetInfoList.map { packet ->
            floatArrayOf(
                packet["Flow Bytes/s"] ?: 0.0f,
                packet["Total Length of Fwd Packets"] ?: 0.0f,
                packet["Fwd IAT Total"] ?: 0.0f,
                packet["Flow Duration"] ?: 0.0f
            )
        }

// Log the inputDataList in a readable format
//        Log.d("InputDataList:", inputDataList.joinToString("\n") { it.contentToString() })

// Step 3: Create a TensorBuffer from the Flattened Input Data
        val inputFeature0 =
            TensorBuffer.createFixedSize(intArrayOf(1, 4), DataType.FLOAT32)

// Step 4: Run Model Inference for each row
        val predictions = mutableListOf<Float>()
        for (row in inputDataList) {
            // Load the current row into the input tensor
            val buffer = TensorBuffer.createFixedSize(intArrayOf(1, row.size), DataType.FLOAT32)
            buffer.loadArray(row)
            inputFeature0.loadBuffer(buffer.buffer)

            // Log the input values for the current row
            Log.d("inputFeature0: ", inputFeature0.floatArray.contentToString())

            // Run Model Inference
            val outputs = model.process(inputFeature0)
            val outputFeature0 = outputs.outputFeature0AsTensorBuffer

            // Log the output values for the current row
            Log.d("pred: ", "${outputFeature0.floatArray[0]}")
            // Store the prediction for this row
            predictions.add(outputFeature0.floatArray[0])
        }

// Step 5: Calculate mean prediction
        val meanPrediction = predictions.average()

// Step 6: Perform Actions Based on Mean Inference Result
        val threshold = 0.7
        if (meanPrediction < threshold) {
            // Malicious Network found
            predict?.setText("Malicious Network Detected")
            Log.d("Prediction: $meanPrediction", "Malicious Network found, Disconnect quickly")
        } else {
            // Safe Network
            predict?.setText("Safe Network Detected")  // safe network
            Log.d("Prediction: $meanPrediction","Safe Network")
        }

//        // Step 1: Convert List of Dictionaries to List of Float Arrays
//        val inputDataList = packetInfoList.map { packet ->
//            floatArrayOf(
//                packet["Flow Bytes/s"] ?: 0.0f,
//                packet["Total Length of Fwd Packets"] ?: 0.0f,
//                packet["Fwd IAT Total"] ?: 0.0f,
//                packet["Flow Duration"] ?: 0.0f
//            )
//        }
//        // Log the inputDataList in a readable format
//        Log.d("InputDataList:", inputDataList.joinToString("\n") { it.contentToString() })
//
//// Step 2: Flatten the List of Float Arrays
////        val flatInputData = inputDataList.flatten()
//
//        // Log the flatInputData in a readable format
////        Log.d("FlatInputData:", flatInputData.map { it.toString() }.toString())
//
//// Step 3: Create a TensorBuffer from the Flattened Input Data
//        val inputFeature0 =
//            TensorBuffer.createFixedSize(intArrayOf(1, 4), DataType.FLOAT32)
////        for (i in flatInputData.indices) {
////            inputFeature0.floatArray[i] = flatInputData[i]
////        }
//
//// Step 4: Run Model Inference
//        val outputs = model.process(inputFeature0)
//        val outputFeature0 = outputs.outputFeature0AsTensorBuffer
//
//// Step 5: Perform Actions Based on Inference Result
//        val threshold = 0.7
//        val meanPrediction = outputFeature0.floatArray.average()
//
//        if (meanPrediction < threshold) {
//            // Malicious Network found
//            Log.d("Prediction: $meanPrediction", "Malicious Network found, Disconnect quickly")
//        } else {
//            // Safe Network
//            Log.d("Prediction: $meanPrediction","Safe Network")
//        }
    }

        // Assuming packet_info_list is a List<Map<String, Float>> representing each packet's features
//        val packet_info_list: List<Map<String, Float>> =
//            stats as List<Map<String, Float>>/* your data initialization */
//
//        val model = TensorflowModel.newInstance(this)
//        // Convert the packet_info_list to a TensorBuffer
//        val inputFeature0 = TensorBuffer.createFixedSize(intArrayOf(packet_info_list.size, 4), DataType.FLOAT32)
//        val inputData = inputFeature0.floatArray
//
//        for (i in packet_info_list.indices) {
//            inputData[i * 4] = packet_info_list[i]["Flow Bytes/s"] ?: 0.0f
//            inputData[i * 4 + 1] = packet_info_list[i]["Total Length of Fwd Packets"] ?: 0.0f
//            inputData[i * 4 + 2] = packet_info_list[i]["Fwd IAT Total"] ?: 0.0f
//            inputData[i * 4 + 3] = packet_info_list[i]["Flow Duration"] ?: 0.0f
//        }
//
//        // Run model inference
//        val outputs = model.process(inputFeature0)
//        val outputFeature0 = outputs.outputFeature0AsTensorBuffer
//
//        // Perform actions based on the inference result
//        val threshold = 0.7
//        val meanPrediction = outputFeature0.floatArray.average()
//
//        if (meanPrediction < threshold) {
//            // Malicious Network found
//            println("Malicious Network found, Disconnect quickly")
//        } else {
//            // Safe Network
//            println("Safe Network")
//        }
//
//    }

    override fun onDestroy() {
        super.onDestroy()
//        MyBroadcastReceiver.CaptureObservable.deleteObserver(this)
        stopCaptureThread()
    }

    fun update(arg: Any) {
        val capture_running = arg as Boolean
        Log.d(TAG, "capture_running: $capture_running")
        setCaptureRunning(capture_running)
    }

    override fun onSaveInstanceState(bundle: Bundle) {
        bundle.putBoolean("capture_running", mCaptureRunning)
        super.onSaveInstanceState(bundle)
    }

    fun onPacketReceived(pkt: IpV4Packet) {
        val hdr = pkt.header
        mLog?.append(
            "[${hdr.protocol}] ${hdr.srcAddr.hostAddress} -> ${hdr.dstAddr.hostAddress} [${pkt.length()} B]\n"
        )
    }

    fun queryCaptureStatus() {
        Log.d(TAG, "Querying PCAPdroid")
        val intent = Intent(Intent.ACTION_VIEW)
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY)
        intent.putExtra("action", "get_status")
        try {
            captureStatusLauncher.launch(intent)
        } catch (e: ActivityNotFoundException) {
            Toast.makeText(this, "PCAPdroid package not found: " + PCAPDROID_PACKAGE, Toast.LENGTH_LONG).show()
        }
    }

    fun startCapture() {
        Log.d(TAG, "Starting PCAPdroid")
        val intent = Intent(Intent.ACTION_VIEW)
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY)
        intent.putExtra("action", "start")
        intent.putExtra("broadcast_receiver", "com.emanuelef.pcap_receiver.MyBroadcastReceiver")
        intent.putExtra("collector_ip_address", "127.0.0.1")
        intent.putExtra("collector_port", "5123")

//         Packets not storing in file, it will display in screen
        intent.putExtra("pcap_dump_mode", "udp_exporter");

        // Packets storing in file.
//        intent.putExtra("pcap_dump_mode", "pcap_file")
//        intent.putExtra("pcap_name", "traffic1.pcap")
        captureStartLauncher.launch(intent)
    }

    fun stopCapture() {
        Log.d(TAG, "Stopping PCAPdroid")
        val intent = Intent(Intent.ACTION_VIEW)
        intent.setClassName(PCAPDROID_PACKAGE, CAPTURE_CTRL_ACTIVITY)
        intent.putExtra("action", "stop")
        intent.putExtra("pcap_name", "captured_packets")
        captureStopLauncher.launch(intent)
    }

    fun setCaptureRunning(running: Boolean) {
        mCaptureRunning = running
        mStart!!.text = if (running) "Stop Capture" else "Start Capture"
        if (mCaptureRunning && mCapThread == null) {
            mCapThread = CaptureThread(this)
            mCapThread!!.start()
        } else if (!mCaptureRunning) stopCaptureThread()
    }

    fun stopCaptureThread() {
        if (mCapThread == null) return
        mCapThread!!.stopCapture()
        mCapThread!!.interrupt()
        mCapThread = null
    }

    fun handleCaptureStartResult(result: ActivityResult) {
        Log.d(TAG, "PCAPdroid start result: $result")
        if (result.resultCode == RESULT_OK) {
            Toast.makeText(this, "Capture started!", Toast.LENGTH_SHORT).show()
            setCaptureRunning(true)
            mLog!!.text = ""
        } else Toast.makeText(this, "Capture failed to start", Toast.LENGTH_SHORT).show()
    }

    fun handleCaptureStopResult(result: ActivityResult) {
        Log.d(TAG, "PCAPdroid stop result: $result")
        if (result.resultCode == RESULT_OK) {
            Toast.makeText(this, "Capture stopped!", Toast.LENGTH_SHORT).show()
            setCaptureRunning(false)
        } else Toast.makeText(this, "Could not stop capture", Toast.LENGTH_SHORT).show()
        val intent = result.data
        if (intent != null && intent.hasExtra("bytes_sent")) logStats(intent)
    }

    fun handleCaptureStatusResult(result: ActivityResult) {
        Log.d(TAG, "PCAPdroid status result: $result")
        if (result.resultCode == RESULT_OK && result.data != null) {
            val intent = result.data
            val running = intent!!.getBooleanExtra("running", false)
            val verCode = intent.getIntExtra("version_code", 0)
            var verName = intent.getStringExtra("version_name")
            if (verName == null) verName = "<1.4.6"
            Log.d(TAG, "PCAPdroid $verName($verCode): running=$running")
            setCaptureRunning(running)
        }
    }

    fun logStats(intent: Intent) {
        val stats = """
               *** Stats ***
               Bytes sent: ${intent.getLongExtra("bytes_sent", 0)}
               Bytes received: ${intent.getLongExtra("bytes_rcvd", 0)}
               Packets sent: ${intent.getIntExtra("pkts_sent", 0)}
               Packets received: ${intent.getIntExtra("pkts_rcvd", 0)}
               Packets dropped: ${intent.getIntExtra("pkts_dropped", 0)}
               PCAP dump size: ${intent.getLongExtra("bytes_dumped", 0)}
               """
        Log.i("stats", stats)
    }

    companion object {
        const val PCAPDROID_PACKAGE = "com.emanuelef.remote_capture" // add ".debug" for the debug build of PCAPdroid
        const val CAPTURE_CTRL_ACTIVITY = "com.emanuelef.remote_capture.activities.CaptureCtrl"
        const val CAPTURE_STATUS_ACTION = "com.emanuelef.remote_capture.CaptureStatus"
        const val TAG = "PCAP Receiver"
    }
}

fun List<FloatArray>.flatten(): FloatArray {
    return this.flatMap { it.toList() }.toFloatArray()
}

