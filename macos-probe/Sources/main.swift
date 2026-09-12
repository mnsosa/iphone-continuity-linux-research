import AVFoundation
import CoreMedia
import CoreVideo
import Foundation

final class FrameObserver: NSObject, AVCaptureVideoDataOutputSampleBufferDelegate, @unchecked Sendable {
    private let lock = NSLock()
    private var frames = 0
    private var firstPTS: CMTime?
    private var lastPTS: CMTime?

    func captureOutput(
        _ output: AVCaptureOutput,
        didOutput sampleBuffer: CMSampleBuffer,
        from connection: AVCaptureConnection
    ) {
        let pts = CMSampleBufferGetPresentationTimeStamp(sampleBuffer)
        lock.lock()
        frames += 1
        firstPTS = firstPTS ?? pts
        lastPTS = pts
        let shouldReport = frames == 1 || frames % 30 == 0
        let count = frames
        lock.unlock()

        if shouldReport {
            var fields: [String: Any] = ["frames": count, "pts": CMTimeGetSeconds(pts)]
            if let image = CMSampleBufferGetImageBuffer(sampleBuffer) {
                fields["width"] = CVPixelBufferGetWidth(image)
                fields["height"] = CVPixelBufferGetHeight(image)
                fields["pixelFormat"] = fourCC(CVPixelBufferGetPixelFormatType(image))
            }
            emit("frame", fields)
        }
    }

    func summary() -> [String: Any] {
        lock.lock()
        defer { lock.unlock() }
        var result: [String: Any] = ["frames": frames]
        if let firstPTS, let lastPTS {
            result["mediaDuration"] = CMTimeGetSeconds(lastPTS - firstPTS)
        }
        return result
    }
}

private let formatter: ISO8601DateFormatter = {
    let value = ISO8601DateFormatter()
    value.formatOptions = [.withInternetDateTime, .withFractionalSeconds]
    return value
}()

private func emit(_ event: String, _ fields: [String: Any] = [:]) {
    var record = fields
    record["event"] = event
    record["timestamp"] = formatter.string(from: Date())
    if let data = try? JSONSerialization.data(withJSONObject: record, options: [.sortedKeys]),
       let line = String(data: data, encoding: .utf8) {
        print(line)
        fflush(stdout)
    }
}

private func fourCC(_ value: OSType) -> String {
    let bytes: [UInt8] = [24, 16, 8, 0].map { UInt8((value >> OSType($0)) & 0xff) }
    if bytes.allSatisfy({ $0 >= 32 && $0 <= 126 }) {
        return String(bytes: bytes, encoding: .ascii) ?? String(format: "0x%08x", value)
    }
    return String(format: "0x%08x", value)
}

private func markerDirectory() -> URL? {
    guard let index = CommandLine.arguments.firstIndex(of: "--markers-dir"),
          CommandLine.arguments.indices.contains(index + 1) else { return nil }
    return URL(fileURLWithPath: CommandLine.arguments[index + 1], isDirectory: true)
}

private func writeMarker(_ name: String, in directory: URL?) {
    guard let directory else { return }
    let body = formatter.string(from: Date()) + "\n"
    try? body.write(to: directory.appendingPathComponent(name), atomically: true, encoding: .utf8)
}

private func sleepUntil(_ seconds: Double, since start: DispatchTime) {
    let target = start.uptimeNanoseconds + UInt64(seconds * 1_000_000_000)
    let now = DispatchTime.now().uptimeNanoseconds
    if target > now {
        Thread.sleep(forTimeInterval: Double(target - now) / 1_000_000_000)
    }
}

private func requestCameraAccess() -> Bool {
    switch AVCaptureDevice.authorizationStatus(for: .video) {
    case .authorized:
        return true
    case .notDetermined:
        let semaphore = DispatchSemaphore(value: 0)
        var granted = false
        AVCaptureDevice.requestAccess(for: .video) { value in
            granted = value
            semaphore.signal()
        }
        semaphore.wait()
        return granted
    default:
        return false
    }
}

@main
struct ContinuityCameraProbe {
    static func main() {
        let markers = markerDirectory()
        emit("authorization", ["granted": requestCameraAccess()])
        guard AVCaptureDevice.authorizationStatus(for: .video) == .authorized else {
            emit("fatal", ["message": "Camera access is not authorized"])
            exit(3)
        }

        let start = DispatchTime.now()
        emit("started", ["pid": ProcessInfo.processInfo.processIdentifier])
        writeMarker("started", in: markers)

        sleepUntil(5, since: start)
        let discovery = AVCaptureDevice.DiscoverySession(
            deviceTypes: [.continuityCamera, .external],
            mediaType: .video,
            position: .unspecified
        )
        let devices = discovery.devices
        emit("discovered", ["count": devices.count])
        for device in devices {
            emit("device", [
                "name": device.localizedName,
                "manufacturer": device.manufacturer,
                "modelID": device.modelID,
                "uniqueID": device.uniqueID,
                "deviceType": device.deviceType.rawValue,
                "connected": device.isConnected,
                "suspended": device.isSuspended,
                "position": device.position.rawValue,
                "formats": device.formats.map { $0.description }
            ])
        }
        writeMarker("discovered", in: markers)

        guard let camera = devices.first(where: { $0.deviceType == .continuityCamera })
                ?? devices.first(where: { $0.localizedName.localizedCaseInsensitiveContains("iPhone") }) else {
            emit("fatal", ["message": "No Continuity Camera iPhone was discovered"])
            exit(4)
        }

        sleepUntil(10, since: start)
        let session = AVCaptureSession()
        let observer = FrameObserver()
        let output = AVCaptureVideoDataOutput()
        output.alwaysDiscardsLateVideoFrames = true
        output.videoSettings = [
            kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_420YpCbCr8BiPlanarVideoRange
        ]
        output.setSampleBufferDelegate(observer, queue: DispatchQueue(label: "org.opencontinuity.frames"))

        do {
            let input = try AVCaptureDeviceInput(device: camera)
            guard session.canAddInput(input), session.canAddOutput(output) else {
                emit("fatal", ["message": "Capture input or output cannot be added"])
                exit(5)
            }
            session.beginConfiguration()
            session.addInput(input)
            session.addOutput(output)
            session.commitConfiguration()
        } catch {
            emit("fatal", ["message": error.localizedDescription])
            exit(6)
        }
        emit("configured", ["device": camera.localizedName])
        writeMarker("configured", in: markers)

        sleepUntil(15, since: start)
        emit("startRunning.begin")
        session.startRunning()
        emit("startRunning.end", ["running": session.isRunning])
        writeMarker("streaming", in: markers)

        sleepUntil(30, since: start)
        emit("stopRunning.begin", observer.summary())
        session.stopRunning()
        emit("stopRunning.end", ["running": session.isRunning])
        writeMarker("stopped", in: markers)
    }
}
