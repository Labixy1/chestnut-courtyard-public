import AVFoundation
import CoreImage
import Foundation

let args = CommandLine.arguments
guard args.count == 5 else {
    fputs("usage: build_captioned_demo_video.swift <slides-dir> <output.mp4> <width> <height>\n", stderr)
    exit(2)
}

let directory = URL(fileURLWithPath: args[1], isDirectory: true)
let outputURL = URL(fileURLWithPath: args[2])
let width = Int(args[3])!
let height = Int(args[4])!
let selectedSlides = Set([
    "01-home", "03-bedroom-night", "04-notice", "05-blackboard-question",
    "06-blackboard-review", "09-orchard-harvest", "10-orchard-topic",
    "11-memory-growth", "13-heart-memory", "14-travel",
])
let files = try FileManager.default.contentsOfDirectory(at: directory, includingPropertiesForKeys: nil)
    .filter { ["jpg", "jpeg", "png"].contains($0.pathExtension.lowercased()) }
    .filter { selectedSlides.contains($0.deletingPathExtension().lastPathComponent) }
    .sorted { $0.lastPathComponent < $1.lastPathComponent }
let durations = [2.20, 2.20, 4.40, 2.40, 3.00, 2.60, 3.20, 3.00, 4.20, 2.80]
guard files.count == durations.count else {
    throw NSError(domain: "CaptionedDemo", code: 1, userInfo: [NSLocalizedDescriptionKey: "expected 10 slides, got \(files.count)"])
}

try? FileManager.default.removeItem(at: outputURL)
let fps: Int32 = 24
let transitionSeconds = 0.85
let totalSeconds = durations.reduce(0, +)
let totalFrames = Int(round(totalSeconds * Double(fps)))
let writer = try AVAssetWriter(outputURL: outputURL, fileType: .mp4)
let input = AVAssetWriterInput(mediaType: .video, outputSettings: [
    AVVideoCodecKey: AVVideoCodecType.h264,
    AVVideoWidthKey: width,
    AVVideoHeightKey: height,
    AVVideoCompressionPropertiesKey: [
        AVVideoAverageBitRateKey: width > 1080 ? 5_000_000 : 4_500_000,
        AVVideoProfileLevelKey: AVVideoProfileLevelH264HighAutoLevel,
        AVVideoMaxKeyFrameIntervalKey: Int(fps * 2),
    ],
])
input.expectsMediaDataInRealTime = false
let adaptor = AVAssetWriterInputPixelBufferAdaptor(assetWriterInput: input, sourcePixelBufferAttributes: [
    kCVPixelBufferPixelFormatTypeKey as String: kCVPixelFormatType_32BGRA,
    kCVPixelBufferWidthKey as String: width,
    kCVPixelBufferHeightKey as String: height,
    kCVPixelBufferIOSurfacePropertiesKey as String: [:],
])
guard writer.canAdd(input) else { throw NSError(domain: "CaptionedDemo", code: 2) }
writer.add(input)

let images = files.compactMap { CIImage(contentsOf: $0) }
guard images.count == files.count else { throw NSError(domain: "CaptionedDemo", code: 3) }
let context = CIContext(options: [.cacheIntermediates: false])
let colorSpace = CGColorSpaceCreateDeviceRGB()
let bounds = CGRect(x: 0, y: 0, width: width, height: height)
let starts = durations.reduce(into: [0.0]) { values, duration in values.append(values.last! + duration) }

guard writer.startWriting() else { throw writer.error ?? NSError(domain: "CaptionedDemo", code: 4) }
writer.startSession(atSourceTime: .zero)
for frame in 0..<totalFrames {
    while !input.isReadyForMoreMediaData { usleep(2_000) }
    let second = Double(frame) / Double(fps)
    let index = min(durations.count - 1, starts.dropLast().lastIndex(where: { $0 <= second }) ?? 0)
    let local = second - starts[index]
    var image = images[index]
    if index < images.count - 1 && local > durations[index] - transitionSeconds {
        let progress = (local - (durations[index] - transitionSeconds)) / transitionSeconds
        if let filter = CIFilter(name: "CIDissolveTransition") {
            filter.setValue(images[index], forKey: kCIInputImageKey)
            filter.setValue(images[index + 1], forKey: kCIInputTargetImageKey)
            filter.setValue(progress, forKey: kCIInputTimeKey)
            image = filter.outputImage ?? image
        }
    }
    guard let pool = adaptor.pixelBufferPool else { throw NSError(domain: "CaptionedDemo", code: 5) }
    var buffer: CVPixelBuffer?
    CVPixelBufferPoolCreatePixelBuffer(nil, pool, &buffer)
    guard let pixelBuffer = buffer else { throw NSError(domain: "CaptionedDemo", code: 6) }
    context.render(image, to: pixelBuffer, bounds: bounds, colorSpace: colorSpace)
    guard adaptor.append(pixelBuffer, withPresentationTime: CMTime(value: Int64(frame), timescale: fps)) else {
        throw writer.error ?? NSError(domain: "CaptionedDemo", code: 7)
    }
}
input.markAsFinished()
await writer.finishWriting()
guard writer.status == .completed else { throw writer.error ?? NSError(domain: "CaptionedDemo", code: 8) }
print("captioned demo ready: \(outputURL.path) (\(String(format: "%.2f", totalSeconds))s)")
