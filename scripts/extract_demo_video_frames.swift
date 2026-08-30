import AppKit
import AVFoundation
import Foundation

let args = CommandLine.arguments
guard args.count >= 4 else {
    fputs("usage: extract_demo_video_frames.swift <video> <output-dir> <prefix> [seconds...]\n", stderr)
    exit(2)
}

let asset = AVURLAsset(url: URL(fileURLWithPath: args[1]))
let generator = AVAssetImageGenerator(asset: asset)
generator.appliesPreferredTrackTransform = true
generator.requestedTimeToleranceBefore = .zero
generator.requestedTimeToleranceAfter = .zero

let outputDirectory = URL(fileURLWithPath: args[2], isDirectory: true)
try FileManager.default.createDirectory(at: outputDirectory, withIntermediateDirectories: true)

let requestedTimes = args.count > 4
    ? args[4...].compactMap(Double.init)
    : [1.0, 8.0, 16.0, 24.0, 29.0]

for second in requestedTimes {
    let image = try await generator.image(at: CMTime(seconds: second, preferredTimescale: 600)).image
    let representation = NSBitmapImageRep(cgImage: image)
    guard let data = representation.representation(using: .jpeg, properties: [.compressionFactor: 0.9]) else {
        throw NSError(domain: "DemoFrames", code: 1)
    }
    let name = "\(args[3])-\(Int(second)).jpg"
    try data.write(to: outputDirectory.appendingPathComponent(name))
}

print("verification frames ready: \(outputDirectory.path)")
