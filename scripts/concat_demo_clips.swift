import AVFoundation
import Foundation

let args = CommandLine.arguments
guard args.count == 4 else {
    fputs("usage: concat_demo_clips.swift <first.mp4> <second.mp4> <output.mp4>\n", stderr)
    exit(2)
}

let composition = AVMutableComposition()
guard let outputVideo = composition.addMutableTrack(withMediaType: .video, preferredTrackID: kCMPersistentTrackID_Invalid) else {
    throw NSError(domain: "DemoConcat", code: 1)
}

var cursor = CMTime.zero
var preferredTransform = CGAffineTransform.identity
for inputPath in args[1...2] {
    let asset = AVURLAsset(url: URL(fileURLWithPath: inputPath))
    guard let sourceVideo = try await asset.loadTracks(withMediaType: .video).first else {
        throw NSError(domain: "DemoConcat", code: 2, userInfo: [NSLocalizedDescriptionKey: "missing video track: \(inputPath)"])
    }
    let duration = try await asset.load(.duration)
    try outputVideo.insertTimeRange(CMTimeRange(start: .zero, duration: duration), of: sourceVideo, at: cursor)
    if cursor == .zero { preferredTransform = try await sourceVideo.load(.preferredTransform) }
    cursor = CMTimeAdd(cursor, duration)
}
outputVideo.preferredTransform = preferredTransform

let outputURL = URL(fileURLWithPath: args[3])
try? FileManager.default.removeItem(at: outputURL)
guard let exporter = AVAssetExportSession(asset: composition, presetName: AVAssetExportPresetHighestQuality) else {
    throw NSError(domain: "DemoConcat", code: 3)
}
try await exporter.export(to: outputURL, as: .mp4)
print("combined demo ready: \(outputURL.path)")
