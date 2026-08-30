import AVFoundation
import Foundation

let args = CommandLine.arguments
guard args.count == 4 else {
    fputs("usage: add_demo_music.swift <video> <music> <output>\n", stderr)
    exit(2)
}

let videoAsset = AVURLAsset(url: URL(fileURLWithPath: args[1]))
let musicAsset = AVURLAsset(url: URL(fileURLWithPath: args[2]))
let outputURL = URL(fileURLWithPath: args[3])
try? FileManager.default.removeItem(at: outputURL)

let composition = AVMutableComposition()
guard let sourceVideo = try await videoAsset.loadTracks(withMediaType: .video).first,
      let videoTrack = composition.addMutableTrack(withMediaType: .video, preferredTrackID: kCMPersistentTrackID_Invalid),
      let sourceMusic = try await musicAsset.loadTracks(withMediaType: .audio).first,
      let musicTrack = composition.addMutableTrack(withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) else {
    throw NSError(domain: "DemoMusic", code: 1)
}

let videoDuration = try await videoAsset.load(.duration)
let musicDuration = min(try await musicAsset.load(.duration), videoDuration)
try videoTrack.insertTimeRange(CMTimeRange(start: .zero, duration: videoDuration), of: sourceVideo, at: .zero)
videoTrack.preferredTransform = try await sourceVideo.load(.preferredTransform)
try musicTrack.insertTimeRange(CMTimeRange(start: .zero, duration: musicDuration), of: sourceMusic, at: .zero)

let parameters = AVMutableAudioMixInputParameters(track: musicTrack)
let fadeIn = CMTime(seconds: 1.5, preferredTimescale: 600)
let fadeOut = CMTime(seconds: 2.5, preferredTimescale: 600)
parameters.setVolumeRamp(fromStartVolume: 0.0, toEndVolume: 0.32, timeRange: CMTimeRange(start: .zero, duration: fadeIn))
parameters.setVolume(0.32, at: fadeIn)
parameters.setVolumeRamp(
    fromStartVolume: 0.32,
    toEndVolume: 0.0,
    timeRange: CMTimeRange(start: CMTimeSubtract(videoDuration, fadeOut), duration: fadeOut)
)

let audioMix = AVMutableAudioMix()
audioMix.inputParameters = [parameters]
guard let exporter = AVAssetExportSession(asset: composition, presetName: AVAssetExportPresetHighestQuality) else {
    throw NSError(domain: "DemoMusic", code: 2)
}
exporter.audioMix = audioMix
try await exporter.export(to: outputURL, as: .mp4)
print("music demo ready: \(outputURL.path)")
