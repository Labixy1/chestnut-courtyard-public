import AVFoundation
import Foundation

let args = CommandLine.arguments
guard args.count == 5 || args.count == 6 else {
    fputs("usage: add_demo_audio.swift <video> <narration> <music> <output> [narration-offset-seconds]\n", stderr)
    exit(2)
}

let videoAsset = AVURLAsset(url: URL(fileURLWithPath: args[1]))
let narrationAsset = AVURLAsset(url: URL(fileURLWithPath: args[2]))
let musicAsset = AVURLAsset(url: URL(fileURLWithPath: args[3]))
let outputURL = URL(fileURLWithPath: args[4])
let narrationOffset = CMTime(seconds: args.count == 6 ? Double(args[5]) ?? 0.35 : 0.35, preferredTimescale: 600)
try? FileManager.default.removeItem(at: outputURL)

let composition = AVMutableComposition()
guard let sourceVideo = try await videoAsset.loadTracks(withMediaType: .video).first,
      let videoTrack = composition.addMutableTrack(withMediaType: .video, preferredTrackID: kCMPersistentTrackID_Invalid) else {
    throw NSError(domain: "DemoAudio", code: 1)
}
let videoDuration = try await videoAsset.load(.duration)
try videoTrack.insertTimeRange(CMTimeRange(start: .zero, duration: videoDuration), of: sourceVideo, at: .zero)
videoTrack.preferredTransform = try await sourceVideo.load(.preferredTransform)

var narrationParameters: AVMutableAudioMixInputParameters?
if let sourceNarration = try await narrationAsset.loadTracks(withMediaType: .audio).first,
   let narrationTrack = composition.addMutableTrack(withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) {
    let availableDuration = CMTimeSubtract(videoDuration, narrationOffset)
    let narrationDuration = min(try await narrationAsset.load(.duration), availableDuration)
    try narrationTrack.insertTimeRange(CMTimeRange(start: .zero, duration: narrationDuration), of: sourceNarration, at: narrationOffset)
    let parameters = AVMutableAudioMixInputParameters(track: narrationTrack)
    parameters.setVolume(1.0, at: .zero)
    narrationParameters = parameters
}

var musicParameters: AVMutableAudioMixInputParameters?
if let sourceMusic = try await musicAsset.loadTracks(withMediaType: .audio).first,
   let musicTrack = composition.addMutableTrack(withMediaType: .audio, preferredTrackID: kCMPersistentTrackID_Invalid) {
    let musicDuration = min(try await musicAsset.load(.duration), videoDuration)
    try musicTrack.insertTimeRange(CMTimeRange(start: .zero, duration: musicDuration), of: sourceMusic, at: .zero)
    let parameters = AVMutableAudioMixInputParameters(track: musicTrack)
    parameters.setVolumeRamp(fromStartVolume: 0.0, toEndVolume: 0.09, timeRange: CMTimeRange(start: .zero, duration: CMTime(seconds: 1.2, preferredTimescale: 600)))
    parameters.setVolume(0.09, at: CMTime(seconds: 1.2, preferredTimescale: 600))
    parameters.setVolumeRamp(fromStartVolume: 0.09, toEndVolume: 0.0, timeRange: CMTimeRange(start: CMTimeSubtract(videoDuration, CMTime(seconds: 2.0, preferredTimescale: 600)), duration: CMTime(seconds: 2.0, preferredTimescale: 600)))
    musicParameters = parameters
}

let audioMix = AVMutableAudioMix()
audioMix.inputParameters = [musicParameters, narrationParameters].compactMap { $0 }
guard let exporter = AVAssetExportSession(asset: composition, presetName: AVAssetExportPresetHighestQuality) else {
    throw NSError(domain: "DemoAudio", code: 2)
}
exporter.audioMix = audioMix
try await exporter.export(to: outputURL, as: .mp4)
print("narrated demo ready: \(outputURL.path)")
