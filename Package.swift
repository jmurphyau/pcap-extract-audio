// swift-tools-version:3.1

import PackageDescription

let package = Package(
    name: "pcap-extract-audio",
    dependencies: [.Package(url: "../cpcap", majorVersion: 0, minor: 1)]
)
