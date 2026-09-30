// swift-tools-version:5.3
import PackageDescription

let package = Package(
    name: "tauri-plugin-native-dpop",
    platforms: [.iOS(.v13)],
    products: [.library(name: "tauri-plugin-native-dpop", type: .static, targets: ["tauri-plugin-native-dpop"])],
    dependencies: [.package(name: "Tauri", path: "../.tauri/tauri-api")],
    targets: [.target(name: "tauri-plugin-native-dpop", dependencies: [.byName(name: "Tauri")], path: "Sources")]
)
