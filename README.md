# NEWireGuard

This project aims to bring WireGuard to iOS and macOS as a custom VPN
client using the NEPacketTunnelProvider family of APIs.

## Goals

 1. Create apps for iOS and macOS that each provide a VPN extension
    to connect to WireGuard servers

 2. Create a couple of libraries that can be used to add WireGuard
    client-side capabilities to iOS and macOS apps.
    
    Folks who run WireGuard servers (like VPN service providers,
    companies who want their employees to access their intranet
    externally, etc.) can develop apps using these libraries to help
    their users on iOS/macOS to connect to the servers. These apps
    can handle the out-of-band transfer of public keys and IP
    addresses, thereby making it simpler to use WireGuard.

## Status

This project is still under development and is not ready for use.

## Building

This project requires Swift 4.0 and is modelled as a Swift Package
Manager package.

To build, run `swift build`, and to run the unit tests, run `swift
test`.

