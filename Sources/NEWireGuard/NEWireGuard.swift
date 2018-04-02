struct NEWireGuard {
    var symmetricState = Noise.SymmetricState(noiseProtocolName: Noise.noiseProtocolName.data(using: .utf8)!)
}
