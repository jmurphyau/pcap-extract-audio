
#if os(Linux)
    import Glibc
#else
    import Darwin.C
#endif

print("Hello, world!")

let offlinePcapFinal: OfflinePcap? = try? OfflinePcap(path: "test-pcap.pcap")

if let offlinePcapFinal = offlinePcapFinal {
    
    print(offlinePcapFinal)
    
    

    var looping = true
    
    while looping {
        if let p = offlinePcapFinal.nextPacket() {
            print("[\(p.ethernet.source_address) -> \(p.ethernet.destination_address)] [\(p.ipv4.source_address) -> \(p.ipv4.destination_address)]")
        } else {
            looping = false
        }
    }
    


}
