
import cpcap

struct OfflinePcap {
    let pcap: OpaquePointer?
    var currentHeader: pcap_pkthdr

    init(path: String) throws {
        let errbuf = UnsafeMutablePointer<Int8>.allocate(capacity: Int(PCAP_ERRBUF_SIZE))

        let ptr = UnsafeMutablePointer<pcap_pkthdr>.allocate(capacity: MemoryLayout<pcap_pkthdr>.size)
        currentHeader = ptr.pointee
        ptr.deinitialize()

        self.pcap = pcap_open_offline(path, errbuf)

        if (self.pcap == nil) {
            throw PcapOpenError.main(message: String(cString: errbuf))
        }
        
    }

    public func nextPacket() -> Packet? {
        let tmpPcap = self.pcap
        var tmpCurrentHeader = self.currentHeader
        let pkt = pcap_next(tmpPcap, &tmpCurrentHeader)
        if (pkt == nil) {
            return nil
        } else {
            return Packet(rawPacket: pkt, rawHeader: tmpCurrentHeader)
        }
        
    }

}
