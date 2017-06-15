
import cpcap
import Foundation

struct Packet : PacketData {
    let content: [UInt8]
    
    var length: Int {
        return content.count
    }
    
    var ethernet: Ethernet {
        return Ethernet(content: Array(self.content[0..<14]))
    }
    
    var ipv4: IPv4 {
        return IPv4(content: Array(self.content[18...37]))
    }
    
    var source_ip_array: [UInt8] {
        return Array(self.content[18...37])
    }
    var source_ip: UInt32 {
        return UInt32(bigEndian: Data(bytes: self.source_ip_array).withUnsafeBytes { $0.pointee })
    }

    init(rawPacket: UnsafePointer<u_char>?, rawHeader: pcap_pkthdr) {
        self.content = [UInt8](UnsafeBufferPointer(start: rawPacket, count: Int(rawHeader.len)))
    }

}

/*
enum EthernetType {
    case
}
*/

struct Ethernet : PacketData {
    let content: [UInt8]
    
    var length: Int { return content.count }
    
    var source_address: EthernetAddress {
        return EthernetAddress(content: Array(self.content[0..<6]))
    }
    var destination_address: EthernetAddress {
        return EthernetAddress(content: Array(self.content[6..<12]))
    }
}

struct EthernetAddress : CustomStringConvertible, PacketData {
    let content: [UInt8]
    
    var length: Int { return content.count }
    
    public func toString() -> String {
        return self.content.map{ String($0, radix: 16) }.joined(separator: ":")
    }
    
    var description: String {
        return "EthernetAddress(\(self.toString()))"
    }
    
}

struct IPv4  {
    let content: [UInt8]
    
    var length: Int { return self.content.count }
    
    var source_address: IPv4Address {
        let content_len = self.content.count
        return IPv4Address(content: Array(self.content[(content_len-8)...content_len-1]))
    }
    
    var destination_address: IPv4Address {
        let content_len = self.content.count
        return IPv4Address(content: Array(self.content[(content_len-4)...content_len-1]))
    }
    
}

struct IPv4Address : CustomStringConvertible {
    private let content: UInt32
    
    let length: Int = 4
    
    init(content: [UInt8]) {
        self.content = UInt32(littleEndian: Data(bytes: content.prefix(4)).withUnsafeBytes { $0.pointee })
    }
    
    public func toString() -> String {
        let ip = self.content
        
        let byte1 = UInt8(ip & 0xff)
        let byte2 = UInt8((ip>>8) & 0xff)
        let byte3 = UInt8((ip>>16) & 0xff)
        let byte4 = UInt8((ip>>24) & 0xff)
        
        return "\(byte1).\(byte2).\(byte3).\(byte4)"
    }
    
    var description: String {
        return "IPv4Address(\(self.toString()))"
    }
    
}
 

