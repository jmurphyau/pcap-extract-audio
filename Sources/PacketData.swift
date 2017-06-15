//
//  PacketData.swift
//  pcap-extract-audio
//
//  Created by James Murphy on 29/5/17.
//
//

import Foundation


protocol PacketData {
    var content: [UInt8] { get }
    var length: Int { get }
}
