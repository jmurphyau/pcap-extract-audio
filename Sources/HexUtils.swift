

public struct HexUtils {

  public static func hexdump2(_ bytes: [UInt8]) -> String {
    return bytes.map{ String($0, radix: 16, uppercase: true) }.joined(separator: " ")
  }

}
