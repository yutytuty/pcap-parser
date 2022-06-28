/// Example for reading a file:
/// ```rust
/// pub fn read_packet(packet: Packet) -> Result<&[u8], ParserError> {
/// if !is_ipv4_packet(packet.clone()) {
///     return Err(NotIPv4Packet);
/// }
/// if !is_udp_packet(packet.clone()) {
///     return Err(NotUdpPacket);
/// }
/// return Ok(get_payload(packet));
/// }
/// ```
///
/// ```rust
/// fn read_next(cap: &mut Capture<Offline>) -> Result<&[u8], ParserError> {
///     match cap.next() {
///         Ok(p) => {
///             return match read_packet(p) {
///                 Ok(d) => Ok(d),
///                 Err(e) => Err(e)
///             }
///         }
///         Err(e) => {
///             if e == NoMorePackets {
///                 return Err(EndOfFile);
///             }
///             return Err(UnknownError(e.to_string()));
///         }
///     }
/// }
/// ```
/// 
/// 

#[allow(dead_code)]
pub mod parser {
    use pcap::{Capture, Offline, Packet};

    const IPV4_MAGIC_NUMBER: u16 = 0x0800;
    const UDP_MAGIC_NUMBER: u8 = 0x11;

    const ETHER_HDR_LEN: usize = 14;
    const UDP_HDR_LEN: usize = 8;

    fn two_u8_to_u16(n1: u8, n2: u8) -> u16 {
        let num = (n1 as u16) << 8;
        return num | n2 as u16;
    }
    
    #[derive(Debug)]
    pub enum ParserError {
        NotUdpPacket,
        NotIPv4Packet,
        EndOfFile,
        UnknownError(String)
    }

    pub fn open_file(path: &str) -> Capture<Offline> {
        Capture::from_file(
            path
        ).unwrap()
    }

    pub fn is_ipv4_packet(packet: Packet) -> bool {
        let bytes = &packet.data[ETHER_HDR_LEN - 2 .. ETHER_HDR_LEN];
        let version = two_u8_to_u16(bytes[0], bytes[1]);
        version == IPV4_MAGIC_NUMBER
    }

    pub fn is_udp_packet(packet: Packet) -> bool {
        let offset = ETHER_HDR_LEN;
        let byte = packet.data[offset + 9];
        byte == UDP_MAGIC_NUMBER
    }

    pub fn get_payload_length(packet: Packet) -> u16 {
        let offset = ETHER_HDR_LEN + get_ip_hdr_len(packet.clone());
        let bytes = &packet.data[offset + 4 .. offset + 6];
        // The payload length in the UDP header includes the size of the header.
        two_u8_to_u16(bytes[0], bytes[1]) - UDP_HDR_LEN as u16
    }

    pub fn get_payload(packet: Packet) -> &[u8] {
        let offset = ETHER_HDR_LEN + get_ip_hdr_len(packet.clone()) + UDP_HDR_LEN;
        &packet.data[offset ..]
    }

    pub fn get_ip_hdr_len(packet: Packet) -> usize {
        let length = (packet.data[ETHER_HDR_LEN] & 0x0F) * 4;
        length as usize
    }
}
