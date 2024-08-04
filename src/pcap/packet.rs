use super::packet_header::PacketHeader;

#[derive(Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub data: Vec<u8>,
}