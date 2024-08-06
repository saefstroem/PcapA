pub mod global_header;
pub mod header;

use crate::{
    pcap::packet_header::PacketHeader,
    protocol::{parse::parse, Protocol},
};

use super::global_header::GlobalHeader;

#[derive(Debug)]
pub struct Packet {
    pub header: PacketHeader,
    pub data: Vec<u8>,
    pub protocols: Vec<Protocol>,
}

impl Packet {
    pub fn new(header: PacketHeader, data: Vec<u8>, global_header: &GlobalHeader) -> Packet {
        let protocols = parse(&data, global_header);
        Packet {
            header,
            data,
            protocols,
        }
    }
}
