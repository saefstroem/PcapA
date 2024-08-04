pub mod global_header;
pub mod header;


use crate::{pcap::{byte_order::ByteOrder, packet_header::PacketHeader}, protocol::ethernet::{parse_ethernet_header, EthernetHeader}};


#[derive(Debug,Clone)]
pub struct Packet {
    pub header: PacketHeader,
    pub data: Vec<u8>,
    pub ethernet_header: Option<EthernetHeader>,
}

impl Packet {
    pub fn new(header: PacketHeader, data: Vec<u8>,byte_order:&ByteOrder,parse_packet:bool) -> Packet {
        if parse_packet {
            let ethernet_header = parse_ethernet_header(data.clone(),byte_order).unwrap();
            Packet {
                header,
                data,
                ethernet_header: Some(ethernet_header),
            }
        } else {
            Packet {
                header,
                data,
                ethernet_header: None,
            }
        }
    }

   

}