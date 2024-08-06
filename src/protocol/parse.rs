use linktype::LinkType;
use crate::pcap::global_header::GlobalHeader;
use super::{ethernet::{self, EtherType}, ipv4, Protocol};



fn parse_ethernet(data:&[u8]) -> Vec<Protocol> {
    // Sequentially parse the Ethernet header and the next protocol, and return the current list of protocols upon error.
    let ethernet_header = match ethernet::parse(data) {
        Ok(header) => header,
        Err(e) => {
            log::error!("Failed to parse Ethernet header: {}", e);
            return vec![];
        }
    };

    let mut protocols = vec![Protocol::Ethernet(ethernet_header)];

    // Parse the next protocol based on the EtherType.
    match ethernet_header.ether_type {
        EtherType::IPv4 => {
            let ip_header=match ipv4::parse(&data[ethernet::Header::size()..]) {
                Ok(header) => header,
                Err(e) => {
                    log::error!("Failed to parse IPv4 header: {}", e);
                    return protocols;
                }
            };
            protocols.push(Protocol::IPv4(ip_header));
        }
        EtherType::IPv6 => {
            log::warn!("Unsupported EtherType: {:?}", ethernet_header.ether_type);
        }
        _ => {
            log::warn!("Unsupported EtherType: {:?}", ethernet_header.ether_type);
        }
    }

    protocols


}

pub fn parse(data:&[u8],global_header:&GlobalHeader)-> Vec<Protocol> {

    match global_header.network {
        LinkType::Ethernet => {
            parse_ethernet(data)
        },
        _ => {
            log::error!("Network type not supported");
            unimplemented!("Network type not supported");
        }
    }
}