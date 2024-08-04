use std::io::{self, Read};

use linktype::LinkType;

use crate::{pcap::byte_order::ByteOrder, read_bytes::read_u32_with_byte_order};

/**
 * Parse the network from the reader
 */
pub fn parse_network<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<LinkType> {
    let network = read_u32_with_byte_order(reader, byte_order)?;
    Ok(LinkType::from_u32(network))
}
