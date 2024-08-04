use std::io::{self, Read};

use crate::{
    pcap::{
        accuracy::parse_accuracy,
        byte_order::parse_byte_order,
        global_header::GlobalHeader,
        network::parse_network,
        time_zone::parse_time_zone,
    },
    read_bytes::{read_u16_with_byte_order, read_u32_with_byte_order},
};

pub fn parse_global_header<R: Read>(reader: &mut R) -> io::Result<GlobalHeader> {
    // First 4 bytes are the magic number, we call it byte_order for clarity
    let byte_order = parse_byte_order(reader)?;
    // Major version number of the file format
    let version_major = read_u16_with_byte_order(reader, &byte_order)?;
    // Minor version number of the file format
    let version_minor = read_u16_with_byte_order(reader, &byte_order)?;
    // Correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps
    let time_zone = parse_time_zone(reader, &byte_order)?;
    let accuracy = parse_accuracy(reader, &byte_order)?;
    let max_bytes = read_u32_with_byte_order(reader, &byte_order)?;
    let network = parse_network(reader, &byte_order)?;

    Ok(GlobalHeader {
        byte_order,
        version_major,
        version_minor,
        time_zone,
        accuracy,
        max_bytes,
        network,
    })
}

