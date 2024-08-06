use std::io::{self, Read};

use crate::{
    pcap::{
     global_header::GlobalHeader, packet_header::PacketHeader
    },
    read_bytes::read_u32_with_byte_order,
};

use super::Packet;

pub fn parse_packet_header<R: Read>(
    reader: &mut R,
    global_header: &GlobalHeader,
) -> io::Result<PacketHeader> {
    let ts_secs = read_u32_with_byte_order(reader, &global_header.byte_order)?;
    let ts_micros = read_u32_with_byte_order(reader, &global_header.byte_order)?;
    let actual_bytes = read_u32_with_byte_order(reader, &global_header.byte_order)?;
    let captured_bytes = read_u32_with_byte_order(reader, &global_header.byte_order)?;

    let ts_micros=ts_micros as f64 / 100000.0;
    let ts_micros=ts_secs as f64 + ts_micros;
    Ok(PacketHeader {
        ts_secs,
        ts_micros,
        actual_bytes,
        captured_bytes,
    })
}

pub fn parse_packet<R: Read>(reader: &mut R, header: PacketHeader,global_header: &GlobalHeader) -> io::Result<Packet> {
    let mut data = vec![0u8; header.captured_bytes as usize];
    reader.read_exact(&mut data)?;
    Ok(Packet::new(header, data,global_header))
}
