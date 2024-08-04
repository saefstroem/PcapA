use std::io::{self, Read};

use crate::pcap::byte_order::ByteOrder;



/**
 * Read and consume 4 bytes from the reader and return a u32
 */
pub fn read_u32_with_byte_order<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<u32> {
    let mut buffer = [0; 4];
    reader.read_exact(&mut buffer)?;
    match byte_order {
        ByteOrder::BigEndian => Ok(u32::from_be_bytes(buffer)),
        ByteOrder::LittleEndian => Ok(u32::from_le_bytes(buffer)),
    }
}

/**
 * Read and consume 2 bytes from the reader and return a u16
 */
pub fn read_u16_with_byte_order<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<u16> {
    let mut buffer = [0; 2];
    reader.read_exact(&mut buffer)?;
    match byte_order {
        ByteOrder::BigEndian => Ok(u16::from_be_bytes(buffer)),
        ByteOrder::LittleEndian => Ok(u16::from_le_bytes(buffer)),
    }
}

/**
 * Read and consume 4 bytes from the reader and return a i32
 */
pub fn read_i32_with_byte_order<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<i32> {
    let mut buffer = [0u8; 4];
    reader.read_exact(&mut buffer)?;
    match byte_order {
        ByteOrder::BigEndian => Ok(i32::from_be_bytes(buffer)),
        ByteOrder::LittleEndian => Ok(i32::from_le_bytes(buffer)),
    }
}