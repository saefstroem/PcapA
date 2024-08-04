use std::io::{self, Read};

use crate::read_bytes::read_u32_with_byte_order;

/**
 ### Order of the bytes in the file
    * `Identical/BigEndian`: The bytes are in the same order as the host system.
    * `Swapped/LittleEndian`: The bytes need to be swapped to match the host system.
 */
#[derive(Debug)]
pub enum ByteOrder {
    BigEndian=0xa1b2c3d4,
    LittleEndian=0xd4c3b2a1
}

/**
 * Read and consume 4 bytes from the reader and return a u32
 */
pub fn parse_byte_order<R: Read>(reader: &mut R) -> io::Result<ByteOrder> {
    let magic_number = read_u32_with_byte_order(reader, &ByteOrder::BigEndian)?;
    println!("Magic number: {}", magic_number);
    match magic_number {
        x if x == ByteOrder::BigEndian as u32 => Ok(ByteOrder::BigEndian),
        x if x == ByteOrder::LittleEndian as u32 => Ok(ByteOrder::LittleEndian),
        _ => Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Invalid magic number",
        )),
    }
}