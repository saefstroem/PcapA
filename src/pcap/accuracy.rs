use std::io::{self, Read};

use crate::{pcap::byte_order::ByteOrder, read_bytes::read_u32_with_byte_order};

/**
 ### The accuracy of the timestamps in the capture file.
 * If the timestamps are not accurate this value is not 0 and will be the number of digits that can be regarded as accurate.
 * Example:
    1. Original Timestamp: `1722774586`
    2. Significant Figures (Sigfigs): 5 significant figures.
    3. Interpretation:
        - Consider only the first five digits from the left as reliable: `17227`
        - All subsequent figures in the timestamp should be regarded as unreliable or not guaranteed for precision, thereby replaced with zeros: `1722700000`.
    **Note**: The timestamps are not modified automatically, so if the timestamps are inaccurate it is your responsibility to interpret them correctly.
 */
#[derive(Debug)]
pub enum Accuracy {
    Accurate,
    Inaccurate(u32)
}

/**
 * Parse the accuracy from the reader
 */
pub fn parse_accuracy<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<Accuracy> {
    let sigfigs = read_u32_with_byte_order(reader, byte_order)?;
    if sigfigs == 0 {
        Ok(Accuracy::Accurate)
    } else {
        Ok(Accuracy::Inaccurate(sigfigs))
    }
}