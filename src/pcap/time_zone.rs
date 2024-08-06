use std::io::{self, Read};

use crate::{pcap::byte_order::ByteOrder, read_bytes::read_i32_with_byte_order};

/**
 ### Time zone correction in seconds between GMT (UTC) and the local timezone of the following packet header timestamps.
    **Examples**: 3600 for GMT+1, -3600 for GMT-1.
    Possible values:
    * `UTC`: No correction
    * `Local`: Correction in seconds. Positive values are ahead of UTC, negative values are behind UTC.
 */
#[derive(Debug)]
pub enum TimeZone {
    Utc,
    Local(i32)
}


/**
 * Parse the time zone from the reader
 */
pub fn parse_time_zone<R: Read>(reader: &mut R, byte_order: &ByteOrder) -> io::Result<TimeZone> {
    let thiszone = read_i32_with_byte_order(reader, byte_order)?;
    if thiszone == 0 {
        Ok(TimeZone::Utc)
    } else {
        Ok(TimeZone::Local(thiszone))
    }
}
