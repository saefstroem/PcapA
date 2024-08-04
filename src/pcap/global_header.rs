use linktype::LinkType;

use super::{accuracy::Accuracy, byte_order::ByteOrder, time_zone::TimeZone};

/**
 ## Global header of a pcap file/network packet capture
    * `byte_order/magic number`: Describes the endianness of the file and the timestamp resolution.
    * `version_major`: The major version number of the file format.
    * `version_minor`: The minor version number of the file format.
    * `time_zone/thiszone`: The correction time in seconds between GMT (UTC) and the local timezone of the following packet header timestamps. Examples: 3600 for GMT+1, -3600 for GMT-1.
    * `accuracy/sigfigs`: The accuracy of the timestamps in the capture file. If the timestamps are not accurate this value is not 0 and will be the number of digits that can be regarded as accurate. Example:
        1. Original Timestamp: `1722774586`

        2. Significant Figures (Sigfigs): 5 significant figures.

        3. Interpretation:
            - Consider only the first five digits from the left as reliable: `17227`
            - All subsequent figures in the timestamp should be regarded as unreliable or not guaranteed for precision, thereby replaced with zeros: `1722700000`.
        
        **Note**: The timestamps are not modified automatically, so if the timestamps are inaccurate it is your responsibility to interpret them correctly.
    * `max_bytes/snaplen`: The maximum number of bytes captured from each packet. The number of bytes captured can be lower but never higher than this value.
*/
#[derive(Debug)]
pub struct GlobalHeader {
    pub byte_order: ByteOrder,
    pub version_major: u16,
    pub version_minor: u16,
    pub time_zone: TimeZone,
    pub accuracy: Accuracy,
    pub max_bytes: u32,
    pub network: LinkType,
}