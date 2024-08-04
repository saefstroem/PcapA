#[derive(Debug, Clone, Copy)]
/**
 ### Struct that represents the header of a packet.

   The header contains the following fields:
   * `ts_sec`: Timestamp seconds
   * `ts_micro`: Timestamp microseconds
   * `captured_bytes`: Number of bytes captured
   * `actual_bytes`: Number of bytes in the packet (off wire)

*/
pub struct PacketHeader {

    pub ts_secs: u32,
    pub ts_micros: f64,
    pub captured_bytes: u32,
    pub actual_bytes: u32,
}
