#[derive(Debug)]
/**
 #### TCP Flags Overview:
- **Reserved (RES)**: Bits set aside for future use. Typically expected to be zero.
- **AccurateECN (AccECN)**: An extension of ECN for more accurate network congestion feedback.
- **Congestion Window Reduced (CWR)**: Indicates that the sender has received a packet with the ECNEcho flag set and has reduced its congestion window.
- **ECN-Echo (ECE)**: Used by the receiver to signal to the sender that network congestion was encountered.
- **Urgent (URG)**: Indicates that this segment contains urgent data which should be prioritized.
- **Acknowledgment (ACK)**: Essential for connection reliability, indicates that the Acknowledgment field is valid.
- **Push (PSH)**: Instructs the receiver to push this to the receiving application promptly.
- **Reset (RST)**: Used to reset the connection due to an error or other issue.
- **Synchronize (SYN)**: Used to initiate synchronization of sequence numbers to establish a connection.
- **Finish (FIN)**: Used to softly close the connection, indicating no more data from the sender.
*/
pub enum Flag {
    Reserved,
    AccurateECN,
    CongestionWindowReduced,
    ECNEcho,
    Urgent,
    Acknowledgment,
    Push,
    Reset,
    Synchronize,
    Finish,
}

#[derive(Debug)]
/**
### TCP header structure
* Source Port (16 bits): The port of the sender.
* Destination Port (16 bits): The port of the receiver.
* Sequence Number (32 bits): The sequence number for this TCP header.
* Acknowledgment Number (32 bits):
    - If the ACK flag is set, this field contains the value of the sequence number of the next expected byte from the sender. This value is calculated as the previous sequence number received plus the number of bytes in the TCP payload (if any) plus any additional control flags (SYN or FIN) that consume a sequence number.
    - Specifically:
    - **With Payload**: If a packet with a sequence number `S` carries `N` bytes of data, the acknowledgment number in the ACK packet sent in response will be `S + N`.
    - **SYN or FIN Flag**: If the packet also includes a SYN or FIN flag (which consume an additional sequence number each), the acknowledgment number will be `S + N + 1`. 
    - **Just SYN or FIN Flag**: If a packet solely contains a SYN or FIN flag and no data, the acknowledgment number will be `S + 1`.   
* Data Offset (4 bits): The number of 32-bit words in the TCP header. 1 word = 4 bytes. So multiply this value by 4 to get the size of the TCP header in bytes.
* Flags (8 bits): The flags of the TCP segment.
* Window Size (16 bits): The size of the receive window.
* Checksum (16 bits): The checksum of the TCP segment.
* Urgent Pointer (16 bits): If the URG flag is set, this field contains a pointer to the last urgent data byte.
* Options (variable): The options of the TCP segment.
*/
pub struct Header {
    pub source_port: u16,
    pub destination_port: u16,
    pub sequence_number: u32,
    pub acknowledgment_number: u32,
    pub data_offset: u8,
    pub flags: Vec<Flag>,
    pub window_size: u16,
    pub checksum: u16,
    pub urgent_pointer: u16,
    pub options: Vec<u8>,
}
