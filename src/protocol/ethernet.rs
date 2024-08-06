use std::io::{self, ErrorKind};


#[derive(Debug,Clone, Copy)]
pub struct MacAddress {
    pub bytes: [u8; 6],
}

impl MacAddress {
    pub fn new(bytes: [u8; 6]) -> MacAddress {
        MacAddress { bytes }
    }

}

#[derive(Debug,Clone, Copy)]
/**
 * Ethernet header structure
 */
pub struct Header {
    pub destination_mac: MacAddress,
    pub source_mac: MacAddress,
    pub ether_type: EtherType,
}

impl Header {
    pub fn size() -> usize {
        14
    }
}


#[derive(Debug,Clone, Copy)]
/**
 * EtherType enumeration. It can be either IPv4, IPv6, or Unsupported in which case it stores the actual value.
 */
pub enum EtherType {
    IPv4,
    IPv6,
    Unsupported(u16),  // Stores the actual value for unsupported or unrecognized EtherTypes
}

/**
 ### Parse the Ethernet header from the data

 As per the Ethernet II frame format, the Ethernet header is 14 bytes long and has the following structure:
    * Destination MAC address (6 bytes)
    * Source MAC address (6 bytes)
    * EtherType (2 bytes)
 */
pub fn parse(data: &[u8]) -> io::Result<Header> {
    // Make sure there's enough data to parse an Ethernet header.
    if data.len() < 14 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "Not enough data to parse Ethernet header",
        ))
    }

    // Extract MAC addresses directly using slices and convert to strings.
    let destination_mac:MacAddress=MacAddress::new({
        match data[0..6].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Failed to convert destination MAC address to array",
                ))
            }
        }
    });
    
    let source_mac:MacAddress=MacAddress::new({
        match data[6..12].try_into() {
            Ok(bytes) => bytes,
            Err(_) => {
                return Err(io::Error::new(
                    ErrorKind::InvalidData,
                    "Failed to convert source MAC address to array",
                ))
            }
        }
    });

    // Extract Ethertype.
    let ether_type = u16::from_be_bytes([data[12], data[13]]);
    
    // Match the EtherType to the corresponding enum variant.
    let ether_type = match ether_type {
        0x0800 => EtherType::IPv4,
        0x86DD => EtherType::IPv6,
        _      => EtherType::Unsupported(ether_type),
    };

    // Store the parsed data.
    Ok(Header {
        destination_mac,
        source_mac,
        ether_type,
    })
}
