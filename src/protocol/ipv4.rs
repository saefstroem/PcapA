use std::io;

use aipn::AIPN;

#[derive(Debug)]
pub enum Version {
    V4=4,
    V6=6,
}

#[derive(Debug)]
pub struct Address {
    pub address:[u8;4],
}

impl Address {
    pub fn new(address:[u8;4])->Address {
        Address {
            address
        }
    }
}

#[derive(Debug)]
pub struct Flags {
    pub reserved:bool,
    pub dont_fragment:bool,
    pub more_fragments:bool,
}

#[derive(Debug)]
pub struct Header {
    pub version:Version,
    pub ihl:u8,
    pub dsf:u8,
    pub total_length:u16,
    pub identification:u16,
    pub flags:Flags,
    pub fragment_offset:u16,
    pub ttl:u8,
    pub protocol:AIPN,
    pub checksum:u16,
    pub source:Address,
    pub destination:Address,
}

pub fn parse(data:&[u8])-> io::Result<Header> {
    let version_ihl = data[0];
    let dsf = data[1];
    let total_length = u16::from_be_bytes(match &data[2..4].try_into(){
        Ok(bytes) => *bytes,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData,"Failed to read total length"))
    });
    let identification = u16::from_be_bytes(match &data[4..6].try_into(){
        Ok(bytes) => *bytes,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData,"Failed to read identification"))
    });
    
    let flags_fragment_offset = u16::from_be_bytes(match &data[6..8].try_into(){
        Ok(bytes) => *bytes,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData,"Failed to read flags and fragment offset"))
    });

    // Extract the flags and fragment offset from the 16-bit field using bit shifting and masking.
    let flags=Flags {
        reserved:(flags_fragment_offset & 1<<15) != 0,
        dont_fragment:(flags_fragment_offset & (1<<14)) != 0,
        more_fragments:(flags_fragment_offset & 1<<13) != 0,
    };

    let ttl = data[8];
    let protocol = AIPN::from(data[9]);
    let checksum = u16::from_be_bytes(match &data[10..12].try_into(){
        Ok(bytes) => *bytes,
        Err(_) => return Err(io::Error::new(io::ErrorKind::InvalidData,"Failed to read checksum"))
    });
    let source = Address::new([data[12],data[13],data[14],data[15]]);
    let destination = Address::new([data[16],data[17],data[18],data[19]]);
    
    
    let header = Header {
        version:Version::V4,
        ihl:version_ihl & 0x0F,
        dsf,
        total_length,
        identification,
        flags,
        fragment_offset:flags_fragment_offset & 0x1FFF,
        ttl,
        protocol,
        checksum,
        source,
        destination,
    };
    Ok(header)

}