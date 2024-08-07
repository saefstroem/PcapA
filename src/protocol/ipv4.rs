use std::io;

use aipn::AIPN;

#[derive(Debug)]
pub enum Version {
    V4=4,
    V6=6,
}

#[derive(Debug)]
/// IPv4 Address 
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
/**
 * Flag enum
 * Reserved (1 bit): Reserved for future use.
 * Don't Fragment (1 bit): If set, the packet should not be fragmented.
 * More Fragments (1 bit): If set, there are more fragments to follow.
 
 */
pub enum Flag {
    Reserved,
    DontFragment,
    MoreFragments,
}

#[derive(Debug)]
/**
 ### IPv4 header structure
 * Version (4 bits): The version of the IP protocol. For IPv4, this is 4.
 * IHL (4 bits): The Internet Header Length (IHL) is the number of 32-bit words in the header. The minimum value is 5, and the maximum value is 15. At the moment the parser **only supports IHL of 5**.
 * Differentiated Services Field (DSF) (8 bits): This field is used to differentiate and prioritize packets.
 * Total Length (16 bits): The total length of the IP packet, including the header and data.
 * Identification (16 bits): Used to identify fragments of an IP packet.
 * Flags (3 bits): Used to control or identify fragments of an IP packet.
 * Fragment Offset (13 bits): The offset of the fragment within the original IP packet.
 * Time to Live (TTL) (8 bits): The number of hops the packet can take before being discarded.
 * Protocol (8 bits): The protocol used in the data portion of the IP packet.
 * Header Checksum (16 bits): Used to verify the integrity of the IP header.
 * Source Address (32 bits): The IP address of the sender.
 * Destination Address (32 bits): The IP address of the receiver.

 */
pub struct Header {
    pub version:Version,
    pub ihl:u8,
    pub dsf:u8,
    pub total_length:u16,
    pub identification:u16,
    pub flags:Vec<Flag>,
    pub fragment_offset:u16,
    pub ttl:u8,
    pub protocol:AIPN,
    pub checksum:u16,
    pub source:Address,
    pub destination:Address,
}

pub fn parse(data:&[u8])-> io::Result<Header> {
    let version_ihl = data[0];
    let ihl=version_ihl & 0x0F;
    if ! ihl == 5 { // TODO: Handle any IHL length.
        return Err(io::Error::new(io::ErrorKind::InvalidData,"Invalid IHL"));
    }
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
    let mut flags=Vec::new();
    if (flags_fragment_offset & 1<<15) != 0 {
        flags.push(Flag::Reserved);
    }
    if (flags_fragment_offset & 1<<14) != 0 {
        flags.push(Flag::DontFragment);
    }
    if (flags_fragment_offset & 1<<13) != 0 {
        flags.push(Flag::MoreFragments);
    }


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
        ihl,
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