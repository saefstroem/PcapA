use std::{fs::File, io::{self, ErrorKind}};

use pcap::{global_header::GlobalHeader, packet::Packet};
use parse::{parse_global_header, parse_packet, parse_packet_header};

/**
 The parse module contains the functions that parse the file into an `SPCap` struct.    
 */
mod parse;

/**
 Functions that read bytes from the file.
 */
mod read_bytes;

/**
 Structs and functions used to compose a pcap file.
 */
mod pcap;


/**
   ## PCapA - Packet Capture Analyzer
 */
#[derive(Debug)]
pub struct PCapA {
    pub global_header: GlobalHeader,
    pub packets: Vec<Packet>,
}


impl PCapA {
    /**
     Loads a pcap file from the given path and tries to parse it into an `SPCap` struct. 
     */
    pub fn open(path: &str) -> io::Result<PCapA> {
        let mut file = File::open(path)?;

        log::info!("Parsing global header...");
        let global_header = parse_global_header(&mut file)?;

        let pcap_file = PCapA {
            global_header,
            packets: Vec::new(),
        };

        log::info!("{:?}", pcap_file);
        let mut packets = Vec::new();

        log::info!("Parsing packets...");
        loop {
            match parse_packet_header(&mut file, &pcap_file.global_header.byte_order) {
                Ok(packet_header) => {
                    let packet = parse_packet(&mut file, packet_header)?;
                    packets.push(packet);
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        Ok(pcap_file)
    }
}


#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        env_logger::builder().is_test(true).try_init().unwrap();
        let pcap_file = PCapA::open("trafik.pcap").unwrap();
    }
}

