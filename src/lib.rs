use std::{fs::File, io::{self, ErrorKind}};

use pcap::{global_header::GlobalHeader, packet::{global_header::parse_global_header, header::{parse_packet, parse_packet_header}, Packet}};


/**
 Functions that read bytes from the file.
 */
mod read_bytes;

/**
 Structs and functions used to compose a pcap file.
 */
mod pcap;

/**
 Various network protocol definitions and parsing functions.
 */
mod protocol;


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

        let mut pcap_file = PCapA {
            global_header,
            packets: Vec::new(),
        };

        log::info!("Parsing packets...");
        loop {
            match parse_packet_header(&mut file, &pcap_file.global_header) {
                Ok(packet_header) => {
                    let packet = parse_packet(&mut file, packet_header,&pcap_file.global_header)?;
                    pcap_file.packets.push(packet);
                }
                Err(e) if e.kind() == ErrorKind::UnexpectedEof => break,
                Err(e) => return Err(e),
            }
        }
        log::info!("Parsed {} packets", pcap_file.packets.len());
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
        let example_packet=&pcap_file.packets[0];

        log::info!("GH: {:?}", pcap_file.global_header);
        log::info!("Packet: {:?}", example_packet);

    }
}

