use std::fmt::Debug;

pub mod ethernet;
pub mod ipv4;
pub mod tcp;
pub mod parse;


#[derive(Debug)]
pub enum Protocol {
    Ethernet(ethernet::Header),
    IPv4(ipv4::Header)
}

