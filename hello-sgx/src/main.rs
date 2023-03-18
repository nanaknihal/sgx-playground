use sgx_isa::{Attributes, Miscselect, ErrorCode, Keyname, Keypolicy, Keyrequest, Report};
use rand::random;
extern crate serde;
use serde::{Serialize, Deserialize};

// use sgx_isa::{Report, Targetinfo};
// use std::net::{TcpListener, TcpStream};
// use std::io::{self, Read, Write};


// For key sealing
pub struct SealData {
    rand: [u8; 16],
    isvsvn: u16,
    cpusvn: [u8; 16],
    // Record attributes and miscselect so that we can verify that
    // we can derive the correct wrapping key, but the actual input
    // to the derivation is CPU enclave state + SW-specified masks.
    attributes: Attributes,
    miscselect: Miscselect,
}

fn egetkey(label: [u8; 16], seal_data: &SealData) -> Result<[u8; 16], ErrorCode> {
    // Key ID is combined from fixed label and random data
    let mut keyid = [0; 32];
    let (label_dst, rand_dst) = keyid.split_at_mut(16);
    label_dst.copy_from_slice(&label);
    rand_dst.copy_from_slice(&seal_data.rand);
    Keyrequest {
        keyname: Keyname::Seal as _,
        keypolicy: Keypolicy::MRENCLAVE, //MRENCLAVE restricts key reading to only Enclaves with the same measurements. MRSIGNER resistricts to encalves by the same signer: https://www.intel.com/content/www/us/en/developer/articles/technical/introduction-to-intel-sgx-sealing.html
        isvsvn: seal_data.isvsvn,
        cpusvn: seal_data.cpusvn,
        attributemask: [!0; 2],
        keyid: keyid,
        miscmask: !0,
            ..Default::default()
    }.egetkey()
}

pub fn get_seal_key_for_label(label: [u8; 16]) -> ([u8; 16], SealData) {
    let report = Report::for_self();

    let seal_data = SealData {
        rand: random(),
        isvsvn: report.isvsvn,
        cpusvn: report.cpusvn,
        attributes: report.attributes,
        miscselect: report.miscselect
    };
    // Return the key and data to to store alongside the label
    (egetkey(label, &seal_data).unwrap(), seal_data)
}

pub fn recover_seal_key(label: [u8; 16], seal_data: SealData) -> Result<[u8; 16], ErrorCode> {
    let report = Report::for_self();

    if report.attributes != seal_data.attributes 
    || report.miscselect != seal_data.miscselect
    {
        return Err(ErrorCode::InvalidAttribute)
    }
    egetkey(label, &seal_data)
}

fn main() {
    let label: [u8; 16] = [69; 16];
    let (key, seal_data) = get_seal_key_for_label(label);
    println!("{:?}", key);
    let recovered = recover_seal_key(label, seal_data);
    println!("{:?}", recovered);
}

// // Get the local attestation report for this enclave (it's always for some enclave):
// let for_self = Targetinfo::from(Report::for_self());

// // Reads target info from a TcpStream
// fn read_targetinfo(s: &mut TcpStream) -> io::Result<Targetinfo> {
//     let mut buf = [0; Targetinfo::UNPADDED_SIZE];
//     s.read_exact(&mut buf)?;
//     // Make sure no extra bytes were provided
//     if !s.read(&mut [0]).ok().map_or(false, |n| n == 0) {
//         return Err(io::ErrorKind::InvalidData.into())
//     }
//     Ok(Targetinfo::try_copy_from(&buf).unwrap())
// }
// fn main() -> io::Result<()> {
//     // Ok(())
//     for stream in TcpListener::bind("localhost:3000")?.incoming() {
//         let mut s = stream?;
//         let ti = read_targetinfo(&mut s)?; //target enclave info 
//         // rust-analyzer shows this line as having a compilatiion error but it compiles just fine:
//         let report = Report::for_target(&ti, &[0; 64]); //local attestation report
//         // s.write_all(report.as_ref())?;
//     }   
//     println!("Hello, world!");
//     Ok(())
//     // println!("Hello, world!");
// }

// use minreq;
// use {http_req::error, http_req::request, std::io, std::io::Write};


// How do you even securely call a https website within the enclave, without relying on OS for https?
/* Perhaps libp2p is easier to use than calling https GET within in an enclave lol */
// fn main() {

//     // let mut a = Vec::new();
// //    request::get("https://speedtest.lax.hivelocity.net", &mut a)?;
// //    io::stdout().write(&a)?;
//     // let response = minreq::get(
//     //     "https://holonym-mpc-node-list.s3.us-east-2.amazonaws.com/nodelist.txt")
//     // .send()
//     // .unwrap();
//     // let nodes = response
//     // .as_str()
//     // .unwrap();
//     // println!("{}", nodes);
// }