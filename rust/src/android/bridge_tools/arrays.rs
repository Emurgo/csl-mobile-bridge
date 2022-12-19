extern crate byteorder;

use std::convert::TryInto;
use byteorder::{ByteOrder, LittleEndian, WriteBytesExt};
use base64;

use crate::panic::{Result, ToResult};

fn u32_vec_to_u8_vec(vec: &Vec<u32>) -> Vec<u8> {
    let mut bytes = Vec::new();
    for val in vec {
        bytes.write_u32::<LittleEndian>(*val).unwrap();
    }
    bytes
}

fn u8_vec_to_u32_vec(bytes: &Vec<u8>) -> Vec<u32> {
    let mut vec = Vec::new();
    for i in (0..bytes.len()).step_by(4) {
        vec.push(LittleEndian::read_u32(&bytes[i..i+4]));
    }
    vec
}

pub fn base64_to_u32_array(base64: &str) -> Result<Vec<u32>> {
    let bytes = base64::decode(base64).into_result()?;
    Ok(u8_vec_to_u32_vec(&bytes))
}

pub fn u32_array_to_base64(vec: &Vec<u32>) -> String {
    let bytes = u32_vec_to_u8_vec(vec);
    base64::encode(&bytes)
}

pub fn usize_array_to_base64(vec: &Vec<usize>) -> String {
    u32_array_to_base64(&vec.into_iter().map(|x| *x as u32).collect())
}