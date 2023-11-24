#![no_std]
#![feature(async_fn_in_trait)]
#![feature(error_in_core)]
extern crate alloc;

pub mod buf_reader;
pub mod http;
pub mod tcp;
