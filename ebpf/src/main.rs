#![no_std]
#![no_main]
#![allow(nonstandard_style, dead_code)]

use aya_bpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::HashMap,
    programs::XdpContext,
};
use aya_log_ebpf::info;

use core::mem;
use network_types::{
    eth::{EthHdr, EtherType},
    ip::{Ipv4Hdr, IpProto},
    udp::UdpHdr,
};

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe { core::hint::unreachable_unchecked() }
}

#[map(name = "BLOCKLIST")] // 
static mut BLOCKLIST: HashMap<u32, u32> =
    HashMap::<u32, u32>::with_max_entries(1024, 0);
#[map(name = "BLOCKLIST_PORT")] // 
static mut BLOCKLIST_PORT: HashMap<u16, bool> =
    HashMap::<u16, bool>::with_max_entries(1024, 0);

#[xdp]
pub fn xdp_firewall(ctx: XdpContext) -> u32 {
    match try_xdp_firewall(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_ABORTED,
    }
}

#[inline(always)]
unsafe fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    let ptr = (start + offset) as *const T;
    Ok(&*ptr)
}

#[inline(always)]
unsafe fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

// 
fn block_ip(address: u32) -> bool {
    unsafe { BLOCKLIST.get(&address).is_some() }
}

fn block_port(port: u16) -> bool {
    unsafe { BLOCKLIST_PORT.get(&port).is_some() }
}

fn print_pkt(ctx: &XdpContext) -> Result<(), ()> {
    let ethhdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    let udphdr: *mut UdpHdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };    

    let mut eth_src = [0; 6];
    eth_src.copy_from_slice(unsafe { &(*ethhdr).src_addr });
    let mut eth_dst = [0; 6];
    eth_dst.copy_from_slice(unsafe { &(*ethhdr).dst_addr });
    let ip_src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let ip_dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let udp_src_port = u16::from_be(unsafe { *udphdr }.source);
    let udp_dst_port = u16::from_be(unsafe { *udphdr }.dest);

    info!(ctx, "{:mac} {:mac} -> {:ipv4}:{} -> {:ipv4}:{}", eth_src, eth_dst, ip_src, udp_src_port, ip_dst, udp_dst_port);

    Ok(())
}

fn try_xdp_firewall(ctx: XdpContext) -> Result<u32, ()> {
    let ethhdr: *mut EthHdr = unsafe { ptr_at_mut(&ctx, 0)? };
    match unsafe { (*ethhdr).ether_type } {
        EtherType::Ipv4 => {}
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ipv4hdr: *mut Ipv4Hdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN)? };
    match unsafe { (*ipv4hdr).proto } {
        IpProto::Udp => {}
        _ => return Ok(xdp_action::XDP_PASS)
    }
    
    let udphdr: *mut UdpHdr = unsafe { ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)? };    
    match u16::from_be(unsafe { (*udphdr).dest }) {
        53 => {}
        _ => return Ok(xdp_action::XDP_PASS)
    }

    print_pkt(&ctx)?;
    
    let mut eth_src = [0; 6];
    eth_src.copy_from_slice(unsafe { &(*ethhdr).src_addr });
    let mut eth_dst = [0; 6];
    eth_dst.copy_from_slice(unsafe { &(*ethhdr).dst_addr });
    let ip_src = u32::from_be(unsafe { (*ipv4hdr).src_addr });
    let ip_dst = u32::from_be(unsafe { (*ipv4hdr).dst_addr });
    let udp_src_port = u16::from_be(unsafe { *udphdr }.source);
    let udp_dst_port = u16::from_be(unsafe { *udphdr }.dest);
    
    unsafe {
        (*ethhdr).src_addr.copy_from_slice(&eth_dst);
        (*ethhdr).dst_addr.copy_from_slice(&eth_src);
        (*ipv4hdr).src_addr = u32::to_be(ip_dst);
        (*ipv4hdr).dst_addr = u32::to_be(ip_src);
        (*udphdr).source = u16::to_be(udp_dst_port);
        (*udphdr).dest = u16::to_be(udp_src_port);
    }

    print_pkt(&ctx)?;
    
    Ok(xdp_action::XDP_TX)
}
