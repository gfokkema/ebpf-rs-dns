use aya_bpf::{
    programs::XdpContext,
};
use aya_log_ebpf::info;
use core::mem;
use network_types::{
    eth::EthHdr,
    ip::Ipv4Hdr,
    udp::UdpHdr,
};

#[inline(always)] //
pub fn ptr_at<T>(ctx: &XdpContext, offset: usize) -> Result<*const T, ()> {
    let start = ctx.data();
    let end = ctx.data_end();
    let len = mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }

    Ok((start + offset) as *const T)
}

#[inline(always)]
pub fn ptr_at_mut<T>(ctx: &XdpContext, offset: usize) -> Result<*mut T, ()> {
    let ptr = ptr_at::<T>(ctx, offset)?;
    Ok(ptr as *mut T)
}

pub fn print_pkt(ctx: &XdpContext) -> Result<(), ()> {
    let ethhdr: *mut EthHdr = ptr_at_mut(&ctx, 0)?;
    let ipv4hdr: *mut Ipv4Hdr = ptr_at_mut(&ctx, EthHdr::LEN)?;
    let udphdr: *mut UdpHdr = ptr_at_mut(&ctx, EthHdr::LEN + Ipv4Hdr::LEN)?;

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