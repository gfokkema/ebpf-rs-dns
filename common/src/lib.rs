#![no_std]
use network_types::bitfield::BitfieldUnit;

pub struct DnsHdr {
    pub id: u16,
    pub _bitfield_1: BitfieldUnit<[u8; 2usize]>,
    pub qdcount: u16,
    pub ancount: u16,
    pub nscount: u16,
    pub arcount: u16,
}

impl DnsHdr {
    pub fn id(&self) -> u16 {
        u16::from_be(self.id)
    }

    pub fn qr(&self) -> u16 {
        self._bitfield_1.get(7usize, 1) as u16
    }

    pub fn opcode(&self) -> u16 {
        self._bitfield_1.get(3usize, 4) as u16
    }

    pub fn aa(&self) -> u16 {
        self._bitfield_1.get(2usize, 1) as u16
    }

    pub fn tc(&self) -> u16 {
        self._bitfield_1.get(1usize, 1) as u16
    }

    pub fn rd(&self) -> u16 {
        self._bitfield_1.get(0usize, 1) as u16
    }

    pub fn ra(&self) -> u16 {
        self._bitfield_1.get(15usize, 1) as u16
    }

    pub fn ad(&self) -> u16 {
        self._bitfield_1.get(13usize, 1) as u16
    }

    pub fn cd(&self) -> u16 {
        self._bitfield_1.get(12usize, 1) as u16
    }

    pub fn rcode(&self) -> u16 {
        self._bitfield_1.get(8usize, 4) as u16
    }

    pub fn qdcount(&self) -> u16 {
        u16::from_be(self.qdcount)
    }

    pub fn ancount(&self) -> u16 {
        u16::from_be(self.ancount)
    }

    pub fn nscount(&self) -> u16 {
        u16::from_be(self.nscount)
    }

    pub fn arcount(&self) -> u16 {
        u16::from_be(self.arcount)
    }
}
