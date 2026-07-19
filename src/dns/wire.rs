use super::*;

pub(super) static PROBE_COUNTER: AtomicU64 = AtomicU64::new(0);
// The scanner is intentionally capped well below the point where a 16 MiB
// send *and* receive reservation per socket is useful.  A smaller buffer still
// absorbs several seconds of the default DNS rate while preventing recursive
// plus authoritative transports from asking the OS for gigabytes of memory.
pub(super) const UDP_SOCKET_BUFFER_BYTES: usize = 2 * 1024 * 1024;
pub(super) const MAX_AUTHORITATIVE_SERVER_CACHE_ENTRIES: usize = 4_096;
pub(super) const MAX_AUTHORITATIVE_TRANSPORTS: usize = 16;
pub(super) const MAX_AUTHORITATIVE_ZONE_CANDIDATES: usize = 5;
pub(super) const MAX_NAMESERVERS_PER_ZONE: usize = 8;
pub(super) const MAX_ADDRESSES_PER_NAMESERVER: usize = 8;
// Only a handful of tasks may reserve future cadence slots at once. Keeping
// the permit until the reserved instant prevents a burst of concurrent tasks
// from building a long queue based on a rate that may already have changed.
// If a task is cancelled after reserving, the abandoned horizon is therefore
// bounded to this many slots.
pub(super) const MAX_CADENCE_RESERVATIONS: usize = 4;
pub(super) type AuthoritativeServers = Vec<(String, Vec<IpAddr>)>;
pub(super) type AuthoritativeServerCell = Arc<OnceCell<AuthoritativeServers>>;

/// Compatibilité locale avec les anciens accesseurs Hickory. La version 0.26
/// expose ces valeurs directement; les centraliser ici garde le moteur DNS
/// lisible et rend la migration vérifiable.
pub(super) trait MessageCompat {
    fn id(&self) -> u16;
    fn set_id(&mut self, id: u16) -> &mut Self;
    fn message_type(&self) -> MessageType;
    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self;
    fn op_code(&self) -> OpCode;
    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self;
    fn queries(&self) -> &[Query];
    fn answers(&self) -> &[Record];
    fn truncated(&self) -> bool;
    #[cfg(test)]
    fn set_truncated(&mut self, truncated: bool) -> &mut Self;
    #[cfg(test)]
    fn recursion_desired(&self) -> bool;
    fn set_recursion_desired(&mut self, desired: bool) -> &mut Self;
    fn authoritative(&self) -> bool;
    fn authentic_data(&self) -> bool;
    fn response_code(&self) -> ResponseCode;
    #[cfg(test)]
    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self;
    #[cfg(test)]
    fn extensions(&self) -> Option<&Edns>;
}

impl MessageCompat for Message {
    fn id(&self) -> u16 {
        self.metadata.id
    }

    fn set_id(&mut self, id: u16) -> &mut Self {
        self.metadata.id = id;
        self
    }

    fn message_type(&self) -> MessageType {
        self.metadata.message_type
    }

    fn set_message_type(&mut self, message_type: MessageType) -> &mut Self {
        self.metadata.message_type = message_type;
        self
    }

    fn op_code(&self) -> OpCode {
        self.metadata.op_code
    }

    fn set_op_code(&mut self, op_code: OpCode) -> &mut Self {
        self.metadata.op_code = op_code;
        self
    }

    fn queries(&self) -> &[Query] {
        &self.queries
    }

    fn answers(&self) -> &[Record] {
        &self.answers
    }

    fn truncated(&self) -> bool {
        self.metadata.truncation
    }

    #[cfg(test)]
    fn set_truncated(&mut self, truncated: bool) -> &mut Self {
        self.metadata.truncation = truncated;
        self
    }

    #[cfg(test)]
    fn recursion_desired(&self) -> bool {
        self.metadata.recursion_desired
    }

    fn set_recursion_desired(&mut self, desired: bool) -> &mut Self {
        self.metadata.recursion_desired = desired;
        self
    }

    fn authoritative(&self) -> bool {
        self.metadata.authoritative
    }

    fn authentic_data(&self) -> bool {
        self.metadata.authentic_data
    }

    fn response_code(&self) -> ResponseCode {
        self.metadata.response_code
    }

    #[cfg(test)]
    fn set_response_code(&mut self, response_code: ResponseCode) -> &mut Self {
        self.metadata.response_code = response_code;
        self
    }

    #[cfg(test)]
    fn extensions(&self) -> Option<&Edns> {
        self.edns.as_ref()
    }
}

pub(super) trait RecordCompat {
    fn name(&self) -> &Name;
    fn data(&self) -> &RData;
    fn ttl(&self) -> u32;
}

impl RecordCompat for Record {
    fn name(&self) -> &Name {
        &self.name
    }

    fn data(&self) -> &RData {
        &self.data
    }

    fn ttl(&self) -> u32 {
        self.ttl
    }
}

pub(crate) fn bind_buffered_udp(address: SocketAddr) -> Result<UdpSocket> {
    let domain = if address.is_ipv4() {
        socket2::Domain::IPV4
    } else {
        socket2::Domain::IPV6
    };
    let socket = socket2::Socket::new(domain, socket2::Type::DGRAM, Some(socket2::Protocol::UDP))?;
    socket.set_nonblocking(true)?;
    socket.set_recv_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.set_send_buffer_size(UDP_SOCKET_BUFFER_BYTES)?;
    socket.bind(&address.into())?;
    Ok(UdpSocket::from_std(socket.into())?)
}
