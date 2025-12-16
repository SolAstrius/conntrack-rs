//! # Connection
//! This module contains the general API for the conntrack library.

use neli::{
    consts::{nl::*, socket::*},
    genl::{Genlmsghdr, GenlmsghdrBuilder},
    nl::{NlPayload, Nlmsghdr},
    router::synchronous::NlRouter,
    socket::synchronous::NlSocketHandle,
    types::{Buffer, GenlBuffer},
    utils::Groups,
};

use crate::attributes::*;
use crate::decoders::*;
use crate::message::*;
use crate::model::*;
use crate::result::*;

/// The `Conntrack` type is used to connect to a netfilter socket and execute
/// conntrack table specific commands.
pub struct Conntrack {
    socket: NlRouter,
}

impl Conntrack {
    /// This method opens a netfilter socket using a `socket()` syscall, and
    /// returns the `Conntrack` instance on success.
    pub fn connect() -> Result<Self> {
        let socket = NlRouter::connect(NlFamily::Netfilter, Some(0), Groups::empty())?.0;
        Ok(Self { socket })
    }

    /// The dump call will list all connection tracking for the `Conntrack` table as a
    /// `Vec<Flow>` instances.
    pub fn dump(&self) -> Result<Vec<Flow>> {
        let genlhdr = GenlmsghdrBuilder::default()
            .cmd(0u8)
            .version(libc::NFNETLINK_V0 as u8)
            .attrs(GenlBuffer::<ConntrackAttr, Buffer>::new())
            .build()?;

        let recv_iter = self.socket.send(
            CtNetlinkMessage::Conntrack,
            NlmF::DUMP,
            NlPayload::Payload(genlhdr),
        )?;

        let mut flows = Vec::new();

        for result in recv_iter {
            let result: Nlmsghdr<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>> = result?;
            if let NlPayload::Payload(message) = result.nl_payload() {
                let handle = message.attrs().get_attr_handle();

                flows.push(Flow::decode(handle)?);
            }
        }

        Ok(flows)
    }
}

/// Event types for conntrack notifications
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EventType {
    New,
    Update,
    Destroy,
}

/// A conntrack event containing the event type and flow data
#[derive(Debug, Clone)]
pub struct Event {
    pub event_type: EventType,
    pub flow: Flow,
}

/// Listener for conntrack events (NEW, UPDATE, DESTROY)
pub struct ConntrackEvents {
    socket: NlSocketHandle,
}

impl ConntrackEvents {
    /// Subscribe to DESTROY events only (most useful for traffic accounting)
    pub fn subscribe_destroy() -> Result<Self> {
        Self::subscribe(&[NfnlGroup::ConntrackDestroy])
    }

    /// Subscribe to all conntrack events (NEW, UPDATE, DESTROY)
    pub fn subscribe_all() -> Result<Self> {
        Self::subscribe(&[
            NfnlGroup::ConntrackNew,
            NfnlGroup::ConntrackUpdate,
            NfnlGroup::ConntrackDestroy,
        ])
    }

    /// Subscribe to specific conntrack event groups
    pub fn subscribe(groups: &[NfnlGroup]) -> Result<Self> {
        // Convert group enums to bitmask
        let mut mask: u32 = 0;
        for group in groups {
            mask |= 1 << (*group as u32);
        }

        let socket = NlSocketHandle::connect(NlFamily::Netfilter, Some(0), Groups::new_bitmask(mask))?;
        Ok(Self { socket })
    }

    /// Receive the next event. Blocks until an event is available.
    pub fn recv(&self) -> Result<Event> {
        let (msgs, _groups): (neli::types::NlBuffer<CtNetlinkMessage, Genlmsghdr<u8, ConntrackAttr>>, _) =
            self.socket.recv_all()?;

        for msg in msgs {
            let event_type = match msg.nl_type() {
                CtNetlinkMessage::New => EventType::New,
                CtNetlinkMessage::Delete => EventType::Destroy,
                _ => EventType::Update,
            };

            if let NlPayload::Payload(message) = msg.nl_payload() {
                let handle = message.attrs().get_attr_handle();
                let flow = Flow::decode(handle)?;
                return Ok(Event { event_type, flow });
            }
        }

        Err(crate::error::Error::Netlink("No valid event received".into()))
    }

    /// Returns an iterator over events
    pub fn iter(&self) -> EventIter<'_> {
        EventIter { events: self }
    }
}

/// Iterator over conntrack events
pub struct EventIter<'a> {
    events: &'a ConntrackEvents,
}

impl<'a> Iterator for EventIter<'a> {
    type Item = Result<Event>;

    fn next(&mut self) -> Option<Self::Item> {
        Some(self.events.recv())
    }
}
