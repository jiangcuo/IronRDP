#![cfg_attr(doc, doc = include_str!("../README.md"))]
#![doc(html_logo_url = "https://cdnweb.devolutions.net/images/projects/devolutions/logos/devolutions-icon-shadow.svg")]

use ironrdp_core::{
    Decode, DecodeResult, Encode, EncodeResult, ReadCursor, WriteCursor, cast_length, ensure_fixed_part_size,
    impl_as_any, invalid_field_err,
};
use ironrdp_dvc::{DvcClientProcessor, DvcEncode, DvcMessage, DvcProcessor, encode_dvc_messages};
use ironrdp_pdu::{PduResult, decode_err};
use ironrdp_svc::{ChannelFlags, SvcMessage};
use tracing::{debug, trace};

pub const CHANNEL_NAME: &str = "Microsoft::Windows::RDS::Input";

const RDPINPUT_HEADER_LENGTH: usize = 6;

const EVENTID_SC_READY: u16 = 0x0001;
const EVENTID_CS_READY: u16 = 0x0002;
const EVENTID_TOUCH: u16 = 0x0003;
const EVENTID_SUSPEND_TOUCH: u16 = 0x0004;
const EVENTID_RESUME_TOUCH: u16 = 0x0005;

pub const RDPINPUT_PROTOCOL_V10: u32 = 0x0001_0000;
pub const RDPINPUT_PROTOCOL_V101: u32 = 0x0001_0001;
pub const RDPINPUT_PROTOCOL_V200: u32 = 0x0002_0000;
pub const RDPINPUT_PROTOCOL_V300: u32 = 0x0003_0000;

pub const SC_READY_MULTIPEN_INJECTION_SUPPORTED: u32 = 0x0001;

pub const CS_READY_FLAGS_SHOW_TOUCH_VISUALS: u32 = 0x0000_0001;
pub const CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION: u32 = 0x0000_0002;
pub const CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION: u32 = 0x0000_0004;

pub const CONTACT_DATA_CONTACTRECT_PRESENT: u16 = 0x0001;
pub const CONTACT_DATA_ORIENTATION_PRESENT: u16 = 0x0002;
pub const CONTACT_DATA_PRESSURE_PRESENT: u16 = 0x0004;

pub const RDPINPUT_CONTACT_FLAG_DOWN: u32 = 0x0001;
pub const RDPINPUT_CONTACT_FLAG_UPDATE: u32 = 0x0002;
pub const RDPINPUT_CONTACT_FLAG_UP: u32 = 0x0004;
pub const RDPINPUT_CONTACT_FLAG_INRANGE: u32 = 0x0008;
pub const RDPINPUT_CONTACT_FLAG_INCONTACT: u32 = 0x0010;
pub const RDPINPUT_CONTACT_FLAG_CANCELED: u32 = 0x0020;

const DEFAULT_MAX_TOUCH_CONTACTS: u16 = 64;
const TOUCH_RECT_SIZE: i32 = 2;

/// Client processor for the RDPEI dynamic virtual channel.
#[derive(Debug, Clone)]
pub struct RdpeiClient {
    max_touch_contacts: u16,
    client_features_mask: u32,
    server_version: Option<u32>,
    server_features: u32,
    suspended: bool,
}

impl RdpeiClient {
    #[must_use]
    pub fn new() -> Self {
        Self {
            max_touch_contacts: DEFAULT_MAX_TOUCH_CONTACTS,
            client_features_mask: CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION,
            server_version: None,
            server_features: 0,
            suspended: false,
        }
    }

    #[must_use]
    pub fn with_max_touch_contacts(mut self, max_touch_contacts: u16) -> Self {
        self.max_touch_contacts = max_touch_contacts;
        self
    }

    #[must_use]
    pub fn with_client_features_mask(mut self, client_features_mask: u32) -> Self {
        self.client_features_mask = client_features_mask;
        self
    }

    #[must_use]
    pub fn is_ready(&self) -> bool {
        self.server_version.is_some() && !self.suspended
    }

    #[must_use]
    pub fn is_suspended(&self) -> bool {
        self.suspended
    }

    #[must_use]
    pub fn server_version(&self) -> Option<u32> {
        self.server_version
    }

    #[must_use]
    pub fn server_features(&self) -> u32 {
        self.server_features
    }

    /// Encodes an arbitrary touch frame for the assigned RDPEI dynamic channel.
    pub fn encode_touch_frame(
        &self,
        channel_id: u32,
        encode_time_ms: u32,
        frame_offset_ms: u64,
        contacts: &[TouchContact],
    ) -> EncodeResult<Vec<SvcMessage>> {
        validate_contact_count(contacts.len(), self.max_touch_contacts)?;

        let pdu = RdpeiClientPdu::touch(encode_time_ms, TouchFrame::new(frame_offset_ms, contacts.to_vec())?)?;
        encode_dvc_messages(channel_id, vec![Box::new(pdu)], ChannelFlags::empty())
    }

    pub fn encode_touch_begin(
        &self,
        channel_id: u32,
        contact_id: u8,
        x: i32,
        y: i32,
        pressure: Option<u32>,
    ) -> EncodeResult<Vec<SvcMessage>> {
        let contact = TouchContact::new(
            contact_id,
            x,
            y,
            RDPINPUT_CONTACT_FLAG_DOWN | RDPINPUT_CONTACT_FLAG_INRANGE | RDPINPUT_CONTACT_FLAG_INCONTACT,
        )
        .with_pressure_opt(pressure)?;

        self.encode_touch_frame(channel_id, 0, 0, &[contact])
    }

    pub fn encode_touch_update(
        &self,
        channel_id: u32,
        contact_id: u8,
        x: i32,
        y: i32,
        pressure: Option<u32>,
    ) -> EncodeResult<Vec<SvcMessage>> {
        let contact = TouchContact::new(
            contact_id,
            x,
            y,
            RDPINPUT_CONTACT_FLAG_UPDATE | RDPINPUT_CONTACT_FLAG_INRANGE | RDPINPUT_CONTACT_FLAG_INCONTACT,
        )
        .with_pressure_opt(pressure)?;

        self.encode_touch_frame(channel_id, 0, 0, &[contact])
    }

    /// Encodes the two-step engaged-to-out-of-range transition used by FreeRDP.
    pub fn encode_touch_end(
        &self,
        channel_id: u32,
        contact_id: u8,
        x: i32,
        y: i32,
        pressure: Option<u32>,
    ) -> EncodeResult<Vec<SvcMessage>> {
        let update = TouchContact::new(
            contact_id,
            x,
            y,
            RDPINPUT_CONTACT_FLAG_UPDATE | RDPINPUT_CONTACT_FLAG_INRANGE | RDPINPUT_CONTACT_FLAG_INCONTACT,
        )
        .with_pressure_opt(pressure)?;
        let up = TouchContact::new(contact_id, x, y, RDPINPUT_CONTACT_FLAG_UP).with_pressure_opt(pressure)?;

        let update_pdu = RdpeiClientPdu::touch(0, TouchFrame::new(0, vec![update])?)?;
        let up_pdu = RdpeiClientPdu::touch(0, TouchFrame::new(0, vec![up])?)?;

        encode_dvc_messages(
            channel_id,
            vec![Box::new(update_pdu), Box::new(up_pdu)],
            ChannelFlags::empty(),
        )
    }

    pub fn encode_touch_cancel(
        &self,
        channel_id: u32,
        contact_id: u8,
        x: i32,
        y: i32,
        pressure: Option<u32>,
    ) -> EncodeResult<Vec<SvcMessage>> {
        let contact = TouchContact::new(
            contact_id,
            x,
            y,
            RDPINPUT_CONTACT_FLAG_UPDATE | RDPINPUT_CONTACT_FLAG_CANCELED,
        )
        .with_pressure_opt(pressure)?;

        self.encode_touch_frame(channel_id, 0, 0, &[contact])
    }

    fn cs_ready_pdu(&self) -> RdpeiClientPdu {
        let version = self.server_version.unwrap_or(RDPINPUT_PROTOCOL_V300);
        let mut flags = CS_READY_FLAGS_SHOW_TOUCH_VISUALS & self.client_features_mask;

        if version > RDPINPUT_PROTOCOL_V10 {
            flags |= CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION & self.client_features_mask;
        }

        if self.server_features & SC_READY_MULTIPEN_INJECTION_SUPPORTED != 0 {
            flags |= CS_READY_FLAGS_ENABLE_MULTIPEN_INJECTION & self.client_features_mask;
        }

        RdpeiClientPdu::cs_ready(flags, version, self.max_touch_contacts)
    }
}

impl Default for RdpeiClient {
    fn default() -> Self {
        Self::new()
    }
}

impl_as_any!(RdpeiClient);

impl DvcProcessor for RdpeiClient {
    fn channel_name(&self) -> &str {
        CHANNEL_NAME
    }

    fn start(&mut self, _channel_id: u32) -> PduResult<Vec<DvcMessage>> {
        Ok(Vec::new())
    }

    fn process(&mut self, _channel_id: u32, payload: &[u8]) -> PduResult<Vec<DvcMessage>> {
        let pdu = ServerPdu::decode(&mut ReadCursor::new(payload)).map_err(|e| decode_err!(e))?;

        match pdu {
            ServerPdu::ScReady {
                protocol_version,
                features,
            } => {
                debug!(protocol_version, features, "RDPEI server ready");
                self.server_version = Some(protocol_version);
                self.server_features = features;
                self.suspended = false;
                Ok(vec![Box::new(self.cs_ready_pdu())])
            }
            ServerPdu::SuspendTouch => {
                debug!("RDPEI touch suspended");
                self.suspended = true;
                Ok(Vec::new())
            }
            ServerPdu::ResumeTouch => {
                debug!("RDPEI touch resumed");
                self.suspended = false;
                Ok(Vec::new())
            }
            ServerPdu::Unknown { event_id, pdu_length } => {
                trace!(event_id, pdu_length, "Ignoring unsupported RDPEI server PDU");
                Ok(Vec::new())
            }
        }
    }
}

impl DvcClientProcessor for RdpeiClient {}

#[derive(Debug, Clone)]
pub enum ServerPdu {
    ScReady { protocol_version: u32, features: u32 },
    SuspendTouch,
    ResumeTouch,
    Unknown { event_id: u16, pdu_length: u32 },
}

impl<'de> Decode<'de> for ServerPdu {
    fn decode(src: &mut ReadCursor<'de>) -> DecodeResult<Self> {
        if src.len() < RDPINPUT_HEADER_LENGTH {
            return Err(invalid_field_err!("RDPEI_HEADER", "not enough bytes for RDPEI header"));
        }

        let event_id = src.read_u16();
        let pdu_length = src.read_u32();

        if pdu_length < cast_length!("pduLength", RDPINPUT_HEADER_LENGTH)? {
            return Err(invalid_field_err!(
                "pduLength",
                "RDPEI PDU length is shorter than its header"
            ));
        }

        match event_id {
            EVENTID_SC_READY => {
                if src.len() < 4 {
                    return Err(invalid_field_err!("SC_READY", "not enough bytes for SC_READY"));
                }
                let protocol_version = src.read_u32();
                let features = if protocol_version >= RDPINPUT_PROTOCOL_V300 && src.len() >= 4 {
                    src.read_u32()
                } else {
                    0
                };

                Ok(Self::ScReady {
                    protocol_version,
                    features,
                })
            }
            EVENTID_SUSPEND_TOUCH => Ok(Self::SuspendTouch),
            EVENTID_RESUME_TOUCH => Ok(Self::ResumeTouch),
            _ => Ok(Self::Unknown { event_id, pdu_length }),
        }
    }
}

#[derive(Debug, Clone)]
pub struct RdpeiClientPdu {
    event_id: u16,
    payload: Vec<u8>,
}

impl RdpeiClientPdu {
    const FIXED_PART_SIZE: usize = RDPINPUT_HEADER_LENGTH;

    #[must_use]
    pub fn cs_ready(flags: u32, protocol_version: u32, max_touch_contacts: u16) -> Self {
        let mut payload = Vec::with_capacity(10);
        payload.extend_from_slice(&flags.to_le_bytes());
        payload.extend_from_slice(&protocol_version.to_le_bytes());
        payload.extend_from_slice(&max_touch_contacts.to_le_bytes());

        Self {
            event_id: EVENTID_CS_READY,
            payload,
        }
    }

    pub fn touch(encode_time_ms: u32, frame: TouchFrame) -> EncodeResult<Self> {
        let mut payload = Vec::with_capacity(64 + frame.contacts.len() * 64);
        write_4byte_unsigned(&mut payload, encode_time_ms)?;
        write_2byte_unsigned(&mut payload, 1)?;
        frame.encode_payload(&mut payload)?;

        Ok(Self {
            event_id: EVENTID_TOUCH,
            payload,
        })
    }
}

impl Encode for RdpeiClientPdu {
    fn encode(&self, dst: &mut WriteCursor<'_>) -> EncodeResult<()> {
        ensure_fixed_part_size!(in: dst);

        dst.write_u16(self.event_id);
        dst.write_u32(cast_length!("pduLength", self.size())?);
        dst.write_slice(&self.payload);

        Ok(())
    }

    fn name(&self) -> &'static str {
        "RDPEI_CLIENT_PDU"
    }

    fn size(&self) -> usize {
        RDPINPUT_HEADER_LENGTH + self.payload.len()
    }
}

impl DvcEncode for RdpeiClientPdu {}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchFrame {
    frame_offset_ms: u64,
    contacts: Vec<TouchContact>,
}

impl TouchFrame {
    pub fn new(frame_offset_ms: u64, contacts: Vec<TouchContact>) -> EncodeResult<Self> {
        if contacts.is_empty() {
            return Err(invalid_field_err!(
                "contactCount",
                "touch frames must include at least one contact"
            ));
        }

        if contacts.len() > usize::from(u16::MAX) {
            return Err(invalid_field_err!("contactCount", "too many touch contacts"));
        }

        Ok(Self {
            frame_offset_ms,
            contacts,
        })
    }

    fn encode_payload(&self, dst: &mut Vec<u8>) -> EncodeResult<()> {
        write_2byte_unsigned(dst, cast_length!("contactCount", self.contacts.len())?)?;
        write_8byte_unsigned(dst, self.frame_offset_ms.saturating_mul(1000))?;

        for contact in &self.contacts {
            contact.encode_payload(dst)?;
        }

        Ok(())
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TouchContact {
    contact_id: u8,
    x: i32,
    y: i32,
    fields_present: u16,
    contact_flags: u32,
    contact_rect_left: i16,
    contact_rect_top: i16,
    contact_rect_right: i16,
    contact_rect_bottom: i16,
    orientation: u32,
    pressure: u32,
}

impl TouchContact {
    #[must_use]
    pub fn new(contact_id: u8, x: i32, y: i32, contact_flags: u32) -> Self {
        Self {
            contact_id,
            x,
            y,
            fields_present: CONTACT_DATA_CONTACTRECT_PRESENT,
            contact_flags,
            contact_rect_left: bounded_i16(x.saturating_sub(TOUCH_RECT_SIZE)),
            contact_rect_top: bounded_i16(y.saturating_sub(TOUCH_RECT_SIZE)),
            contact_rect_right: bounded_i16(x.saturating_add(TOUCH_RECT_SIZE)),
            contact_rect_bottom: bounded_i16(y.saturating_add(TOUCH_RECT_SIZE)),
            orientation: 0,
            pressure: 0,
        }
    }

    pub fn with_orientation(mut self, orientation: u32) -> EncodeResult<Self> {
        if orientation >= 360 {
            return Err(invalid_field_err!(
                "orientation",
                "touch orientation must be in the range 0..360"
            ));
        }

        self.fields_present |= CONTACT_DATA_ORIENTATION_PRESENT;
        self.orientation = orientation;
        Ok(self)
    }

    pub fn with_pressure(mut self, pressure: u32) -> EncodeResult<Self> {
        if pressure > 1024 {
            return Err(invalid_field_err!(
                "pressure",
                "touch pressure must be in the range 0..=1024"
            ));
        }

        self.fields_present |= CONTACT_DATA_PRESSURE_PRESENT;
        self.pressure = pressure;
        Ok(self)
    }

    pub fn with_pressure_opt(self, pressure: Option<u32>) -> EncodeResult<Self> {
        if let Some(pressure) = pressure {
            self.with_pressure(pressure)
        } else {
            Ok(self)
        }
    }

    fn encode_payload(&self, dst: &mut Vec<u8>) -> EncodeResult<()> {
        dst.push(self.contact_id);
        write_2byte_unsigned(dst, self.fields_present)?;
        write_4byte_signed(dst, self.x)?;
        write_4byte_signed(dst, self.y)?;
        write_4byte_unsigned(dst, self.contact_flags)?;

        if self.fields_present & CONTACT_DATA_CONTACTRECT_PRESENT != 0 {
            write_2byte_signed(dst, self.contact_rect_left)?;
            write_2byte_signed(dst, self.contact_rect_top)?;
            write_2byte_signed(dst, self.contact_rect_right)?;
            write_2byte_signed(dst, self.contact_rect_bottom)?;
        }

        if self.fields_present & CONTACT_DATA_ORIENTATION_PRESENT != 0 {
            write_4byte_unsigned(dst, self.orientation)?;
        }

        if self.fields_present & CONTACT_DATA_PRESSURE_PRESENT != 0 {
            write_4byte_unsigned(dst, self.pressure)?;
        }

        Ok(())
    }
}

fn validate_contact_count(contact_count: usize, max_touch_contacts: u16) -> EncodeResult<()> {
    if contact_count > usize::from(max_touch_contacts) {
        return Err(invalid_field_err!("contactCount", "too many active touch contacts"));
    }

    Ok(())
}

fn bounded_i16(value: i32) -> i16 {
    if value < i32::from(i16::MIN) {
        i16::MIN
    } else if value > i32::from(i16::MAX) {
        i16::MAX
    } else {
        i16::try_from(value).expect("value is bounded to i16 range")
    }
}

fn write_2byte_unsigned(dst: &mut Vec<u8>, value: u16) -> EncodeResult<()> {
    if value > 0x7FFF {
        return Err(invalid_field_err!("TWO_BYTE_UNSIGNED_INTEGER", "value is out of range"));
    }

    if value >= 0x7F {
        dst.push(u8::try_from((value & 0x7F00) >> 8).expect("masked value fits in u8") | 0x80);
        dst.push(u8::try_from(value & 0x00FF).expect("masked value fits in u8"));
    } else {
        dst.push(u8::try_from(value & 0x007F).expect("masked value fits in u8"));
    }

    Ok(())
}

fn write_2byte_signed(dst: &mut Vec<u8>, value: i16) -> EncodeResult<()> {
    let negative = value < 0;
    let magnitude = u16::try_from(i32::from(value).unsigned_abs())
        .map_err(|_| invalid_field_err!("TWO_BYTE_SIGNED_INTEGER", "value is out of range"))?;

    if magnitude > 0x3FFF {
        return Err(invalid_field_err!("TWO_BYTE_SIGNED_INTEGER", "value is out of range"));
    }

    let sign = if negative { 0x40 } else { 0 };

    if magnitude >= 0x3F {
        dst.push(u8::try_from((magnitude & 0x3F00) >> 8).expect("masked value fits in u8") | sign | 0x80);
        dst.push(u8::try_from(magnitude & 0x00FF).expect("masked value fits in u8"));
    } else {
        dst.push(u8::try_from(magnitude & 0x003F).expect("masked value fits in u8") | sign);
    }

    Ok(())
}

fn write_4byte_unsigned(dst: &mut Vec<u8>, value: u32) -> EncodeResult<()> {
    if value <= 0x3F {
        dst.push(u8::try_from(value).expect("value <= 0x3F fits in u8"));
    } else if value <= 0x3FFF {
        dst.push(u8::try_from((value >> 8) & 0x3F).expect("masked value fits in u8") | 0x40);
        dst.push(u8::try_from(value & 0xFF).expect("masked value fits in u8"));
    } else if value <= 0x3F_FFFF {
        dst.push(u8::try_from((value >> 16) & 0x3F).expect("masked value fits in u8") | 0x80);
        dst.push(u8::try_from((value >> 8) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from(value & 0xFF).expect("masked value fits in u8"));
    } else if value <= 0x3FFF_FFFF {
        dst.push(u8::try_from((value >> 24) & 0x3F).expect("masked value fits in u8") | 0xC0);
        dst.push(u8::try_from((value >> 16) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from((value >> 8) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from(value & 0xFF).expect("masked value fits in u8"));
    } else {
        return Err(invalid_field_err!(
            "FOUR_BYTE_UNSIGNED_INTEGER",
            "value is out of range"
        ));
    }

    Ok(())
}

fn write_4byte_signed(dst: &mut Vec<u8>, value: i32) -> EncodeResult<()> {
    let negative = value < 0;
    let magnitude = value.unsigned_abs();

    if magnitude <= 0x1F {
        let sign = if negative { 0x20 } else { 0 };
        dst.push(u8::try_from(magnitude).expect("value <= 0x1F fits in u8") | sign);
    } else if magnitude <= 0x1FFF {
        let sign = if negative { 0x20 } else { 0 };
        dst.push(u8::try_from((magnitude >> 8) & 0x1F).expect("masked value fits in u8") | sign | 0x40);
        dst.push(u8::try_from(magnitude & 0xFF).expect("masked value fits in u8"));
    } else if magnitude <= 0x1F_FFFF {
        let sign = if negative { 0x20 } else { 0 };
        dst.push(u8::try_from((magnitude >> 16) & 0x1F).expect("masked value fits in u8") | sign | 0x80);
        dst.push(u8::try_from((magnitude >> 8) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from(magnitude & 0xFF).expect("masked value fits in u8"));
    } else if magnitude <= 0x1FFF_FFFF {
        let sign = if negative { 0x20 } else { 0 };
        dst.push(u8::try_from((magnitude >> 24) & 0x1F).expect("masked value fits in u8") | sign | 0xC0);
        dst.push(u8::try_from((magnitude >> 16) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from((magnitude >> 8) & 0xFF).expect("masked value fits in u8"));
        dst.push(u8::try_from(magnitude & 0xFF).expect("masked value fits in u8"));
    } else {
        return Err(invalid_field_err!("FOUR_BYTE_SIGNED_INTEGER", "value is out of range"));
    }

    Ok(())
}

fn write_8byte_unsigned(dst: &mut Vec<u8>, value: u64) -> EncodeResult<()> {
    if value > 0x01FF_FFFF_FFFF_FFFF {
        return Err(invalid_field_err!(
            "EIGHT_BYTE_UNSIGNED_INTEGER",
            "value is out of range"
        ));
    }

    let mut count = 0u8;
    let mut max = 0x1F_u64;
    while value > max {
        count = count.saturating_add(1);
        max = (max << 8) | 0xFF;
    }

    let shift = u32::from(count) * 8;
    dst.push(u8::try_from((value >> shift) & 0x1F).expect("masked value fits in u8") | (count << 5));

    for byte_index in (0..count).rev() {
        let shift = u32::from(byte_index) * 8;
        dst.push(u8::try_from((value >> shift) & 0xFF).expect("masked value fits in u8"));
    }

    Ok(())
}

#[cfg(test)]
mod tests {
    use ironrdp_core::encode_vec;

    use super::*;

    #[test]
    fn encodes_cs_ready() {
        let pdu = RdpeiClientPdu::cs_ready(CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION, RDPINPUT_PROTOCOL_V300, 10);

        let bytes = encode_vec(&pdu).unwrap();
        assert_eq!(&bytes[0..2], &EVENTID_CS_READY.to_le_bytes());
        assert_eq!(u32::from_le_bytes(bytes[2..6].try_into().unwrap()), 16);
        assert_eq!(
            u32::from_le_bytes(bytes[6..10].try_into().unwrap()),
            CS_READY_FLAGS_DISABLE_TIMESTAMP_INJECTION
        );
        assert_eq!(u16::from_le_bytes(bytes[14..16].try_into().unwrap()), 10);
    }

    #[test]
    fn encodes_touch_begin() {
        let client = RdpeiClient::new();
        let messages = client.encode_touch_begin(7, 1, 320, 640, Some(512)).unwrap();
        assert!(!messages.is_empty());
    }
}
