use core::net::{Ipv4Addr, SocketAddr, SocketAddrV4};

use ironrdp_connector::{ClientConnector, ClientConnectorState, Config, Credentials, DesktopSize, Sequence as _};
use ironrdp_core::{WriteBuf, decode, encode_vec};
use ironrdp_pdu::gcc;
use ironrdp_pdu::nego::{ConnectionConfirm, ConnectionRequest, ResponseFlags, SecurityProtocol};
use ironrdp_pdu::rdp::capability_sets::MajorPlatformType;
use ironrdp_pdu::x224::X224;

/// Builds the minimal connector configuration required for proxy negotiation tests.
fn test_config() -> Config {
    Config {
        desktop_size: DesktopSize {
            width: 1024,
            height: 768,
        },
        desktop_scale_factor: 0,
        enable_tls: true,
        enable_credssp: true,
        credentials: Credentials::UsernamePassword {
            username: String::new(),
            password: String::new(),
        },
        domain: None,
        client_build: 0,
        client_name: "proxy-test".into(),
        keyboard_type: gcc::KeyboardType::IbmEnhanced,
        keyboard_subtype: 0,
        keyboard_layout: 0,
        keyboard_functional_keys_count: 12,
        ime_file_name: String::new(),
        bitmap: None,
        dig_product_id: String::new(),
        client_dir: String::new(),
        platform: MajorPlatformType::UNIX,
        hardware_id: None,
        request_data: None,
        autologon: false,
        enable_audio_playback: false,
        license_cache: None,
        compression_type: None,
        enable_server_pointer: false,
        pointer_software_rendering: false,
        multitransport_flags: None,
        performance_flags: Default::default(),
        timezone_info: Default::default(),
        alternate_shell: String::new(),
        work_dir: String::new(),
    }
}

/// Builds a connector that mirrors the VMConnect post-authentication negotiation.
fn proxy_connector() -> ClientConnector {
    let address = SocketAddr::V4(SocketAddrV4::new(Ipv4Addr::LOCALHOST, 33899));
    ClientConnector::new(test_config(), address)
        .with_requested_protocols(SecurityProtocol::HYBRID | SecurityProtocol::SSL)
}

/// Advances a connector through its initial X.224 request.
fn send_connection_request(connector: &mut ClientConnector) -> Vec<u8> {
    let mut output = WriteBuf::new();
    connector.step(&[], &mut output).unwrap();
    output.filled().to_vec()
}

/// Confirms that proxy-completed CredSSP advertises the FreeRDP VMConnect mask 0x3.
#[test]
fn proxy_completed_credssp_requests_hybrid_and_ssl() {
    let mut connector = proxy_connector();
    let request = send_connection_request(&mut connector);
    let request = decode::<X224<ConnectionRequest>>(&request).unwrap().0;

    assert_eq!(request.protocol.bits(), 0x0000_0003);
}

/// Confirms that a HYBRID response can advance past externally completed CredSSP into MCS setup.
#[test]
fn proxy_completed_credssp_reaches_basic_settings_exchange() {
    let mut connector = proxy_connector();
    let _request = send_connection_request(&mut connector);
    let confirm = encode_vec(&X224(ConnectionConfirm::Response {
        flags: ResponseFlags::empty(),
        protocol: SecurityProtocol::HYBRID,
    }))
    .unwrap();
    let mut output = WriteBuf::new();

    connector.step(&confirm, &mut output).unwrap();
    connector.mark_security_upgrade_as_done();
    assert!(connector.should_perform_credssp());

    connector.mark_credssp_as_done();
    assert!(matches!(
        connector.state,
        ClientConnectorState::BasicSettingsExchangeSendInitial {
            selected_protocol: SecurityProtocol::HYBRID
        }
    ));
}
