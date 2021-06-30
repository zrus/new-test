#[macro_use]
extern crate lazy_static;

mod net;
mod scanner;
mod svc_table;
mod utils;

use core::fmt;
use std::{collections::{HashMap, HashSet}, error::Error, fmt::{Display, Formatter}, fs::File, io::BufRead, io::{self, BufReader}, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4, SocketAddrV6}, path::PathBuf, result, str::FromStr, sync::Arc, time::Duration};

use futures::{Future, FutureExt};
use net::{raw::{devices::EthernetDevice, ether::MacAddr, pcap}, rtsp::sdp::{FromAttribute, MediaType, RTPMap, SessionDescription}};
use scanner::ScanResult;
use svc_table::{Service, ServiceType};

use crate::net::raw::{arp::scanner::Ipv4ArpScanner, icmp::scanner::IcmpScanner, tcp::scanner::{PortCollection, TcpPortScanner}};
use crate::net::rtsp::Request as RtspRequest;
use crate::net::rtsp::Response as RtspResponse;

// use result::ScanResult;

const RTSP_PATH_FILE: &str = "rtsp-paths";
// const MJPEG_PATH_FILE: &str = "mjpeg-paths";

const RTSP_PORT_CANDIDATES: &[u16] = &[554, 88, 81, 555, 7447, 8554, 7070, 10554, 80, 6667];
// const HTTP_PORT_CANDIDATES: &[u16] = &[80, 81, 8080, 8081, 8090];

const HR_FLAG_ARP: u8 = 0x01;
const HR_FLAG_ICMP: u8 = 0x02;

#[derive(Debug, Clone)]
pub struct DiscoveryError {
    msg: String,
}

impl DiscoveryError {
    /// Create a new error.
    pub fn new<T>(msg: T) -> Self
    where
        T: ToString,
    {
        Self {
            msg: msg.to_string(),
        }
    }
}

impl Error for DiscoveryError {}

impl Display for DiscoveryError {
    fn fmt(&self, f: &mut Formatter) -> result::Result<(), fmt::Error> {
        f.write_str(&self.msg)
    }
}

impl From<pcap::PcapError> for DiscoveryError {
    fn from(err: pcap::PcapError) -> Self {
        Self::new(format!("pcap error: {}", err))
    }
}

impl From<io::Error> for DiscoveryError {
    fn from(err: io::Error) -> Self {
        Self::new(format!("IO error: {}", err))
    }
}

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
enum StreamType {
    Supported,
    Locked,
    Unsupported,
    NotFound,
    Error,
}

impl From<RtspResponse> for StreamType {
    fn from(response: RtspResponse) -> Self {
        let status_code = response.status_code();

        if status_code == 200 {
            if is_supported_rtsp_service(response.body()) {
                Self::Supported
            } else {
                Self::Unsupported
            }
        } else if status_code == 401 {
            Self::Locked
        } else if status_code == 404 {
            Self::NotFound
        } else {
            Self::Error
        }
    }
}

/// Discovery result type alias.
pub type Result<T> = result::Result<T, DiscoveryError>;

fn main() {
    let rtsp_paths_file = PathBuf::from(RTSP_PATH_FILE);
    let file = File::open(rtsp_paths_file);

    let breader = BufReader::new(file.unwrap());
    let mut rtsp_paths = Vec::new();
    for line in breader.lines() {
        let path = line.unwrap();
        if !path.starts_with('#') {
            rtsp_paths.push(path);
        }
    }

    // let mjpeg_paths_file = PathBuf::from(MJPEG_PATH_FILE);
    // let file = File::open(mjpeg_paths_file);

    // let breader = BufReader::new(file.unwrap());
    // let mut mjpeg_paths = Vec::new();
    // for line in breader.lines() {
    //     let path = line.unwrap();
    //     if !path.starts_with('#') {
    //         mjpeg_paths.push(path);
    //     }
    // }

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_io()
        .enable_time()
        .build().map_err(|err| DiscoveryError::new(format!("Async IO error: {}", err))).unwrap();

    let rtsp_port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);

    let mut port_candidates = HashSet::<u16>::new();
    port_candidates.extend(RTSP_PORT_CANDIDATES);
    // port_candidates.extend(HTTP_PORT_CANDIDATES);

    let mut report = find_open_ports(&port_candidates);

    println!("Successfully");

    let rtsp_services = runtime.block_on(find_rtsp_services(report.socket_addrs()));

    let rtsp_services = filter_duplicit_services(rtsp_services, &rtsp_port_priorities);

    let rtsp_streams = runtime.block_on(find_rtsp_streams(rtsp_services.into_iter(), &rtsp_paths));

    let mut hosts = HashSet::new();

    hosts.extend(get_hosts(&rtsp_streams));

    for svc in rtsp_streams {
        report.add_service(svc);
    }

    println!("Successfully");

    for svc in report.services() {
        println!("{:?}", svc);
    }
}

fn get_port_priorities(ports: &[u16]) -> HashMap<u16, usize> {
    let mut res = HashMap::new();

    let len = ports.len();

    for (index, port) in ports.iter().enumerate() {
        res.insert(*port, len - index);
    }

    res
}

fn find_open_ports(port_candidates: &HashSet::<u16>) -> ScanResult {
    let mut report = ScanResult::new();

    let devices = EthernetDevice::list();

    for dev in devices {
        let res = find_open_ports_in_network(port_candidates, &dev);

        if let Err(err) = res {
            println!(
                "unable to find open ports in local network on interface {}: {}",
                dev.name, err
            );
        } else if let Ok(res) = res {
            report.merge(res);
        }
    }

    report
}

fn find_open_ports_in_network(port_candidates: &HashSet::<u16>, device: &EthernetDevice) -> Result<ScanResult> {
    let mut report = ScanResult::new();

    println!(
        "running ARP scan in local network on interface {}",
        device.name
    );

    for (mac, ip) in Ipv4ArpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ARP);
    }

    println!(
        "running ICMP echo scan in local network on interface {}",
        device.name
    );

    for (mac, ip) in IcmpScanner::scan_device(device)? {
        report.add_host(mac, IpAddr::V4(ip), HR_FLAG_ICMP);
    }

    let open_ports;

    {
        let hosts = report.hosts().map(|host| (host.mac, host.ip));

        open_ports = find_open_ports_on_hosts(port_candidates, device, hosts)?;
    }

    for (mac, addr) in open_ports {
        report.add_port(mac, addr.ip(), addr.port());
    }

    Ok(report)
}

fn find_open_ports_on_hosts<I>(
    port_candidates: &HashSet::<u16>,
    device: &EthernetDevice,
    hosts: I,
) -> Result<Vec<(MacAddr, SocketAddr)>>
where
    I: IntoIterator<Item = (MacAddr, IpAddr)>,
{
    println!(
        "running TCP port scan in local network on interface {}",
        device.name
    );

    let hosts = hosts.into_iter().filter_map(|(mac, ip)| match ip {
        IpAddr::V4(ip) => Some((mac, ip)),
        _ => None,
    });

    let candidates = port_candidates.iter().cloned();

    let ports = PortCollection::new().push_all(candidates);

    let res = TcpPortScanner::scan_ipv4_hosts(device, hosts, &ports)?
        .into_iter()
        .map(|(mac, ip, p)| (mac, SocketAddr::V4(SocketAddrV4::new(ip, p))))
        .collect::<Vec<_>>();

    Ok(res)
}

async fn find_rtsp_services<I>(open_ports: I) -> Vec<(MacAddr, SocketAddr)>
where I: IntoIterator<Item = (MacAddr, SocketAddr)>
{
    println!("looking for RTSP services");

    let filtered = filter_services(open_ports, |saddr| async move {
        if RTSP_PORT_CANDIDATES.contains(&saddr.port()) {
            is_rtsp_service(saddr).await
        } else {
            false
        }
    }) ;

    filtered.await
}

async fn filter_services<I, P, F>(candidates: I, predicate: P,) -> Vec<(MacAddr, SocketAddr)> 
where I: IntoIterator<Item = (MacAddr, SocketAddr)>, P: Fn(SocketAddr) -> F, F: Future<Output = bool>, {
    let futures = candidates.into_iter().map(|(mac, saddr)| predicate(saddr).map(move |res| (mac, saddr, res)));

    futures::future::join_all(futures).await.into_iter().filter_map(|(mac, saddr, res)| {
        if res {
            Some((mac, saddr))
        } else {
            None
        }
    }).collect()
}

async fn is_rtsp_service(addr: SocketAddr) -> bool {
    let request = RtspRequest::options(&format!("rtsp://{}/", addr));

    if request.is_err() {
        return false;
    }

    request.unwrap().set_request_timeout(Some(Duration::from_millis(2000))).send().await.is_ok()
}

fn filter_duplicit_services<I>(services: I, port_priorities: &HashMap<u16, usize>) -> Vec<(MacAddr, SocketAddr)>
where I: IntoIterator<Item = (MacAddr, SocketAddr)> {
    let mut svc_map = HashMap::new();

    for (mac, saddr) in services {
        let ip = saddr.ip();
        let port = saddr.port();

        svc_map.entry(ip).and_modify(|v| {
            let &mut (_, _, old_port) = v;

            let old_priority = port_priorities.get(&old_port).cloned().unwrap_or(0);
            let new_priority = port_priorities.get(&port).cloned().unwrap_or(0);

            if new_priority > old_priority {
                *v = (mac, ip, port);
            }
        }).or_insert((mac, ip, port));
    }

    svc_map.into_iter().map(|(_, (mac, ip, port))| match ip {
        IpAddr::V4(ip) => (mac, SocketAddr::V4(SocketAddrV4::new(ip, port))),
        IpAddr::V6(ip) => (mac, SocketAddr::V6(SocketAddrV6::new(ip, port, 0, 0))),
    }).collect::<_>()
}

async fn find_rtsp_streams<I>(rtsp_services: I, rtsp_paths: &Vec<String>) -> Vec<Service>
where I: IntoIterator<Item = (MacAddr, SocketAddr)> {
    println!("looking for RTSP stream");

    let futures = rtsp_services.into_iter().map(|(mac, addr)| find_rtsp_stream(mac, addr, rtsp_paths));

    futures::future::join_all(futures).await
} 

async fn find_rtsp_stream(mac: MacAddr, addr: SocketAddr, rtsp_paths: &Vec<String>) -> Service {
    let mut res = Service::unknown_rtsp(mac, addr);

    for path in rtsp_paths.iter() {
        let service = get_rtsp_stream(mac, addr, path);

        if let Some(svc) = service.await {
            if svc.service_type() == ServiceType::RTSP || svc.service_type() == ServiceType::LockedRTSP
            {
                return svc;
            } else {
                res = svc;
            }
        }
    }

    res
}

async fn get_rtsp_stream(
    mac: MacAddr,
    addr: SocketAddr,
    path: &str,
) -> Option<Service> {
    let path = path.to_string();

    let stream_type = get_rtsp_stream_type(addr, &path);

    match stream_type.await {
        StreamType::Supported => Some(Service::rtsp(mac, addr, path)),
        StreamType::Unsupported => Some(Service::unsupported_rtsp(mac, addr, path)),
        StreamType::Locked => Some(Service::locked_rtsp(mac, addr, None)),

        _ => None,
    }
}

/// Get stream type for a given RTSP service and path.
async fn get_rtsp_stream_type(addr: SocketAddr, path: &str) -> StreamType {
    let path = path.to_string();

    let request = RtspRequest::describe(&format!("rtsp://{}{}", addr, path));

    if request.is_err() {
        return StreamType::Error;
    }

    request
        .unwrap()
        .set_request_timeout(Some(Duration::from_millis(2000)))
        .send()
        .await
        .map(|response| {
            if is_hipcam_rtsp_response(&response) && path != "/11" && path != "/12" {
                StreamType::NotFound
            } else {
                StreamType::from(response)
            }
        })
        .unwrap_or(StreamType::Error)
}

/// Check if a given RTSP response is from a buggy Hi(I)pcam RTSP server.
fn is_hipcam_rtsp_response(response: &RtspResponse) -> bool {
    matches!(
        response.get_header_field_value("server"),
        Some("HiIpcam/V100R003 VodServer/1.0.0") | Some("Hipcam RealServer/V1.0"),
    )
}

fn is_supported_rtsp_service(sdp: &[u8]) -> bool {
    if let Ok(sdp) = SessionDescription::parse(sdp) {
        let mut vcodecs = HashSet::new();

        let video_streams = sdp
            .media_descriptions
            .into_iter()
            .filter(|md| md.media_type == MediaType::Video);

        for md in video_streams {
            for attr in md.attributes {
                if let Ok(rtpmap) = RTPMap::from_attr(&attr) {
                    vcodecs.insert(rtpmap.encoding.to_uppercase());
                }
            }
        }

        vcodecs.contains("H264")
            || vcodecs.contains("H264-RCDO")
            || vcodecs.contains("H264-SVC")
            || vcodecs.contains("MP4V-ES")
            || vcodecs.contains("MPEG4-GENERIC")
    } else {
        false
    }
}

fn get_hosts(services: &[Service]) -> Vec<IpAddr> {
    let mut hosts = HashSet::new();

    for svc in services {
        if let Some(saddr) = svc.address() {
            hosts.insert(saddr.ip());
        }
    }

    hosts.into_iter().collect::<_>()
}
