#[macro_use]
extern crate lazy_static;

mod net;
mod scanner;
mod svc_table;
mod utils;

use core::fmt;
use std::{collections::{HashMap, HashSet}, error::Error, fmt::{Display, Formatter}, fs::File, io::BufRead, io::{self, BufReader}, net::{IpAddr, Ipv4Addr, SocketAddr, SocketAddrV4}, path::PathBuf, result, str::FromStr, sync::Arc, time::Duration};

use net::raw::{devices::EthernetDevice, ether::MacAddr, pcap};
use scanner::ScanResult;

use crate::net::raw::{arp::scanner::Ipv4ArpScanner, icmp::scanner::IcmpScanner, tcp::scanner::{PortCollection, TcpPortScanner}};

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
        .build();

    let rtsp_port_priorities = get_port_priorities(RTSP_PORT_CANDIDATES);

    let mut port_candidates = HashSet::<u16>::new();
    port_candidates.extend(RTSP_PORT_CANDIDATES);
    // port_candidates.extend(HTTP_PORT_CANDIDATES);

    let mut report = find_open_ports(&port_candidates);

    println!("Successfully");
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
