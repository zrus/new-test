use std::net::Ipv4Addr;
use std::os::raw::{c_char, c_void};

use super::ether::MacAddr;

#[allow(non_camel_case_types)]
type net_device = *mut c_void;

#[link(name = "net_devices")]
extern "C" {
    fn net_find_devices() -> net_device;
    fn net_free_device_list(dev: net_device) -> c_void;
    fn net_get_name(dev: net_device) -> *const c_char;
    fn net_get_ipv4_address(dev: net_device) -> *const c_char;
    fn net_get_ipv4_netmask(dev: net_device) -> *const c_char;
    fn net_get_mac_address(dev: net_device) -> *const c_char;
    fn net_get_next_device(dev: net_device) -> net_device;
    fn net_get_mac_addr_size() -> usize;
    fn net_get_ipv4_addr_size() -> usize;
}

#[derive(Clone, Debug)]
pub struct EthernetDevice {
    pub name: String,
    pub mac_addr: MacAddr,
    pub ip_addr: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

impl EthernetDevice {
    /// List all configured IPv4 network devices.
    pub fn list() -> Vec<Self> {
        let mut result = Vec::new();

        unsafe {
            let devices = net_find_devices();

            let mut device = devices;

            while !device.is_null() {
                result.push(Self::new(device));
                device = net_get_next_device(device);
            }

            net_free_device_list(devices);
        }

        result
    }
}
