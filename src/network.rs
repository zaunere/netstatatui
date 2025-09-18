use std::collections::HashMap;
use std::fs;
use std::net::{Ipv4Addr, Ipv6Addr};
use anyhow::Result;

#[derive(Debug, Clone)]
pub struct Connection {
    pub protocol: String,
    pub local_address: String,
    pub local_port: u16,
    pub remote_address: String,
    pub remote_port: u16,
    pub state: String,
    pub pid: Option<u32>,
    pub process_name: Option<String>,
}

pub struct NetworkMonitor {
    process_cache: HashMap<u32, String>,
}

impl NetworkMonitor {
    pub fn new() -> Self {
        Self {
            process_cache: HashMap::new(),
        }
    }

    pub fn get_connections(&mut self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();
        
        // Parse TCP connections
        connections.extend(self.parse_tcp_connections()?);
        
        // Parse UDP connections
        connections.extend(self.parse_udp_connections()?);
        
        Ok(connections)
    }

    fn parse_tcp_connections(&mut self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();
        
        // Parse IPv4 TCP
        if let Ok(content) = fs::read_to_string("/proc/net/tcp") {
            connections.extend(self.parse_proc_net_file(&content, "TCP")?);
        }
        
        // Parse IPv6 TCP
        if let Ok(content) = fs::read_to_string("/proc/net/tcp6") {
            connections.extend(self.parse_proc_net_file(&content, "TCP6")?);
        }
        
        Ok(connections)
    }

    fn parse_udp_connections(&mut self) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();
        
        // Parse IPv4 UDP
        if let Ok(content) = fs::read_to_string("/proc/net/udp") {
            connections.extend(self.parse_proc_net_file(&content, "UDP")?);
        }
        
        // Parse IPv6 UDP
        if let Ok(content) = fs::read_to_string("/proc/net/udp6") {
            connections.extend(self.parse_proc_net_file(&content, "UDP6")?);
        }
        
        Ok(connections)
    }

    fn parse_proc_net_file(&mut self, content: &str, protocol: &str) -> Result<Vec<Connection>> {
        let mut connections = Vec::new();
        
        for (i, line) in content.lines().enumerate() {
            if i == 0 {
                continue; // Skip header
            }
            
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.len() < 10 {
                continue;
            }
            
            let local_addr = self.parse_address(fields[1])?;
            let remote_addr = self.parse_address(fields[2])?;
            let state = self.parse_state(fields[3], protocol)?;
            let _uid = fields[7].parse::<u32>().unwrap_or(0);
            let inode = fields[9].parse::<u32>().unwrap_or(0);
            
            let (pid, process_name) = self.get_process_info(inode);
            
            connections.push(Connection {
                protocol: protocol.to_string(),
                local_address: local_addr.0,
                local_port: local_addr.1,
                remote_address: remote_addr.0,
                remote_port: remote_addr.1,
                state,
                pid,
                process_name,
            });
        }
        
        Ok(connections)
    }

    fn parse_address(&self, addr_str: &str) -> Result<(String, u16)> {
        let parts: Vec<&str> = addr_str.split(':').collect();
        if parts.len() != 2 {
            return Ok(("0.0.0.0".to_string(), 0));
        }
        
        let addr_hex = parts[0];
        let port_hex = parts[1];
        
        let port = u16::from_str_radix(port_hex, 16).unwrap_or(0);
        
        let addr = if addr_hex.len() == 8 {
            // IPv4
            let addr_num = u32::from_str_radix(addr_hex, 16).unwrap_or(0);
            let ip = Ipv4Addr::from(addr_num.to_le_bytes());
            ip.to_string()
        } else if addr_hex.len() == 32 {
            // IPv6
            let mut bytes = [0u8; 16];
            for i in 0..16 {
                let start = i * 2;
                let end = start + 2;
                if end <= addr_hex.len() {
                    bytes[i] = u8::from_str_radix(&addr_hex[start..end], 16).unwrap_or(0);
                }
            }
            let ip = Ipv6Addr::from(bytes);
            ip.to_string()
        } else {
            "0.0.0.0".to_string()
        };
        
        Ok((addr, port))
    }

    fn parse_state(&self, state_hex: &str, protocol: &str) -> Result<String> {
        if protocol.starts_with("UDP") {
            return Ok("".to_string()); // UDP is connectionless
        }
        
        let state_num = u8::from_str_radix(state_hex, 16).unwrap_or(0);
        let state = match state_num {
            0x01 => "ESTABLISHED",
            0x02 => "SYN_SENT",
            0x03 => "SYN_RECV",
            0x04 => "FIN_WAIT1",
            0x05 => "FIN_WAIT2",
            0x06 => "TIME_WAIT",
            0x07 => "CLOSE",
            0x08 => "CLOSE_WAIT",
            0x09 => "LAST_ACK",
            0x0A => "LISTEN",
            0x0B => "CLOSING",
            _ => "UNKNOWN",
        };
        
        Ok(state.to_string())
    }

    fn get_process_info(&mut self, inode: u32) -> (Option<u32>, Option<String>) {
        if inode == 0 {
            return (None, None);
        }
        
        // Try to find process by inode
        if let Ok(entries) = fs::read_dir("/proc") {
            for entry in entries.flatten() {
                if let Ok(pid) = entry.file_name().to_string_lossy().parse::<u32>() {
                    if let Some(process_name) = self.get_process_name_by_inode(pid, inode) {
                        self.process_cache.insert(pid, process_name.clone());
                        return (Some(pid), Some(process_name));
                    }
                }
            }
        }
        
        (None, None)
    }

    fn get_process_name_by_inode(&self, pid: u32, target_inode: u32) -> Option<String> {
        let fd_dir = format!("/proc/{}/fd", pid);
        if let Ok(entries) = fs::read_dir(&fd_dir) {
            for entry in entries.flatten() {
                if let Ok(link) = fs::read_link(entry.path()) {
                    if let Some(link_str) = link.to_str() {
                        if link_str.starts_with("socket:[") {
                            let inode_str = link_str.trim_start_matches("socket:[").trim_end_matches(']');
                            if let Ok(inode) = inode_str.parse::<u32>() {
                                if inode == target_inode {
                                    return self.get_process_name(pid);
                                }
                            }
                        }
                    }
                }
            }
        }
        None
    }

    fn get_process_name(&self, pid: u32) -> Option<String> {
        let comm_path = format!("/proc/{}/comm", pid);
        fs::read_to_string(&comm_path)
            .ok()
            .map(|s| s.trim().to_string())
    }
}
