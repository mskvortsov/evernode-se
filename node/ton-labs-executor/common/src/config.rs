use adnl::node::{AdnlNodeConfig, AdnlNodeConfigJson};
use ever_crypto::sha256_digest;
use std::{fs::{File, read_to_string}, io::Write, net::{IpAddr, SocketAddr}, path::Path};
use ton_types::{fail, Result};

pub async fn resolve_ip(ip: &str) -> Result<SocketAddr> {
    let mut ret = ip.parse::<SocketAddr>()?;
    if ret.ip().is_unspecified() {
        let ip = external_ip::ConsensusBuilder::new()
            .add_sources(external_ip::get_http_sources::<external_ip::Sources>())
            .build()
            .get_consensus().await;
        if let Some(IpAddr::V4(ip)) = ip {
            ret.set_ip(IpAddr::V4(ip))
        } else {
            fail!("Cannot obtain own external IP address")
        }
    }
    Ok(ret)
}

pub fn get_test_config_path(prefix: &str, addr: &SocketAddr) -> Result<String> {
    if let IpAddr::V4(ip) = addr.ip() {
        Ok(
            format!(
                "{}_{}_{}.json", 
                prefix, 
                ip.to_string().as_str(), 
                addr.port().to_string().as_str()
            )
        )
    } else {
        fail!("Cannot generate config path for IP address that is not V4")
    }
} 

pub fn generate_adnl_configs(
    ip: &str,
    tags: Vec<usize>,
    addr: Option<SocketAddr>
) -> Result<(AdnlNodeConfigJson, AdnlNodeConfig)> {
    if let Some(addr) = addr {
        let mut keys = Vec::new();
        let addr = addr.to_string();
        for tag in tags {
            let mut data = Vec::new();
            data.extend_from_slice(&addr.as_bytes());
            data.extend_from_slice(&tag.to_be_bytes());
            let key: [u8; 32] = sha256_digest(&data);
            keys.push((key, tag));
        }
        AdnlNodeConfig::from_ip_address_and_private_keys(ip, keys)
    } else {
        AdnlNodeConfig::with_ip_address_and_private_key_tags(ip, tags)
    }
}

// Is used only for protocol tests
#[allow(dead_code)]
pub async fn get_adnl_config(
    prefix: &str, 
    ip: &str, 
    tags: Vec<usize>,
    deterministic: bool
) -> Result<AdnlNodeConfig> {
    let resolved_ip = resolve_ip(ip).await?;
    let config = get_test_config_path(prefix, &resolved_ip)?;
    let config = if Path::new(config.as_str()).exists() {
        let config = read_to_string(config)?;
        AdnlNodeConfig::from_json(config.as_str())?
    } else {
        let resolved_ip = if deterministic {
            Some(resolved_ip)
        } else {
            None
        };
        let (json, bin) = generate_adnl_configs(ip, tags, resolved_ip)?;
        File::create(config.as_str())?.write_all(
            serde_json::to_string_pretty(&json)?.as_bytes()
        )?;
        bin
    };
    Ok(config)
}
