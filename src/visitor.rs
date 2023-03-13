use crate::proto::Visitor;
use anyhow::Context;
use maxminddb::{geoip2, Reader};
use std::net::{IpAddr, Ipv4Addr};
use tracing::*;

fn nice_uri(uri: &str) -> String {
    let out = uri.to_string();
    if out.contains('?') {
        // return everything before the ?
        return out.split('?').next().unwrap().to_string();
    }
    out
}

pub struct MmReader {
    reader: Reader<Vec<u8>>,
}

impl MmReader {
    pub fn new(path: &str) -> anyhow::Result<Self> {
        let db = format!("{}/GeoLite2-City.mmdb", path);
        let reader = Reader::open_readfile(db).context("open maxmind db")?;
        Ok(Self { reader })
    }

    #[instrument(skip(self), level = "debug")]
    pub fn visit(&self, ip: Ipv4Addr, uri: &str) -> anyhow::Result<Visit> {
        // convert Ipv4Addr into IpAddr
        let gc: geoip2::City = self
            .reader
            .lookup(IpAddr::V4(ip))
            .context("lookup ip in maxmind db")?;
        let country: Option<String> = match gc.country {
            Some(c) => c.iso_code.map(|x| x.to_string()),
            None => None,
        };
        let city: Option<String> = match gc.city {
            Some(c) => c.names.and_then(|x| x.get("en").map(|x| x.to_string())),
            None => None,
        };
        Ok(Visit {
            ip,
            country,
            city,
            uri: nice_uri(uri),
        })
    }
}

#[derive(Debug, Clone)]
pub struct Visit {
    ip: Ipv4Addr,
    country: Option<String>,
    city: Option<String>,
    uri: String,
}

impl Visit {
    pub fn no_ip(uri: &str) -> Self {
        Self {
            ip: Ipv4Addr::new(127, 0, 0, 1),
            country: None,
            city: None,
            uri: nice_uri(uri),
        }
    }
}

impl Visitor for Visit {
    fn ip(&self) -> Ipv4Addr {
        self.ip
    }
    fn country(&self) -> Option<String> {
        self.country.clone()
    }
    fn city(&self) -> Option<String> {
        self.city.clone()
    }
    fn uri(&self) -> String {
        self.uri.clone()
    }
}
