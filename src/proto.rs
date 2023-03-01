use anyhow::{bail, Context};
use ipnetwork::{Ipv4Network, Ipv6Network};
use serde::{Deserialize, Serialize};
// use std::collections::BTreeMap as Map;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::*;

// abstraction to wrap properties of HTTP request
pub trait Visitor {
    fn country(&self) -> Option<String>;
    fn city(&self) -> Option<String>;
    fn ip(&self) -> Ipv4Addr;
    fn ipv6(&self) -> Ipv6Addr;
    fn uri(&self) -> String;
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Source {
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "ip")]
    FromIpv4(Ipv4Addr),
    #[serde(rename = "ip6")]
    FromIpv6(Ipv6Addr),
    #[serde(rename = "net")]
    FromIpv4Network(Ipv4Network),
    #[serde(rename = "net6")]
    FromIpv6Network(Ipv6Network),
    #[serde(rename = "country")]
    FromCountry(String),
    #[serde(rename = "city")]
    FromCity(String),
}

impl Source {
    pub fn to_string(&self) -> String {
        match self {
            Source::Any => "*".to_string(),
            Source::FromIpv4(ip) => ip.to_string(),
            Source::FromIpv6(ip) => ip.to_string(),
            Source::FromIpv4Network(net) => net.to_string(),
            Source::FromIpv6Network(net) => net.to_string(),
            Source::FromCountry(country) => country.to_string(),
            Source::FromCity(city) => city.to_string(),
        }
    }

    pub fn parse(input: &str) -> Self {
        if input == "" || input == "*" {
            Source::Any
        } else if input.len() == 2 {
            // 2 rule character set will be treated as a country
            Source::FromCountry(input.to_string())
        } else if let Ok(ip) = input.parse::<Ipv4Addr>() {
            Source::FromIpv4(ip)
        } else if let Ok(net) = input.parse::<Ipv4Network>() {
            Source::FromIpv4Network(net)
        } else if let Ok(ip) = input.parse::<Ipv6Addr>() {
            Source::FromIpv6(ip)
        } else if let Ok(net) = input.parse::<Ipv6Network>() {
            Source::FromIpv6Network(net)
        } else {
            // we've filtered out empty results already
            // so the unclassified string would be treated like a city
            Source::FromCity(input.to_string())
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Target {
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "path")]
    Path(String),
    #[serde(rename = "path-prefix")]
    PathPrefix(String),
}

impl Target {
    pub fn to_string(&self) -> String {
        match self {
            Target::Any => "".to_string(),
            Target::Path(path) => path.to_string(),
            Target::PathPrefix(path) => format!("^{}", path),
        }
    }

    pub fn parse(input: &str) -> Self {
        if input == "" {
            return Self::Any;
        }
        let start = input.chars().next().unwrap();
        if start == '/' {
            Self::Path(input.to_string())
        } else if start == '^' {
            Self::PathPrefix(input.chars().skip(1).collect())
        } else {
            Self::Any
        }
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Access {
    #[serde(rename = "from")]
    From(Source),
    #[serde(rename = "excluding")]
    Excluding(Source),
}

impl Access {
    pub fn to_string(&self) -> String {
        match self {
            Access::From(source) => source.to_string(),
            Access::Excluding(source) => format!("-{}", source.to_string()),
        }
    }

    pub fn parse(input: &str) -> Self {
        if input.len() > 1 && input.chars().next().unwrap() == '-' {
            let next = &input[1..];
            return Access::Excluding(Source::parse(next));
        }
        Access::From(Source::parse(input))
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Reaction {
    #[serde(rename = "301")]
    PermanentRedirect(String),
    #[serde(rename = "302")]
    TemporaryRedirect(String),
    #[serde(rename = "code")]
    HttpStatus(u16),
    // TODO: reaction with additional header (key=value)
}

impl Reaction {
    // returns reaction code
    pub fn code(&self) -> u16 {
        match self {
            Reaction::PermanentRedirect(_) => 301,
            Reaction::TemporaryRedirect(_) => 302,
            Reaction::HttpStatus(code) => *code,
        }
    }

    // returns redirect location, if any
    pub fn redirect(&self) -> Option<String> {
        match self {
            Reaction::PermanentRedirect(loc) => Some(loc.to_string()),
            Reaction::TemporaryRedirect(loc) => Some(loc.to_string()),
            Reaction::HttpStatus(_) => None,
        }
    }

    pub fn extract(input: &str) -> anyhow::Result<(String, Reaction)> {
        let parts: Vec<&str> = input.split("|").collect();
        // if there are 2 parts in the rule, we expect the description of the redirect
        let (remaining, out) = if parts.len() == 3 {
            // case for redirect
            let part1 = parts[0];
            // we are expecting redirect, acceptable statuses
            if part1 != "301" && part1 != "302" {
                bail!("redirect HTTP status expected 301 or 302");
            }
            let redirect = parts[2];
            if part1 == "301" {
                (parts[1], Reaction::PermanentRedirect(redirect.to_owned()))
            } else {
                (parts[1], Reaction::TemporaryRedirect(redirect.to_owned()))
            }
        } else if parts.len() == 1 {
            (parts[0], Reaction::HttpStatus(200))
        } else {
            // if parts.len() == 2 {
            let status = parts[0].parse::<u16>().context("invalid HTTP status")?;
            (parts[1], Reaction::HttpStatus(status))
        };
        Ok((remaining.to_string(), out))
    }
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(flatten)]
    pub access: Vec<Access>,
    #[serde(flatten)]
    pub target: Vec<Target>,
    #[serde(flatten)]
    pub reaction: Reaction,
}

impl Rule {
    /// function to parse the rule from one line string
    /// rule consists of optional reaction, separated by |, access list and target list
    /// to match the rule, any of the source in the access list should be matched
    /// and at least of the target in the target list should be matched
    /// If access list is not specified, it matches any source,
    /// if target list is not specified, it matches any target. Empty rule matches everything.
    ///
    /// Examples of rules:
    /// ```
    /// 200|US,CA,/path/to/resource
    /// 301|-GB,^/path/to/resource|/not-found
    /// 403|-US
    /// ```
    pub fn parse(src: &str) -> anyhow::Result<Rule> {
        let (input, reaction) = Reaction::extract(src)?;

        let mut access = vec![];
        let mut target = vec![];
        for part in input.split(",") {
            if part.starts_with("/") || part.starts_with("^") {
                target.push(Target::parse(part));
            } else {
                access.push(Access::parse(part));
            }
        }
        // empty strings turn it into the ALLOW-ALL rule
        if access.len() == 0 {
            access.push(Access::From(Source::Any));
        }
        if target.len() == 0 {
            target.push(Target::Any);
        }
        Ok(Self {
            access,
            target,
            reaction,
        })
    }

    // function to convert rule to string representation
    pub fn to_string(&self) -> String {
        let mut out = Vec::<String>::new();
        if self.reaction.code() != 200 {
            out.push(self.reaction.code().to_string());
        };
        let mut parts = Vec::<String>::new();
        for access in &self.access {
            let a = access.to_string();
            if a.len() > 0 {
                parts.push(a);
            }
        }
        for target in &self.target {
            let t = target.to_string();
            if t.len() > 0 {
                parts.push(t);
            }
        }
        out.push(parts.join(","));
        if let Some(redirect) = self.reaction.redirect() {
            out.push(redirect);
        }
        out.join("|")
    }

    // function to validate the Rule against Visitor
    pub fn react<V: Visitor>(&self, v: &V) -> Option<Reaction> {
        let mut out = None;
        for access in &self.access {
            match access {
                Access::From(source) => {
                    let result = match source {
                        Source::Any => true,
                        Source::FromIpv4(ip) => v.ip() == *ip,
                        Source::FromIpv6(ip) => v.ipv6() == *ip,
                        Source::FromIpv4Network(net) => net.contains(v.ip()),
                        Source::FromIpv6Network(net) => net.contains(v.ipv6()),
                        Source::FromCountry(country) => v.country() == Some(country.to_string()),
                        Source::FromCity(city) => v.city() == Some(city.to_string()),
                    };
                    if result {
                        out = Some(self.reaction.clone());
                    }
                }
                Access::Excluding(source) => {
                    let result = match source {
                        Source::Any => false,
                        Source::FromIpv4(ip) => v.ip() == *ip,
                        Source::FromIpv6(ip) => v.ipv6() == *ip,
                        Source::FromIpv4Network(net) => net.contains(v.ip()),
                        Source::FromIpv6Network(net) => net.contains(v.ipv6()),
                        Source::FromCountry(country) => v.country() == Some(country.to_string()),
                        Source::FromCity(city) => v.city() == Some(city.to_string()),
                    };
                    if result {
                        out = None;
                    }
                }
            }
        }
        out
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SecurityGroup {
    // alphanumeric name
    pub name: String,
    // list of rules that apply to this rule
    pub list: Vec<Rule>,
}

impl SecurityGroup {
    pub fn react<V: Visitor>(&self, v: &V) -> anyhow::Result<Option<Reaction>> {
        for rule in &self.list {
            if let Some(reaction) = rule.react(v) {
                return Ok(Some(reaction));
            }
        }
        Ok(None)
    }

    // writes security group to the writer, using rule writer, one rule at a line
    pub fn to_writer<W: Write>(&self, w: &mut W) -> anyhow::Result<()> {
        for rule in &self.list {
            writeln!(w, "{}", rule.to_string())?;
        }
        Ok(())
    }

    // save to local file
    pub fn save_to_file(&self, path: &str) -> anyhow::Result<()> {
        let mut f = File::create(path)?;
        self.to_writer(&mut f)?;
        Ok(())
    }

    // reads rules from reader, one rule per line
    pub fn from_reader<R: Read>(name: &str, r: &mut R) -> Self {
        let mut out = Self {
            name: name.to_string(),
            list: vec![],
        };
        let lines = BufReader::new(r).lines();
        for next_line in lines {
            if let Ok(line) = next_line {
                let ln = line.trim();
                // skipping empty lines and comments
                if ln.len() > 0 && !ln.starts_with("#") {
                    match Rule::parse(ln) {
                        Ok(rule) => out.list.push(rule),
                        Err(e) => warn!("{:?}", e),
                    };
                }
            }
        }
        out
    }

    // load from local file
    pub fn from_file(name: &str, path: &str) -> anyhow::Result<Self> {
        let mut f = File::open(path)?;
        Ok(Self::from_reader(name, &mut f))
    }
}

#[cfg(test)]
pub mod tests {

    use super::*;
    use std::io::BufWriter;
    // mock visitor
    pub struct MockVisitor {
        ip: Ipv4Addr,
        ipv6: Ipv6Addr,
        country: Option<String>,
        city: Option<String>,
        uri: String,
    }

    impl MockVisitor {
        pub fn new() -> Self {
            Self {
                ip: Ipv4Addr::new(127, 0, 0, 1),
                ipv6: Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1),
                country: None,
                city: None,
                uri: "/".to_owned(),
            }
        }
        pub fn set_ip(&mut self, ip: Ipv4Addr) {
            self.ip = ip;
        }
        pub fn set_ipv6(&mut self, ipv6: Ipv6Addr) {
            self.ipv6 = ipv6;
        }
        pub fn set_country(&mut self, country: Option<String>) {
            self.country = country;
        }
        pub fn set_city(&mut self, city: Option<String>) {
            self.city = city;
        }
        pub fn set_uri(&mut self, uri: &str) {
            self.uri = uri.to_string();
        }
    }

    impl Visitor for MockVisitor {
        fn ip(&self) -> Ipv4Addr {
            self.ip
        }
        fn ipv6(&self) -> Ipv6Addr {
            self.ipv6
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

    // The macro we'll use to define our tests
    macro_rules! test_rule  {
        ($($name:ident: $value:expr,)*) => {
        $(
            #[test]
            fn $name() {
                let (input, expected) = $value;
                let r = Rule::parse(input).unwrap();
                assert_eq!(r, expected);
            }
        )*
        }
    }

    test_rule! {
        empty_string : ("", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        asterisk : ("*", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        deny_all : ("403|*", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(403),
        }),
    }
    test_rule! {
        error_on_country : ("500|US", Rule {
            access: vec![Access::From(Source::FromCountry("US".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(500),
        }),
    }
    test_rule! {
        fail_on_country : ("401|-GB", Rule {
            access: vec![Access::Excluding(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(401),
        }),
    }
    test_rule! {
        permanent_redirect : ("301|/api/metrics|/metrics", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Path("/api/metrics".to_owned())],
            reaction: Reaction::PermanentRedirect("/metrics".to_owned()),
        }),
    }
    test_rule! {
        temp_redirect : ("302|/api/metrics|/metrics", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Path("/api/metrics".to_owned())],
            reaction: Reaction::TemporaryRedirect("/metrics".to_owned()),
        }),
    }
    test_rule! {
        country : ("GB", Rule {
            access: vec![Access::From(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        excluding_country : ("-GB", Rule {
            access: vec![Access::Excluding(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        ipv4network : ("192.168.0.0/8", Rule {
            access: vec![Access::From(Source::FromIpv4Network("192.168.0.0/8".parse().unwrap()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        ipv4 : ("192.168.0.1", Rule {
            access: vec![Access::From(Source::FromIpv4("192.168.0.1".parse().unwrap()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        ipv6 : ("2001:0db8:85a3:0000:0000:8a2e:0370:7334", Rule {
            access: vec![Access::From(Source::FromIpv6("2001:0db8:85a3:0000:0000:8a2e:0370:7334".parse().unwrap()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        city : ("London", Rule {
            access: vec![Access::From(Source::FromCity("London".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }
    test_rule! {
        multiple : ("GB,-US,ES", Rule {
            access: vec![
                Access::From(Source::FromCountry("GB".to_owned())),
                Access::Excluding(Source::FromCountry("US".to_owned())),
                Access::From(Source::FromCountry("ES".to_owned())),
            ],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
        }),
    }

    #[test]
    fn test_reaction_codes() {
        assert_eq!(Reaction::HttpStatus(200).code(), 200);
        assert_eq!(Reaction::HttpStatus(403).code(), 403);
        assert_eq!(Reaction::PermanentRedirect("/404".to_owned()).code(), 301);
        assert_eq!(Reaction::TemporaryRedirect("/404".to_owned()).code(), 302);
    }

    #[test]
    fn test_security_group_read_write() {
        let source = vec!["401|-JP", "403|ES", "301|127.0.0.1,/a/|/b/"].join("\n");

        let mut r = BufReader::new(source.as_bytes());
        let sg = SecurityGroup::from_reader("default", &mut r);
        let mut writer = BufWriter::new(Vec::new());
        sg.to_writer(&mut writer).unwrap();
        let s = String::from_utf8(writer.into_inner().unwrap()).unwrap();

        assert_eq!(s, format!("{}\n", source));
    }
}