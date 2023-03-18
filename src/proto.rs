use anyhow::{bail, Context};
use ipnetwork::Ipv4Network;
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap as Map;
use std::fs::File;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::Ipv4Addr;
use tracing::*;

// abstraction to wrap properties of HTTP request
pub trait Visitor {
    fn country(&self) -> Option<String>;
    fn city(&self) -> Option<String>;
    fn ip(&self) -> Ipv4Addr;
    fn uri(&self) -> String;
}

#[derive(PartialEq, Debug, Clone, Serialize, Deserialize)]
pub enum Source {
    #[serde(rename = "any")]
    Any,
    #[serde(rename = "ip")]
    FromIpv4(Ipv4Addr),
    #[serde(rename = "net")]
    FromIpv4Network(Ipv4Network),
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
            Source::FromIpv4Network(net) => net.to_string(),
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
    #[serde(flatten)]
    pub tags: Vec<String>,
}

impl Rule {
    // function to check if the rule has any access conditions
    // it is typical for redirects not to have any access conditions
    fn has_access_conditions(&self) -> bool {
        if self.access.len() == 0 || self.access.len() == 1 {
            if let Access::From(Source::Any) = self.access[0] {
                return false;
            }
        }
        true
    }

    // function to check if the rule has any target conditions
    // it is typical for IP-based rules not to have any target URL conditions
    fn has_target_conditions(&self) -> bool {
        if self.target.len() == 0 || self.target.len() == 1 {
            if let Target::Any = self.target[0] {
                return false;
            }
        }
        true
    }

    // returns the list of index keys for the rule
    fn index_keys(&self) -> Vec<String> {
        let mut v = vec![];
        if !self.has_access_conditions() {
            for t in &self.target {
                if let Target::Path(x) = t {
                    if let Some(last_char) = x.chars().last() {
                        if last_char != '/' {
                            v.push(format!("{}/", x));
                        }
                    }
                    v.push(x.to_string());
                }
            }
        } else if !self.has_target_conditions() {
            for a in &self.access {
                if let Access::From(Source::FromIpv4(ip)) = a {
                    v.push(ip.to_string());
                } else if let Access::From(Source::FromCountry(country)) = a {
                    v.push(country.to_string());
                }
            }
        }
        v
    }

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
    /// 200|US,CA,/path/to/resource#blacklist,recent
    /// 301|-GB,^/path/to/resource|/not-found
    /// 403|-US
    /// ```
    pub fn parse(src: &str) -> anyhow::Result<Rule> {
        let mut tags = vec![];
        let with_tags: Vec<&str> = src.split("#").collect();
        let remains = if with_tags.len() > 1 {
            tags = with_tags[1].split(",").map(|s| s.to_string()).collect();
            with_tags[0]
        } else {
            src
        };
        let (input, reaction) = Reaction::extract(remains)?;
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
            tags,
        })
    }

    // function to convert rule to string representation
    pub fn to_string(&self) -> String {
        let mut out = Vec::<String>::new();
        if self.reaction.code() != 200 {
            out.push(self.reaction.code().to_string());
        };
        let mut parts = Vec::<String>::new();
        if self.has_access_conditions() {
            for access in &self.access {
                let a = access.to_string();
                if a.len() > 0 {
                    parts.push(a);
                }
            }
        }
        for target in &self.target {
            let t = target.to_string();
            if t.len() > 0 {
                parts.push(t);
            }
        }
        // if parts.len() > 0 {
        out.push(parts.join(","));
        // }
        if let Some(redirect) = self.reaction.redirect() {
            out.push(redirect);
        }
        let mut out_str = out.join("|");
        if self.tags.len() > 0 {
            out_str.push_str("#");
            out_str.push_str(&self.tags.join(","));
        }
        // let index_keys = self.index_keys();
        // if index_keys.len() > 0 {
        //     out_str.push_str("---");
        //     out_str.push_str(&index_keys.join(","));
        // }
        out_str
    }

    // function to validate the Rule against Visitor
    pub fn react<V: Visitor>(&self, v: &V) -> Option<Reaction> {
        let mut out = None;

        let mut match_target = false;
        if self.target.len() > 0 {
            // if rule is target-specific, we should check each URL, otherwise continue
            for t in &self.target {
                match t {
                    Target::Path(path) => {
                        if v.uri() == *path || v.uri() == format!("{}/", *path) {
                            match_target = true;
                            break;
                        }
                    }
                    Target::PathPrefix(prefix) => {
                        if v.uri().starts_with(prefix) {
                            match_target = true;
                            break;
                        }
                    }
                    Target::Any => {
                        match_target = true;
                        break;
                    }
                }
                if match_target {
                    continue;
                }
            }
        } else {
            match_target = true; // no target rules - we have match
        }
        if !match_target {
            return None;
        }

        for access in &self.access {
            match access {
                Access::From(source) => {
                    let result = match source {
                        Source::Any => true,
                        Source::FromIpv4(ip) => v.ip() == *ip,
                        Source::FromIpv4Network(net) => net.contains(v.ip()),
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
                        Source::FromIpv4Network(net) => net.contains(v.ip()),
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

#[derive(Clone, Serialize, Deserialize)]
pub struct SecurityGroup {
    // alphanumeric name
    pub name: String,
    // map of quick rule reqction
    pub map_indexed: Map<String, Reaction>,
    // list of the rules that could be searched
    list_indexed: Vec<Rule>,
    // list of rules that
    list_non_indexed: Vec<Rule>,
}

impl std::fmt::Debug for SecurityGroup {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // return list of group keys:
        let mut out = f.debug_struct("SecurityGroup");
        out.field("name", &self.name);
        out.field("map_indexed", &self.map_indexed.len());
        out.field("list_indexed", &self.list_indexed.len());
        out.field("list_non_indexed", &self.list_non_indexed.len());
        out.finish()
    }
}

// contructor implementation
impl SecurityGroup {
    pub fn new(name: &str) -> Self {
        Self {
            name: name.to_string(),
            list_indexed: vec![],
            list_non_indexed: vec![],
            map_indexed: Map::new(),
        }
    }
}

// management implementation
impl SecurityGroup {
    pub fn count(&self) -> usize {
        self.list_indexed.len() + self.list_non_indexed.len()
    }

    pub fn list_indexed(&self) -> impl Iterator<Item = &Rule> {
        self.list_indexed.iter()
    }

    pub fn list_non_indexed(&self) -> impl Iterator<Item = &Rule> {
        self.list_non_indexed.iter()
    }

    pub fn add(&mut self, r: Rule) {
        let keys = r.index_keys();
        if keys.len() > 0 {
            for key in keys {
                self.map_indexed.insert(key, r.reaction.clone());
            }
            self.list_indexed.push(r);
        } else {
            self.list_non_indexed.push(r);
        }
    }

    pub fn remove_by_index(&mut self, index: usize) {
        if index < self.list_indexed.len() {
            self.remove_many(vec![index].into_iter())
        } else {
            let real_index = index - self.list_indexed.len();
            self.list_non_indexed.remove(real_index);
        }
    }

    pub fn remove_many(&mut self, indexes: impl Iterator<Item = usize>) {
        // remove the items from the map

        let mut idx_indexed: Vec<usize> = vec![];
        let mut idx_non_indexed: Vec<usize> = vec![];
        for index in indexes {
            if index < self.list_indexed.len() {
                if let Some(rule) = self.list_indexed.get(index) {
                    for key in rule.index_keys() {
                        self.map_indexed.remove(&key);
                    }
                    idx_indexed.push(index);
                }
            } else {
                idx_non_indexed.push(index - self.list_indexed.len());
            }
        }
        // replace list_indexed with the new list, skipping indexes
        if idx_indexed.len() > 0 {
            let mut new_list_indexed = vec![];
            for (index, rule) in self.list_indexed.iter().enumerate() {
                let mut skip = false;
                for i in &idx_indexed {
                    if *i == index {
                        skip = true;
                        break;
                    }
                }
                if !skip {
                    new_list_indexed.push(rule.clone());
                }
            }
            self.list_indexed = new_list_indexed;
        }
        // replace list_indexed with the new list, skipping indexes
        if idx_non_indexed.len() > 0 {
            let mut new_list_non_indexed = vec![];
            for (index, rule) in self.list_indexed.iter().enumerate() {
                let mut skip = false;
                for i in &idx_non_indexed {
                    if *i == index {
                        skip = true;
                        break;
                    }
                }
                if !skip {
                    new_list_non_indexed.push(rule.clone());
                }
            }
            self.list_non_indexed = new_list_non_indexed;
        }
    }

    pub fn set_by_index(&mut self, index: usize, r: Rule) {
        if index < self.list_indexed.len() {
            self.remove_many(vec![index].into_iter())
        } else {
            let real_index = index - self.list_indexed.len();
            self.list_non_indexed.remove(real_index);
        }
        self.add(r);
    }

    pub fn set_many(&mut self, indexes: impl Iterator<Item = usize>, r: Rule) {
        self.remove_many(indexes);
        self.add(r.clone());
    }
}

impl SecurityGroup {
    // writes security group to the writer, using rule writer, one rule at a line
    pub fn to_writer<W: Write>(&self, w: &mut W) -> anyhow::Result<()> {
        for rule in &self.list_indexed {
            writeln!(w, "{}", rule.to_string())?;
        }
        for rule in &self.list_non_indexed {
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
        let mut out = Self::new(name);
        let lines = BufReader::new(r).lines();
        for next_line in lines {
            if let Ok(line) = next_line {
                let ln = line.trim();
                // skipping empty lines and comments
                if ln.len() > 0 && !ln.starts_with("#") {
                    match Rule::parse(ln) {
                        Ok(rule) => out.add(rule),
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
            tags: vec![],
        }),
    }
    test_rule! {
        asterisk : ("*", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
        }),
    }
    test_rule! {
        deny_all : ("403|*", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(403),
            tags: vec![],
        }),
    }
    test_rule! {
        error_on_country : ("500|US", Rule {
            access: vec![Access::From(Source::FromCountry("US".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(500),
            tags: vec![],
        }),
    }
    test_rule! {
        error_with_tags : ("500|US#blacklist", Rule {
            access: vec![Access::From(Source::FromCountry("US".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(500),
            tags: vec!["blacklist".to_owned()],
        }),
    }

    test_rule! {
        fail_on_country : ("401|-GB", Rule {
            access: vec![Access::Excluding(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(401),
            tags: vec![],
        }),
    }
    test_rule! {
        permanent_redirect : ("301|/api/metrics|/metrics", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Path("/api/metrics".to_owned())],
            reaction: Reaction::PermanentRedirect("/metrics".to_owned()),
            tags: vec![],
        }),
    }
    test_rule! {
        temp_redirect : ("302|/api/metrics|/metrics", Rule {
            access: vec![Access::From(Source::Any)],
            target: vec![Target::Path("/api/metrics".to_owned())],
            reaction: Reaction::TemporaryRedirect("/metrics".to_owned()),
            tags: vec![],
        }),
    }
    test_rule! {
        country : ("GB", Rule {
            access: vec![Access::From(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
        }),
    }
    test_rule! {
        excluding_country : ("-GB", Rule {
            access: vec![Access::Excluding(Source::FromCountry("GB".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
        }),
    }
    test_rule! {
        ipv4network : ("192.168.0.0/8", Rule {
            access: vec![Access::From(Source::FromIpv4Network("192.168.0.0/8".parse().unwrap()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
        }),
    }
    test_rule! {
        ipv4 : ("192.168.0.1", Rule {
            access: vec![Access::From(Source::FromIpv4("192.168.0.1".parse().unwrap()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
        }),
    }

    test_rule! {
        city : ("London", Rule {
            access: vec![Access::From(Source::FromCity("London".to_owned()))],
            target: vec![Target::Any],
            reaction: Reaction::HttpStatus(200),
            tags: vec![],
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
            tags: vec![],
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
        let source = vec!["403|ES", "401|-JP", "301|127.0.0.1,/a/|/b/"].join("\n");

        let mut r = BufReader::new(source.as_bytes());
        let sg = SecurityGroup::from_reader("default", &mut r);
        let mut writer = BufWriter::new(Vec::new());
        sg.to_writer(&mut writer).unwrap();
        let s = String::from_utf8(writer.into_inner().unwrap()).unwrap();

        assert_eq!(s, format!("{}\n", source));
    }

    #[test]
    fn test_security_group_indexes() {
        let source = vec![
            "200|51.138.72.171,20.198.223.70,161.156.174.216,161.156.87.230,20.113.168.212",
            "401|*",
        ]
        .join("\n");
        let mut r = BufReader::new(source.as_bytes());
        let sg = SecurityGroup::from_reader("default", &mut r);
        assert_eq!(sg.list_non_indexed.len(), 1);
        assert_eq!(sg.list_indexed.len(), 1);
        // let rule1 = sg.list_indexed.get(0).unwrap();
        assert_eq!(sg.map_indexed.len(), 5);
    }
}
