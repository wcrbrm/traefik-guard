use std::collections::HashMap as Map;

#[derive(Clone)]
pub struct TagMap {
    pub including: Map<String, u8>,
    pub excluding: Map<String, u8>,
}

impl std::fmt::Debug for TagMap {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let mut out: Vec<String> = Vec::new();
        for (k, _) in &self.including {
            out.push(k.to_string());
        }
        for (k, _) in &self.excluding {
            out.push(format!("-{}", k));
        }
        write!(f, "{}", out.join(","))
    }
}

impl TagMap {
    pub fn new() -> Self {
        Self {
            including: Map::new(),
            excluding: Map::new(),
        }
    }

    pub fn from_query(input: &str) -> Self {
        let mut including = Map::new();
        let mut excluding = Map::new();
        for tag in input.split(',') {
            if tag.starts_with('-') {
                excluding.insert(tag[1..].to_string(), 1);
            } else {
                including.insert(tag.to_string(), 1);
            }
        }
        Self {
            including,
            excluding,
        }
    }

    pub fn matches(&self, tags: &Vec<String>) -> bool {
        if self.including.is_empty() && self.excluding.is_empty() {
            return true;
        }
        for tag in tags {
            if self.excluding.contains_key(tag) {
                return false;
            }
        }
        if self.including.is_empty() {
            return true;
        }
        for tag in tags {
            if self.including.contains_key(tag) {
                return true;
            }
        }
        false
    }
}
