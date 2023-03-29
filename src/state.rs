use super::proto::*;
use super::tags::TagMap;
use anyhow::{anyhow, bail, Context};
use std::collections::BTreeMap as Map;
use std::fs;
use tracing::*;

/*
service
 - creates rule for the given group
 - lists rules (as JSON)
 - updates rule for the given group
 - gets rule for the given group by reference
 - deletes rule for the given group
 - reacts on visitor
*/

#[derive(Debug, Clone)]
pub enum RulesRef {
    All,
    Index(usize),
    Tag(TagMap),
}

// service structure as a state with map of security groups
#[derive(Clone)]
pub struct SecurityGroupService {
    pub storage_path: String,
    pub groups: Map<String, SecurityGroup>,
}

impl std::fmt::Debug for SecurityGroupService {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // return list of group keys:
        let mut out = f.debug_struct("SecurityGroupService");
        for (k, v) in &self.groups {
            out.field(k, v);
        }
        out.finish()
    }
}

// implementation of the service
impl SecurityGroupService {
    // function to load all security groups from the given path, each group is stored in a separate file
    #[instrument(ret)]
    pub fn from_local_path(path: &str) -> anyhow::Result<Self> {
        let mut groups = Map::new();
        // for each file in the given path, add a new group from it
        let paths = fs::read_dir(path).context("read dir")?;
        for path in paths {
            let path = path.context("read path")?;
            let full_file_name = format!("{}", path.path().display());

            let basename = path
                .file_name()
                .into_string()
                .unwrap()
                .replace(".rules.txt", "");

            match SecurityGroup::from_file(&basename, &full_file_name) {
                Ok(group) => {
                    // info!("Loaded group {}, {} rules", basename, group.list.len());
                    groups.insert(basename, group);
                }
                Err(e) => {
                    warn!("Failed to load group {}: {}", full_file_name, e);
                }
            };
        }
        Ok(Self {
            groups,
            storage_path: path.to_string(),
        })
    }

    // function to save each security group to a separate file
    #[instrument(skip(self))]
    pub fn save(&self) {
        if self.storage_path == "" {
            return;
        }
        for (name, group) in &self.groups {
            let file_name = format!(
                "{}/{}.rules.txt",
                self.storage_path.trim_end_matches('/'),
                name
            );
            match group.save_to_file(&file_name) {
                Ok(_) => {} // info!("Saved group {} to {}", name, file_name),
                Err(e) => warn!("Failed to save group {} to {}: {}", name, file_name, e),
            }
        }
    }

    // function to create rule for a given group, returns index of the rule
    #[instrument(skip(self, rule), fields(result))]
    pub fn create_rule(&mut self, group_name: &str, rule: &str) -> anyhow::Result<usize> {
        // get or create group
        let group = self
            .groups
            .entry(group_name.to_string())
            .or_insert_with(|| SecurityGroup::new(group_name));
        for r in rule.lines() {
            if r.trim().len() > 0 {
                group.add(Rule::parse(r.trim())?);
            }
        }
        let index = group.count() - 1;
        self.save();
        Ok(index)
    }

    // function to list all rules for a given group
    #[instrument(skip(self))]
    pub fn list_rules_as_str(&self, group_name: &str, tags: &TagMap) -> anyhow::Result<String> {
        let group = match self.groups.get(group_name) {
            Some(x) => x,
            None => return Ok("".to_string()), // no rules if there is no group
        };

        let mut out = "".to_string();
        group
            .list_indexed()
            .filter(|r| tags.matches(&r.tags))
            .for_each(|r| {
                out.push_str(&r.to_string());
                out.push_str("\n");
            });
        group
            .list_non_indexed()
            .filter(|r| tags.matches(&r.tags))
            .for_each(|r| {
                out.push_str(&r.to_string());
                out.push_str("\n");
            });

        Ok(out)
    }

    // function to update rule by its index for a given group
    #[instrument(skip(self))]
    pub fn update_rule(
        &mut self,
        group_name: &str,
        rule_ref: &RulesRef,
        input: &str,
    ) -> anyhow::Result<()> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("group {} not found", group_name))?;
        match rule_ref {
            RulesRef::All => {
                bail!("please use index or tag to update rule");
            }
            RulesRef::Index(index) => {
                if *index >= group.count() {
                    bail!("index {} out of range", index);
                }
                group.set_by_index(*index, Rule::parse(input)?);
            }
            RulesRef::Tag(tag) => {
                let mut indexes = vec![];
                for (index, r) in group.list_indexed().enumerate() {
                    if tag.matches(&r.tags) {
                        indexes.push(index);
                    }
                }
                for (index, r) in group.list_non_indexed().enumerate() {
                    if tag.matches(&r.tags) {
                        indexes.push(index + group.list_indexed().count());
                    }
                }
                if indexes.len() > 0 {
                    group.set_many(indexes.into_iter(), Rule::parse(input)?);
                }
            }
        }
        self.save();
        Ok(())
    }

    // function to delete rule by its index for a given group
    #[instrument(skip(self))]
    pub fn delete_rule(&mut self, group_name: &str, rule_ref: &RulesRef) -> anyhow::Result<()> {
        let group = match self.groups.get_mut(group_name) {
            Some(x) => x,
            None => {
                warn!("group is not set yet, nothing to delete");
                return Ok(());
            }
        };
        match rule_ref {
            RulesRef::All => {
                group.reset();
            }
            RulesRef::Index(index) => {
                if *index >= group.count() {
                    bail!("index {} out of range", index);
                }
                group.remove_by_index(*index);
            }
            RulesRef::Tag(tag) => {
                let mut indexes = vec![];
                for (index, r) in group.list_indexed().enumerate() {
                    if tag.matches(&r.tags) {
                        indexes.push(index);
                    }
                }
                for (index, r) in group.list_non_indexed().enumerate() {
                    if tag.matches(&r.tags) {
                        indexes.push(index + group.list_indexed().count());
                    }
                }
                if indexes.len() > 0 {
                    group.remove_many(indexes.into_iter());
                }
            }
        };
        self.save();
        Ok(())
    }

    // function to react on visitor by checking all rules for a given group
    #[instrument(skip(self), ret, level = "debug")]
    pub fn react<V: Visitor + std::fmt::Debug>(
        &self,
        group_name: &str,
        visitor: &V,
    ) -> anyhow::Result<Reaction> {
        let group = match self.groups.get(group_name) {
            Some(x) => x,
            None => return Ok(Reaction::HttpStatus(200)), // no rules if there is no group
        };
        let indexes = visitor_index_keys(visitor);
        for index in indexes {
            if let Some(reaction) = group.map_indexed.get(&index) {
                return Ok(reaction.clone());
            }
        }
        for rule in group.list_non_indexed() {
            if let Some(reaction) = rule.react(visitor) {
                return Ok(reaction.clone());
            }
        }
        // fallback to no reaction
        Ok(Reaction::HttpStatus(200))
    }
}

fn visitor_index_keys(visitor: &impl Visitor) -> Vec<String> {
    let uri = visitor.uri();
    let mut keys = vec![visitor.ip().to_string()];
    if let Some(country) = visitor.country() {
        keys.push(country.to_string());
    }
    if let Some(last_char) = uri.chars().last() {
        if last_char != '/' {
            keys.push(format!("{}/", uri));
        }
    }
    keys.push(uri);
    keys
}
