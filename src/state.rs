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
pub enum RuleRef {
    Index(usize),
    Tag(TagMap),
}

// service structure as a state with map of security groups
#[derive(Debug, Clone)]
pub struct SecurityGroupService {
    pub storage_path: String,
    pub groups: Map<String, SecurityGroup>,
}

// implementation of the service
impl SecurityGroupService {
    // create a new service with single group with no rules
    pub fn _new(path: &str) -> Self {
        let mut groups = Map::new();
        groups.insert(
            "default".to_string(),
            SecurityGroup {
                name: "default".to_string(),
                list: Vec::new(),
            },
        );
        Self {
            groups,
            storage_path: path.to_string(),
        }
    }

    // function to load all security groups from the given path, each group is stored in a separate file
    #[instrument]
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
            let file_name = format!("{}/{}.rules.txt", self.storage_path, name);
            match group.save_to_file(&file_name) {
                Ok(_) => {} // info!("Saved group {} to {}", name, file_name),
                Err(e) => warn!("Failed to save group {} to {}: {}", name, file_name, e),
            }
        }
    }

    // function to reset rules for a given group
    #[instrument(skip(self))]
    pub fn reset_rules(&mut self, group_name: &str) -> anyhow::Result<()> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("group {} not found", group_name))?;
        group.list = Vec::new();
        self.save();
        Ok(())
    }

    // function to create rule for a given group, returns index of the rule
    #[instrument(skip(self))]
    pub fn create_rule(&mut self, group_name: &str, rule: &str) -> anyhow::Result<usize> {
        // get or create group
        let group = self
            .groups
            .entry(group_name.to_string())
            .or_insert_with(|| SecurityGroup {
                name: group_name.to_string(),
                list: Vec::new(),
            });
        for r in rule.lines() {
            if r.len() > 0 {
                group.list.push(Rule::parse(r)?);
            }
        }
        let index = group.list.len() - 1;
        self.save();
        Ok(index)
    }

    // function to list all rules for a given group
    #[instrument(skip(self))]
    pub fn list_rules(&self, group_name: &str, tags: &TagMap) -> anyhow::Result<Vec<String>> {
        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| anyhow::anyhow!("group {} not found", group_name))?;

        Ok(group
            .list
            .iter()
            .map(|r| Some(r.to_string()))
            .flatten()
            .collect())
    }

    // function to update rule by its index for a given group
    #[instrument(skip(self))]
    pub fn update_rule(
        &mut self,
        group_name: &str,
        rule_ref: &RuleRef,
        input: &str,
    ) -> anyhow::Result<()> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("group {} not found", group_name))?;
        match rule_ref {
            RuleRef::Index(index) => {
                if *index >= group.list.len() {
                    bail!("index {} out of range", index);
                }
                group.list[*index] = Rule::parse(input)?;
            }
            RuleRef::Tag(tag) => {
                let mut found = false;
                for rule in &mut group.list {
                    if tag.matches(&rule.tags) {
                        *rule = Rule::parse(input)?;
                        found = true;
                    }
                }
                if !found {
                    bail!("rule with tag {:?} not found", tag);
                }
            }
        }
        self.save();
        Ok(())
    }

    // function to delete rule by its index for a given group
    #[instrument(skip(self))]
    pub fn delete_rule(&mut self, group_name: &str, rule_ref: &RuleRef) -> anyhow::Result<()> {
        let group = self
            .groups
            .get_mut(group_name)
            .ok_or_else(|| anyhow!("group {} not found", group_name))?;

        match rule_ref {
            RuleRef::Index(index) => {
                if *index >= group.list.len() {
                    bail!("index {} out of range", index);
                }
                group.list.remove(*index);
            }
            RuleRef::Tag(tag) => {
                let mut list = vec![];
                for rule in &group.list {
                    if !tag.matches(&rule.tags) {
                        list.push(rule.clone());
                    }
                }
                group.list = list;
            }
        };
        self.save();
        Ok(())
    }

    // function to react on visitor by checking all rules for a given group
    #[instrument(skip(self, visitor))]
    pub fn react<V: Visitor>(&self, group_name: &str, visitor: &V) -> anyhow::Result<Reaction> {
        let group = self
            .groups
            .get(group_name)
            .ok_or_else(|| anyhow!("group {} not found", group_name))?;
        for rule in &group.list {
            if let Some(reaction) = rule.react(visitor) {
                return Ok(reaction.clone());
            }
        }
        Ok(Reaction::HttpStatus(200))
    }
}
