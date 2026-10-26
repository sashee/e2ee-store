//! Where a blob's copies belong (SPEC §7.4), as pure rules: the places it goes, the steps that bring its copies in
//! line with them, and the order reads try copies in. Nothing here does I/O.

/// A place a blob can have a copy in: the database, or the backend of that name.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub enum Location {
    Local,
    Backend(String),
}

/// The database's name in `blob_target` and in the logs.
pub const LOCAL: &str = "local";

impl Location {
    /// "local", or a backend's name.
    pub fn named(name: &str) -> Self {
        if name == LOCAL {
            Self::Local
        } else {
            Self::Backend(name.to_owned())
        }
    }

    pub fn as_str(&self) -> &str {
        match self {
            Self::Local => LOCAL,
            Self::Backend(name) => name,
        }
    }
}

/// One step towards where a blob belongs.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Make a copy there.
    Copy(Location),
    /// Drop the copy there.
    Drop(Location),
}

/// Where a blob belongs: an offloadable one in each of the targets, any other in the database alone.
pub fn belongs(offloadable: bool, targets: &[Location]) -> Vec<Location> {
    if offloadable {
        targets.to_vec()
    } else {
        vec![Location::Local]
    }
}

/// The steps that bring a blob with `copies` to where it belongs: the missing copies first, and only once there are
/// none, dropping the ones anywhere else. So a blob never has fewer copies on the way. Nothing for a blob with no copy
/// at all: there is nothing to copy from.
pub fn plan(offloadable: bool, copies: &[Location], targets: &[Location]) -> Vec<Step> {
    if copies.is_empty() {
        return Vec::new();
    }
    let wanted = belongs(offloadable, targets);
    let missing: Vec<Step> = wanted
        .iter()
        .filter(|place| !copies.contains(place))
        .cloned()
        .map(Step::Copy)
        .collect();
    if !missing.is_empty() {
        return missing;
    }
    copies
        .iter()
        .filter(|place| !wanted.contains(place))
        .cloned()
        .map(Step::Drop)
        .collect()
}

/// Whether the copy in `place` may go now: the blob has a copy in every place it belongs, and this isn't one of them.
pub fn droppable(
    offloadable: bool,
    copies: &[Location],
    targets: &[Location],
    place: &Location,
) -> bool {
    plan(offloadable, copies, targets).contains(&Step::Drop(place.clone()))
}

/// The backends with a copy, in the order reads and copies try them: those among the targets in the targets' order,
/// then any others by name. The database's copy, when there is one, comes before all of them.
pub fn read_order(copies: &[Location], targets: &[Location]) -> Vec<String> {
    let mut backends: Vec<&String> = copies
        .iter()
        .filter_map(|place| match place {
            Location::Backend(name) => Some(name),
            Location::Local => None,
        })
        .collect();
    let rank = |name: &String| {
        targets
            .iter()
            .position(|target| target.as_str() == name && *target != Location::Local)
            .unwrap_or(targets.len())
    };
    backends.sort_by_key(|name| (rank(name), *name));
    backends.into_iter().cloned().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn places(names: &[&str]) -> Vec<Location> {
        names.iter().map(|name| Location::named(name)).collect()
    }

    fn copy_to(name: &str) -> Step {
        Step::Copy(Location::named(name))
    }

    fn drop_at(name: &str) -> Step {
        Step::Drop(Location::named(name))
    }

    #[test]
    fn an_offloadable_blob_gets_a_copy_in_every_target() {
        let targets = places(&["local", "aws", "b2"]);
        assert_eq!(
            plan(true, &places(&["local"]), &targets),
            [copy_to("aws"), copy_to("b2")]
        );
        assert_eq!(
            plan(true, &places(&["b2"]), &targets),
            [copy_to("local"), copy_to("aws")]
        );
        assert_eq!(plan(true, &places(&["local", "aws", "b2"]), &targets), []);
    }

    #[test]
    fn copies_go_only_once_every_target_has_one() {
        let targets = places(&["b2"]);
        assert_eq!(
            plan(true, &places(&["local", "aws"]), &targets),
            [copy_to("b2")],
            "nothing is dropped while b2 lacks a copy"
        );
        assert_eq!(
            plan(true, &places(&["local", "aws", "b2"]), &targets),
            [drop_at("local"), drop_at("aws")]
        );
        assert!(!droppable(
            true,
            &places(&["local", "aws"]),
            &targets,
            &Location::Local
        ));
        assert!(droppable(
            true,
            &places(&["local", "aws", "b2"]),
            &targets,
            &Location::Local
        ));
        assert!(
            !droppable(
                true,
                &places(&["local", "b2"]),
                &targets,
                &Location::named("b2")
            ),
            "a target's copy stays"
        );
    }

    #[test]
    fn any_other_blob_belongs_in_the_database_alone() {
        let targets = places(&["aws"]);
        assert_eq!(plan(false, &places(&["local"]), &targets), []);
        assert_eq!(
            plan(false, &places(&["local", "aws"]), &targets),
            [drop_at("aws")]
        );
        assert_eq!(
            plan(false, &places(&["aws"]), &targets),
            [copy_to("local")],
            "brought home before its backend copy goes"
        );
    }

    #[test]
    fn a_blob_with_no_copy_left_has_nothing_to_copy_from() {
        assert_eq!(plan(true, &[], &places(&["aws"])), []);
        assert_eq!(plan(false, &[], &places(&["local"])), []);
    }

    #[test]
    fn reads_try_the_targets_in_order_then_the_rest() {
        let targets = places(&["local", "zeta", "aws"]);
        assert_eq!(
            read_order(&places(&["local", "aws", "b2", "zeta", "old"]), &targets),
            ["zeta", "aws", "b2", "old"]
        );
        assert_eq!(
            read_order(&places(&["local"]), &targets),
            Vec::<String>::new()
        );
        assert_eq!(
            read_order(&places(&["b2", "a1"]), &places(&["local"])),
            ["a1", "b2"]
        );
    }

    #[test]
    fn locations_are_named_as_blob_target_names_them() {
        assert_eq!(Location::named("local"), Location::Local);
        assert_eq!(Location::named("aws"), Location::Backend("aws".into()));
        assert_eq!(Location::Backend("aws".into()).as_str(), "aws");
        assert!(
            Location::Local < Location::Backend("a".into()),
            "the database first"
        );
    }
}
