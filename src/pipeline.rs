use std::cmp::Ordering;
use std::collections::{BTreeSet, BinaryHeap};

#[derive(Debug, Clone, Eq, PartialEq)]
struct Event {
    priority: u16,
    name: String,
}

impl Ord for Event {
    fn cmp(&self, other: &Self) -> Ordering {
        self.priority
            .cmp(&other.priority)
            .then_with(|| other.name.cmp(&self.name))
    }
}

impl PartialOrd for Event {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

#[derive(Debug)]
pub struct DiscoveryPipeline {
    queue: BinaryHeap<Event>,
    seen: BTreeSet<String>,
    processed: BTreeSet<String>,
    budget: usize,
    pub enqueued: usize,
    pub duplicates: usize,
    pub budget_exhausted: bool,
}

impl DiscoveryPipeline {
    pub fn new(budget: usize) -> Self {
        Self {
            queue: BinaryHeap::new(),
            seen: BTreeSet::new(),
            processed: BTreeSet::new(),
            budget: budget.max(1),
            enqueued: 0,
            duplicates: 0,
            budget_exhausted: false,
        }
    }

    pub fn mark_processed(&mut self, names: impl IntoIterator<Item = String>) {
        for name in names {
            self.seen.insert(name.clone());
            self.processed.insert(name);
        }
    }

    pub fn enqueue(&mut self, name: String, priority: u16) -> bool {
        if self.seen.contains(&name) {
            self.duplicates += 1;
            return false;
        }
        if self.enqueued >= self.budget {
            self.budget_exhausted = true;
            return false;
        }
        self.seen.insert(name.clone());
        self.queue.push(Event { priority, name });
        self.enqueued += 1;
        true
    }

    pub fn drain(&mut self, limit: usize) -> Vec<String> {
        let mut names = Vec::new();
        while names.len() < limit {
            let Some(event) = self.queue.pop() else {
                break;
            };
            if self.processed.insert(event.name.clone()) {
                names.push(event.name);
            }
        }
        names
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_prioritizes_deduplicates_and_honors_budget() {
        let mut pipeline = DiscoveryPipeline::new(2);
        assert!(pipeline.enqueue("low.example.com".to_owned(), 10));
        assert!(pipeline.enqueue("high.example.com".to_owned(), 100));
        assert!(!pipeline.enqueue("low.example.com".to_owned(), 50));
        assert!(!pipeline.enqueue("third.example.com".to_owned(), 20));
        assert_eq!(pipeline.drain(1), vec!["high.example.com"]);
        assert_eq!(pipeline.duplicates, 1);
        assert!(pipeline.budget_exhausted);
    }
}
