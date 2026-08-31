use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;
use std::sync::Mutex;

pub const DEFAULT_PROMOTION_THRESHOLD: usize = 10;
pub const DEFAULT_MAX_HOSTS: usize = 10000;

#[derive(Debug, Default)]
struct TrieNode {
    children: Option<HashMap<String, TrieNode>>,
    param_child: Option<Box<TrieNode>>,
    promoted: bool,
}

impl TrieNode {
    fn new() -> Self {
        Self {
            children: Some(HashMap::new()),
            param_child: None,
            promoted: false,
        }
    }
}

/// Adaptive PathTrie for tracking segment cardinality per host and collapsing promoted paths.
pub struct PathTrie {
    roots: Mutex<LruCache<String, TrieNode>>,
    threshold: usize,
}

impl PathTrie {
    pub fn new(threshold: usize) -> Self {
        let t = if threshold == 0 {
            DEFAULT_PROMOTION_THRESHOLD
        } else {
            threshold
        };
        Self {
            roots: Mutex::new(LruCache::new(NonZeroUsize::new(DEFAULT_MAX_HOSTS).unwrap())),
            threshold: t,
        }
    }

    /// Walk the trie for host and segments, returning transformed segments with "{param}" at promoted positions.
    pub fn fingerprint(&self, host: &str, segments: &[String]) -> Vec<String> {
        let mut roots = self.roots.lock().unwrap();
        if !roots.contains(host) {
            roots.put(host.to_string(), TrieNode::new());
        }
        let root = roots.get_mut(host).unwrap();

        let mut result = Vec::with_capacity(segments.len());
        let mut current = root;

        for seg in segments {
            if current.promoted {
                result.push("{param}".to_string());
                if current.param_child.is_none() {
                    current.param_child = Some(Box::new(TrieNode::new()));
                }
                current = current.param_child.as_mut().unwrap();
                continue;
            }

            if let Some(children) = &mut current.children {
                if !children.contains_key(seg) {
                    children.insert(seg.clone(), TrieNode::new());

                    if children.len() > self.threshold {
                        current.promoted = true;
                        current.param_child = Some(Box::new(TrieNode::new()));
                        current.children = None;
                        result.push("{param}".to_string());
                        current = current.param_child.as_mut().unwrap();
                        continue;
                    }
                }

                result.push(seg.clone());
                current = current.children.as_mut().unwrap().get_mut(seg).unwrap();
            } else {
                result.push("{param}".to_string());
                if current.param_child.is_none() {
                    current.param_child = Some(Box::new(TrieNode::new()));
                }
                current = current.param_child.as_mut().unwrap();
            }
        }

        result
    }
}
