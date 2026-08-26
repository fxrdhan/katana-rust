use lru::LruCache;
use std::collections::HashMap;
use std::num::NonZeroUsize;

#[derive(Debug, Default)]
struct TrieNode {
    children: HashMap<String, TrieNode>,
    is_promoted: bool,
}

#[derive(Debug, Default)]
pub struct HostTrie {
    root: TrieNode,
}

impl HostTrie {
    pub fn insert_and_collapse(&mut self, segments: &[String], threshold: usize) -> Vec<String> {
        let mut current = &mut self.root;
        let mut output = Vec::with_capacity(segments.len());

        for seg in segments {
            if current.is_promoted {
                output.push("{param}".to_string());
                continue;
            }

            if !current.children.contains_key(seg) {
                if current.children.len() >= threshold {
                    current.is_promoted = true;
                    current.children.clear();
                    output.push("{param}".to_string());
                    continue;
                }
                current.children.insert(seg.clone(), TrieNode::default());
            }

            current = current.children.get_mut(seg).unwrap();
            output.push(seg.clone());
        }

        output
    }
}

/// LRU-cached per-host PathTrie.
pub struct PathTrie {
    threshold: usize,
    cache: LruCache<String, HostTrie>,
}

impl PathTrie {
    pub fn new(threshold: usize) -> Self {
        Self {
            threshold,
            cache: LruCache::new(NonZeroUsize::new(10000).unwrap()),
        }
    }

    pub fn insert_and_collapse(&mut self, host: &str, segments: &[String]) -> Vec<String> {
        if !self.cache.contains(host) {
            self.cache.put(host.to_string(), HostTrie::default());
        }

        let host_trie = self.cache.get_mut(host).unwrap();
        host_trie.insert_and_collapse(segments, self.threshold)
    }
}
