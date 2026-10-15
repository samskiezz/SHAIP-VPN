//! Query-name minimization (RFC 7816): resolve from the parent zone down.

pub fn minimized_queries(qname: &str) -> Vec<String> {
    let mut parts: Vec<&str> = qname.trim_end_matches('.').split('.').collect();
    if parts.len() < 2 {
        return vec![qname.to_string()];
    }
    let mut out = Vec::new();
    while parts.len() >= 2 {
        out.push(parts.join("."));
        parts.remove(0);
    }
    out.reverse();
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn minimizes() {
        assert_eq!(
            minimized_queries("www.example.com"),
            vec!["example.com", "www.example.com"]
        );
    }

    #[test]
    fn single_label_passthrough() {
        assert_eq!(minimized_queries("localhost"), vec!["localhost"]);
    }
}
