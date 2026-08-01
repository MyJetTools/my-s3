//! Just enough XML to talk to S3: pull a single text node out of a response.
//!
//! Everything here is fed by bytes the *server* chose, so nothing may panic on
//! malformed input - a truncated body or a proxy's HTML error page has to come back as
//! `None`, not as an aborted process.

/// Reads the text content of the node at `x_path` (e.g. `"Error/Code"`).
///
/// Returns `None` if the body is not XML, if the node is absent, if the document ends
/// before the closing tag, or if the content is not valid UTF-8.
pub fn read_node_text(body: &[u8], x_path: &str) -> Option<String> {
    let mut reader = my_xml_reader::MyXmlReader::from_slice(body).ok()?;

    let open_node = reader.find_the_open_node(x_path).ok()??;

    // The reader now sits just past `<Node>`; the next tag is the matching `</Node>`,
    // so the text lives between the two. A malformed document can end here instead -
    // `read_next_tag` then gives Err/None rather than the close tag.
    let close_node = reader.read_next_tag().ok()??;

    // `<Node/>` (self-closing) and `<Node></Node>` both leave nothing in between, and
    // a corrupt document can even report the close tag before the open one. Guard the
    // slice rather than trusting the positions.
    let from = open_node.end_pos + 1;
    let to = close_node.start_pos;

    if from > to || to > body.len() {
        return Some(String::new());
    }

    std::str::from_utf8(&body[from..to]).ok().map(unescape)
}

/// Decodes the five predefined XML entities. Numeric
/// character references are left as-is: nothing S3 puts in the nodes we read (error
/// codes, upload ids) uses them, and silently mangling an unrecognised `&...;` would
/// be worse than passing it through.
fn unescape(src: &str) -> String {
    if !src.contains('&') {
        return src.to_string();
    }

    let mut result = String::with_capacity(src.len());
    let mut rest = src;

    while let Some(index) = rest.find('&') {
        result.push_str(&rest[..index]);
        let tail = &rest[index..];

        let matched = [
            ("&amp;", '&'),
            ("&lt;", '<'),
            ("&gt;", '>'),
            ("&quot;", '"'),
            ("&apos;", '\''),
        ]
        .into_iter()
        .find(|(entity, _)| tail.starts_with(entity));

        match matched {
            Some((entity, decoded)) => {
                result.push(decoded);
                rest = &tail[entity.len()..];
            }
            None => {
                result.push('&');
                rest = &tail[1..];
            }
        }
    }

    result.push_str(rest);
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn reads_the_error_code() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code><Message>The specified key does not exist.</Message></Error>"#;

        assert_eq!(
            read_node_text(xml, "Error/Code").as_deref(),
            Some("NoSuchKey")
        );
    }

    #[test]
    fn reads_the_upload_id() {
        let xml = br#"<?xml version="1.0" encoding="UTF-8"?><InitiateMultipartUploadResult><Bucket>b</Bucket><Key>k</Key><UploadId>2~aBc-1_2.3</UploadId></InitiateMultipartUploadResult>"#;

        assert_eq!(
            read_node_text(xml, "InitiateMultipartUploadResult/UploadId").as_deref(),
            Some("2~aBc-1_2.3")
        );
    }

    #[test]
    fn missing_node_is_none_not_a_panic() {
        let xml = br#"<Error><Message>no code here</Message></Error>"#;
        assert_eq!(read_node_text(xml, "Error/Code"), None);
    }

    /// A proxy or a load balancer in front of S3 answers with HTML, not XML. The old
    /// parser reached `read_next_tag().unwrap().unwrap()` on inputs like this.
    #[test]
    fn non_xml_body_is_none_not_a_panic() {
        assert_eq!(read_node_text(b"502 Bad Gateway", "Error/Code"), None);
        assert_eq!(read_node_text(b"", "Error/Code"), None);
        assert_eq!(read_node_text(b"<Error><Code>tru", "Error/Code"), None);
    }

    /// The old code sliced the body with `from_utf8_unchecked`, which is undefined
    /// behaviour on bytes the server controls.
    #[test]
    fn invalid_utf8_is_none_not_undefined_behaviour() {
        let mut xml = b"<Error><Code>".to_vec();
        xml.extend_from_slice(&[0xFF, 0xFE]);
        xml.extend_from_slice(b"</Code></Error>");

        assert_eq!(read_node_text(&xml, "Error/Code"), None);
    }

    #[test]
    fn empty_node_reads_as_empty_string() {
        assert_eq!(
            read_node_text(b"<Error><Code></Code></Error>", "Error/Code").as_deref(),
            Some("")
        );
    }

    #[test]
    fn predefined_entities_are_decoded() {
        assert_eq!(unescape("a&amp;b&lt;c&gt;d&quot;e&apos;f"), "a&b<c>d\"e'f");
        // An entity we do not know stays verbatim rather than being swallowed.
        assert_eq!(unescape("a&#38;b"), "a&#38;b");
        assert_eq!(unescape("plain"), "plain");
        assert_eq!(unescape("trailing&"), "trailing&");
    }
}
