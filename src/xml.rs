//! Just enough XML to talk to S3: pull a single text node out of a response.
//!
//! Everything here is fed by bytes the *server* chose, so nothing may panic on
//! malformed input - a truncated body or a proxy's HTML error page has to come back as
//! `None`, not as an aborted process.

/// Whether `body` is a complete XML document that `MyXmlReader` can be driven over
/// without aborting the process.
///
/// The reader's contract is that a malformed document is an `Err`, and for the most part
/// it is. Two inputs escape that and panic instead, and both are bytes a *server* can
/// choose - a proxy's error page is enough - so neither may be left to chance:
///
/// * **Non-UTF-8 anywhere.** Tag names go through
///   `std::str::from_utf8(..).unwrap()` while the document is being scanned, before any
///   caller gets a chance to inspect what was read.
/// * **A closing tag with nothing open.** `</div>` at the top level takes the reader's
///   nesting depth below zero, and it is a `usize`: `attempt to subtract with overflow`.
///   The reader's own "there are no opened tags" error sits one line further down and is
///   never reached. In release builds the subtraction wraps instead and the error *does*
///   surface - so this is a crash that only shows up in a debug build, which is the worse
///   way round for a library.
///
/// It also rejects a document that never closes what it opened, which is what a body
/// cut short by a dropped connection looks like. That one is not a panic - it is worse.
/// The reader reports running out of input the same way it reports reaching a closing
/// tag, so a listing truncated between two `<Contents>` blocks reads as a page that
/// simply ended: fewer objects than the bucket holds, returned as a success. Refusing
/// the body up front is the only place that difference is still visible.
///
/// The scan below classifies tags the same way the reader does - a tag runs from `<` to
/// the next `>`, a leading `/` closes, a trailing `/` is self-closing - so a document
/// this accepts is one the reader tokenises identically. A declaration or doctype
/// (`<?xml ... ?>`, `<!DOCTYPE ...>`) counts as neither, which is how the reader treats
/// the header it skips.
fn is_safe_to_read(body: &[u8]) -> bool {
    if std::str::from_utf8(body).is_err() {
        return false;
    }

    let mut depth: usize = 0;
    let mut pos = 0;

    while let Some(start) = body[pos..].iter().position(|byte| *byte == b'<') {
        let start = pos + start;

        let Some(end) = body[start..].iter().position(|byte| *byte == b'>') else {
            // A tag that never ends is a body that was cut in the middle of one.
            return false;
        };
        let end = start + end;

        let tag = &body[start..=end];
        pos = end + 1;

        // `<?xml ...?>`, `<!DOCTYPE ...>`, `<!-- ... -->`: not nesting.
        if matches!(tag.get(1), Some(b'?') | Some(b'!')) {
            continue;
        }

        if tag.get(1) == Some(&b'/') {
            if depth == 0 {
                return false;
            }
            depth -= 1;
            continue;
        }

        // `<Node/>` opens and closes in one tag. `tag` is at least `<>`, so the index is
        // in range.
        if tag[tag.len() - 2] != b'/' {
            depth += 1;
        }
    }

    // Everything that was opened was closed again.
    depth == 0
}

/// Reads the text content of the node at `x_path` (e.g. `"Error/Code"`).
///
/// Returns `None` if the body is not XML, if the node is absent, if the document ends
/// before the closing tag, or if the content is not valid UTF-8.
pub fn read_node_text(body: &[u8], x_path: &str) -> Option<String> {
    if !is_safe_to_read(body) {
        return None;
    }

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

/// Walks the repeated child elements of one XML document, in document order.
///
/// [`read_node_text`] answers "what is inside this one node", which is all a
/// `GetBucketLocation` or an `<Error>` ever needs. A `ListObjectsV2` answer is the other
/// shape: `<Contents>` and `<CommonPrefixes>` repeat an unbounded number of times, and
/// the scalars that describe the page (`<IsTruncated>`, `<NextContinuationToken>`) sit
/// among them in an order that is the *storage's* choice - AWS, Ceph and MinIO all pick
/// a different one. Walking whatever comes next, rather than looking each element up by
/// name, is what makes the order stop mattering.
///
/// Nothing here may panic: every byte it reads was chosen by the server.
pub struct XmlWalker<'t> {
    reader: my_xml_reader::MyXmlReader<'t>,
    root: my_xml_reader::XmlTagInfo<'t>,
}

impl<'t> XmlWalker<'t> {
    /// Opens `body` and positions the walker just inside `<root_name>`.
    ///
    /// `Ok(None)` means the document was readable but holds no such root - an `<Error>`
    /// body, or a proxy's XML-ish page. `Err` means it could not be read as XML at all.
    /// Callers normally report both the same way, because both mean "this is not the
    /// answer we asked for".
    pub fn open(body: &'t [u8], root_name: &str) -> Result<Option<Self>, String> {
        if !is_safe_to_read(body) {
            return Err("body is not XML this reader can be driven over safely".to_string());
        }

        let mut reader = my_xml_reader::MyXmlReader::from_slice(body)?;

        let Some(root) = reader.find_the_open_node(root_name)? else {
            return Ok(None);
        };

        Ok(Some(Self { reader, root }))
    }

    /// The next direct child of the root named in `names`, or `None` once the root's
    /// closing tag is reached.
    ///
    /// Elements not in `names` are skipped however deeply they nest, so an `<Owner>`
    /// subtree or a `<StorageClass>` this crate does not model costs nothing.
    pub fn next_child(
        &mut self,
        names: &[&str],
    ) -> Result<Option<my_xml_reader::XmlTagInfo<'t>>, String> {
        // A self-closing root (`<ListBucketResult/>`) has no children *and* no closing
        // tag to stop at, so scanning on would run into whatever trails the document -
        // a newline is enough to make the reader report "can not find the next open
        // tag". An empty document is an empty page, not an error.
        if is_self_closing(&self.root) {
            return Ok(None);
        }

        next_direct_child(&mut self.reader, &self.root, names)
    }

    /// [`Self::next_child`] one level down: the next child of `parent`, which must be a
    /// node this walker just handed out and whose content has not been consumed yet.
    pub fn next_child_of(
        &mut self,
        parent: &my_xml_reader::XmlTagInfo<'t>,
        names: &[&str],
    ) -> Result<Option<my_xml_reader::XmlTagInfo<'t>>, String> {
        if is_self_closing(parent) {
            return Ok(None);
        }

        next_direct_child(&mut self.reader, parent, names)
    }

    /// Consumes `node` and returns its text, XML-unescaped.
    ///
    /// `node` must be one this walker handed out. A self-closing element reads as an
    /// empty string: `<NextContinuationToken/>` is a token that is not there, which is
    /// the same statement as an empty one.
    pub fn read_text(&mut self, node: my_xml_reader::XmlTagInfo<'t>) -> Result<String, String> {
        let node = self.reader.read_the_whole_node(node)?;

        let Some(content) = node.get_inner_content() else {
            return Ok(String::new());
        };

        // `MyXmlNode::get_value` would do this, and it is the wrong thing to lean on:
        // it decodes the five entities with one `String::replace` per entity, in
        // `HashMap` iteration order, so `&amp;lt;` comes back as `<` or as `&lt;`
        // depending on where the hasher happened to put the keys. The single
        // left-to-right pass in `unescape` has no such ambiguity.
        let text = std::str::from_utf8(content)
            .map_err(|_| format!("<{}> holds bytes that are not UTF-8", node.get_node_name()))?;

        Ok(unescape(text))
    }
}

/// `find_any_of_these_nodes_inside_parent` matches on the **name alone**, at any depth,
/// so an element with a wanted name buried inside a subtree we meant to skip comes back
/// as though it were a child. In a `<Contents>` that is not hypothetical: `<Owner>` sits
/// between the fields, and an implementation that ever puts a `<Key>` or an `<ETag>` in
/// one would have it read as the object's own.
///
/// Filtering on the depth is what makes "child" mean child. A node that is too deep is
/// passed over rather than returned - the scan has already moved past its opening tag,
/// and its closing tag pops on the way to the next candidate.
fn next_direct_child<'t>(
    reader: &mut my_xml_reader::MyXmlReader<'t>,
    parent: &my_xml_reader::XmlTagInfo<'t>,
    names: &[&str],
) -> Result<Option<my_xml_reader::XmlTagInfo<'t>>, String> {
    loop {
        let Some(found) = reader.find_any_of_these_nodes_inside_parent(parent, names)? else {
            return Ok(None);
        };

        if found.level == parent.level + 1 {
            return Ok(Some(found));
        }
    }
}

/// Whether the tag closed itself (`<Prefix/>`) rather than opening a body.
///
/// Read off the raw tag rather than off `XmlTagInfo::tag_type`, so that this file does
/// not have to name `my_xml_reader::my_xml_reader::XmlTagType` - the enum is re-exported
/// from the inner module, not from the crate root.
fn is_self_closing(node: &my_xml_reader::XmlTagInfo<'_>) -> bool {
    node.raw.ends_with(b"/>")
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

    /// A closing tag with nothing open takes `MyXmlReader`'s depth counter - a `usize` -
    /// below zero. The reader's own "there are no opened tags" error is written one line
    /// below the subtraction and never runs, so this aborts a debug build. These are all
    /// bytes a proxy in front of the storage can put in front of us.
    #[test]
    fn a_stray_closing_tag_is_none_not_an_abort() {
        for body in [
            b"</a>".as_slice(),
            b"</div>not xml".as_slice(),
            b"<R></R></R>".as_slice(),
            b"</Error><Error><Code>NoSuchKey</Code></Error>".as_slice(),
        ] {
            assert_eq!(
                read_node_text(body, "Error/Code"),
                None,
                "{:?} must not abort the process",
                String::from_utf8_lossy(body)
            );
        }
    }

    /// The guard exists to stop panics, not to become a validator: it must still let
    /// through every document this crate actually reads.
    #[test]
    fn well_formed_documents_are_still_readable() {
        assert!(is_safe_to_read(
            br#"<?xml version="1.0" encoding="UTF-8"?><Error><Code>NoSuchKey</Code></Error>"#
        ));
        assert!(is_safe_to_read(b"<LocationConstraint/>"));
        assert!(is_safe_to_read(b"<A><B/><C>x</C></A>"));
        assert!(is_safe_to_read(b""));
        assert!(is_safe_to_read(b"not xml at all"));
        assert!(!is_safe_to_read(b"</A>"));
        assert!(!is_safe_to_read(&[b'<', b'A', b'>', 0xFF, b'<', b'/', b'A', b'>']));
    }

    /// A body the connection cut short is the dangerous kind of malformed: the reader
    /// reports running out of input exactly the way it reports reaching a closing tag,
    /// so the half of the document that did arrive would be handed back as a whole one.
    #[test]
    fn a_document_that_was_cut_short_is_refused() {
        assert!(!is_safe_to_read(b"<A><B>text</B>"), "root never closed");
        assert!(!is_safe_to_read(b"<A><B"), "cut inside a tag");
        assert!(!is_safe_to_read(b"<A><B>te"), "cut inside the text");

        // And the complete version of the same document is fine.
        assert!(is_safe_to_read(b"<A><B>text</B></A>"));
        assert!(is_safe_to_read(b"<A><B>text</B></A>\n"));
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
