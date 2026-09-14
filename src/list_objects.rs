//! `ListObjectsV2` - one page of a bucket's contents.

use crate::S3Error;

/// What to list, and where to resume from.
///
/// Everything is optional, so `S3ListObjectsRequest::default()` lists the first page of
/// the whole bucket. A parameter left as `None` is **not sent**: S3 distinguishes "not
/// asked for" from "asked for, and empty" by the absence of the query parameter, and a
/// `delimiter=` with no value is not the same request as no delimiter at all.
///
/// ```no_run
/// # async fn doc(s3: &my_s3::S3Client) -> Result<(), my_s3::S3Error> {
/// // One "folder" level: the immediate children of `photos/`.
/// let page = s3
///     .list_objects_v2(
///         "my-bucket",
///         my_s3::S3ListObjectsRequest {
///             prefix: Some("photos/"),
///             delimiter: Some("/"),
///             ..Default::default()
///         },
///     )
///     .await?;
///
/// for folder in &page.common_prefixes {
///     println!("dir  {}", folder);
/// }
/// for object in &page.objects {
///     println!("file {} ({} bytes)", object.key, object.size);
/// }
/// # Ok(())
/// # }
/// ```
#[derive(Debug, Clone, Default)]
pub struct S3ListObjectsRequest<'s> {
    /// Only keys starting with this. To walk a tree one level at a time, pass the
    /// `common_prefix` the previous page handed back - it already ends with the
    /// delimiter.
    pub prefix: Option<&'s str>,
    /// Collapses everything after the next occurrence of this string into a single
    /// entry in [`S3ListObjectsPage::common_prefixes`]. `"/"` is what turns a flat key
    /// space into folders.
    pub delimiter: Option<&'s str>,
    /// [`S3ListObjectsPage::next_continuation_token`] from the previous page. The
    /// `prefix` and `delimiter` must be repeated unchanged alongside it.
    pub continuation_token: Option<&'s str>,
    /// At most this many entries in the page. S3 caps it at 1000 and answers with
    /// fewer than asked whenever it likes, so this bounds a page - it never promises
    /// one.
    pub max_keys: Option<u32>,
}

/// One object in a listing.
#[derive(Debug, Clone)]
pub struct S3ObjectInfo {
    /// The full key, not the part after the prefix, and already XML-unescaped - a key
    /// containing `&` arrives as `&amp;` on the wire.
    pub key: String,
    pub size: u64,
    /// Exactly as the storage stated it: ISO-8601, normally
    /// `2024-07-01T12:34:56.000Z`. Left as a string on purpose - this crate has no date
    /// type in its public API, and parsing here would force one on every caller.
    pub last_modified: String,
    /// The entity tag **as sent**, quotes included
    /// (`"d41d8cd98f00b204e9800998ecf8427e"`): that is what the header form is, and what
    /// an `If-Match` has to carry back. `None` when the storage did not send one.
    pub etag: Option<String>,
}

/// One page of a listing. A page is not the whole bucket: check
/// [`Self::next_continuation_token`].
#[derive(Debug, Clone)]
pub struct S3ListObjectsPage {
    /// The "folders", when a `delimiter` was given. Each one is a **full** prefix -
    /// `photos/2024/`, not `2024/` - and ends with the delimiter, so it can be passed
    /// straight back as the next request's `prefix`.
    pub common_prefixes: Vec<String>,
    /// The objects at this level. With a `delimiter`, these are only the keys that have
    /// no further delimiter after the prefix.
    pub objects: Vec<S3ObjectInfo>,
    /// `Some` only when the storage said the listing was truncated. Pass it back as
    /// `continuation_token` - with the same `prefix` and `delimiter` - to get the next
    /// page; `None` means this was the last one.
    pub next_continuation_token: Option<String>,
}

/// Root children worth stopping at. Anything else - `<Name>`, `<KeyCount>`, `<Owner>`,
/// `<EncodingType>`, whatever a given implementation adds - is skipped by the walker.
const PAGE_ELEMENTS: &[&str] = &[
    "Contents",
    "CommonPrefixes",
    "IsTruncated",
    "NextContinuationToken",
];

const OBJECT_ELEMENTS: &[&str] = &["Key", "Size", "LastModified", "ETag"];

/// Reads a `ListObjectsV2` answer.
///
/// The elements are read in whatever order they arrive rather than looked up by name,
/// because the order is the implementation's choice: AWS puts `<IsTruncated>` ahead of
/// the entries, Ceph and MinIO do too but disagree about `<Owner>`, `<StorageClass>` and
/// `<EncodingType>`, and nothing forbids `<CommonPrefixes>` from being interleaved with
/// `<Contents>` rather than grouped after them.
pub(crate) fn parse_list_objects_v2(body: &[u8]) -> Result<S3ListObjectsPage, S3Error> {
    let walker = crate::xml::XmlWalker::open(body, "ListBucketResult");

    // "Could not be read as XML" and "read fine, but is not a listing" are the same
    // thing to a caller: the answer is not the one that was asked for. A `<Error>` body
    // has already been turned into a typed error by `read_success_body`, so anything
    // arriving here with a 2xx is a genuine surprise and the body belongs in the
    // message.
    let walker = match walker {
        Ok(Some(walker)) => Some(walker),
        Ok(None) => None,
        Err(err) => {
            return Err(S3Error::Other(format!(
                "ListObjectsV2 answered with a body that is not a ListBucketResult ({}): {}",
                err,
                String::from_utf8_lossy(body)
            )));
        }
    };

    let Some(mut walker) = walker else {
        return Err(S3Error::Other(format!(
            "ListObjectsV2 answered with a body that is not a ListBucketResult: {}",
            String::from_utf8_lossy(body)
        )));
    };

    let mut common_prefixes = Vec::new();
    let mut objects = Vec::new();
    let mut is_truncated = false;
    let mut next_continuation_token = None;

    while let Some(node) = walker.next_child(PAGE_ELEMENTS).map_err(malformed)? {
        match node.name {
            "Contents" => objects.push(read_object(&mut walker, node)?),
            "CommonPrefixes" => read_common_prefixes(&mut walker, node, &mut common_prefixes)?,
            "IsTruncated" => {
                let value = walker.read_text(node).map_err(malformed)?;
                // Ceph has been seen writing `True`; the XSD says `true`.
                is_truncated = value.trim().eq_ignore_ascii_case("true");
            }
            "NextContinuationToken" => {
                let value = walker.read_text(node).map_err(malformed)?;
                if !value.is_empty() {
                    next_continuation_token = Some(value);
                }
            }
            // `next_child` only ever returns a name from the list it was given.
            _ => {}
        }
    }

    if !is_truncated {
        // A token on a page that is not truncated is not an invitation to ask again -
        // handing it back would loop forever on an implementation that always sends one.
        return Ok(S3ListObjectsPage {
            common_prefixes,
            objects,
            next_continuation_token: None,
        });
    }

    // Truncated with nothing to resume from would be reported as "that was the last
    // page", and the caller would silently list part of the bucket and believe it had
    // all of it. Refusing is the only way that stays visible.
    if next_continuation_token.is_none() {
        return Err(S3Error::Other(
            "ListObjectsV2 reported a truncated listing but sent no NextContinuationToken"
                .to_string(),
        ));
    }

    Ok(S3ListObjectsPage {
        common_prefixes,
        objects,
        next_continuation_token,
    })
}

fn read_object<'t>(
    walker: &mut crate::xml::XmlWalker<'t>,
    contents: my_xml_reader::XmlTagInfo<'t>,
) -> Result<S3ObjectInfo, S3Error> {
    let mut key = None;
    let mut size = None;
    let mut last_modified = None;
    let mut etag = None;

    while let Some(field) = walker
        .next_child_of(&contents, OBJECT_ELEMENTS)
        .map_err(malformed)?
    {
        let name = field.name;
        let value = walker.read_text(field).map_err(malformed)?;

        match name {
            "Key" => key = Some(value),
            "Size" => size = Some(value),
            "LastModified" => last_modified = Some(value),
            "ETag" => etag = Some(value),
            _ => {}
        }
    }

    let key = required(key, "Key")?;
    let last_modified = required(last_modified, "LastModified")?;

    // A size that is missing or not a number is not defaulted to 0: a listing that
    // reports every object as empty is worse than one that says it could not be read.
    let size = required(size, "Size")?;
    let size = size.trim().parse::<u64>().map_err(|_| {
        S3Error::Other(format!(
            "ListObjectsV2 gave <Size>{}</Size> for key {}, which is not a byte count",
            size, key
        ))
    })?;

    Ok(S3ObjectInfo {
        key,
        size,
        last_modified,
        etag,
    })
}

fn read_common_prefixes<'t>(
    walker: &mut crate::xml::XmlWalker<'t>,
    common_prefixes_node: my_xml_reader::XmlTagInfo<'t>,
    dest: &mut Vec<String>,
) -> Result<(), S3Error> {
    let mut found = false;

    // Every implementation seen sends one `<Prefix>` per `<CommonPrefixes>`, but the
    // element is declared as a repeating one, so the loop costs nothing and covers both.
    while let Some(node) = walker
        .next_child_of(&common_prefixes_node, &["Prefix"])
        .map_err(malformed)?
    {
        dest.push(walker.read_text(node).map_err(malformed)?);
        found = true;
    }

    if !found {
        return Err(S3Error::Other(
            "ListObjectsV2 sent a <CommonPrefixes> with no <Prefix> in it".to_string(),
        ));
    }

    Ok(())
}

fn required(value: Option<String>, element: &str) -> Result<String, S3Error> {
    value.ok_or_else(|| {
        S3Error::Other(format!(
            "ListObjectsV2 sent a <Contents> with no <{}> in it",
            element
        ))
    })
}

fn malformed(err: String) -> S3Error {
    S3Error::Other(format!(
        "ListObjectsV2 answered with malformed XML: {}",
        err
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The shape the AWS documentation shows for a delimited listing: folders first,
    /// then the objects at this level, `<Owner>` and `<StorageClass>` present.
    const AWS_WITH_DELIMITER: &str = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <Delimiter>/</Delimiter>
  <KeyCount>3</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>photos/cover.jpg</Key>
    <LastModified>2024-07-01T12:34:56.000Z</LastModified>
    <ETag>&quot;d41d8cd98f00b204e9800998ecf8427e&quot;</ETag>
    <Size>1048576</Size>
    <StorageClass>STANDARD</StorageClass>
    <Owner>
      <ID>75aa57f09aa0c8caeab4f8c24e99d10f8e7faeebf76c078efc7c6caea54ba06a</ID>
      <DisplayName>someone</DisplayName>
    </Owner>
  </Contents>
  <CommonPrefixes>
    <Prefix>photos/2023/</Prefix>
  </CommonPrefixes>
  <CommonPrefixes>
    <Prefix>photos/2024/</Prefix>
  </CommonPrefixes>
</ListBucketResult>"#;

    #[test]
    fn the_aws_example_reads_as_one_folder_level() {
        let page = parse_list_objects_v2(AWS_WITH_DELIMITER.as_bytes()).unwrap();

        assert_eq!(page.common_prefixes, ["photos/2023/", "photos/2024/"]);
        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.next_continuation_token, None);

        let object = &page.objects[0];
        assert_eq!(object.key, "photos/cover.jpg");
        assert_eq!(object.size, 1_048_576);
        assert_eq!(object.last_modified, "2024-07-01T12:34:56.000Z");
        // The quotes are part of an entity tag; `&quot;` is how they cross the wire.
        assert_eq!(
            object.etag.as_deref(),
            Some("\"d41d8cd98f00b204e9800998ecf8427e\"")
        );
    }

    /// The common prefixes have to be usable as the next request's `prefix` without any
    /// stitching at the call site - which is only true if they are full keys.
    #[test]
    fn a_common_prefix_is_a_full_prefix_not_a_suffix() {
        let page = parse_list_objects_v2(AWS_WITH_DELIMITER.as_bytes()).unwrap();

        for prefix in &page.common_prefixes {
            assert!(prefix.starts_with("photos/"), "got {}", prefix);
            assert!(prefix.ends_with('/'), "got {}", prefix);
        }
    }

    /// An empty bucket answers with no `<Contents>` at all, not with an empty one.
    #[test]
    fn an_empty_bucket_is_an_empty_page_not_an_error() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix></Prefix>
  <KeyCount>0</KeyCount>
  <MaxKeys>1000</MaxKeys>
  <IsTruncated>false</IsTruncated>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert!(page.common_prefixes.is_empty());
        assert!(page.objects.is_empty());
        assert_eq!(page.next_continuation_token, None);
    }

    #[test]
    fn a_truncated_page_hands_back_the_token_to_resume_from() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <IsTruncated>true</IsTruncated>
  <NextContinuationToken>1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=</NextContinuationToken>
  <Contents>
    <Key>a.bin</Key>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <Size>1</Size>
  </Contents>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert_eq!(
            page.next_continuation_token.as_deref(),
            Some("1ueGcxLPRx1Tr/XYExHnhbYLgveDs2J/wm36Hy4vbOwM=")
        );
    }

    /// A token on an untruncated page is not a next page. Handing it back would make a
    /// pagination loop run forever on an implementation that always sends one.
    #[test]
    fn a_token_without_truncation_is_not_a_next_page() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <NextContinuationToken>leftover</NextContinuationToken>
</ListBucketResult>"#;

        assert_eq!(
            parse_list_objects_v2(xml.as_bytes())
                .unwrap()
                .next_continuation_token,
            None
        );
    }

    /// The inverse, and the one that silently loses data if it is allowed through: a
    /// truncated page with nothing to resume from would be read as "that was all".
    #[test]
    fn truncated_with_no_token_is_an_error_not_a_last_page() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>true</IsTruncated>
  <Contents><Key>a</Key><LastModified>x</LastModified><Size>0</Size></Contents>
</ListBucketResult>"#;

        assert!(parse_list_objects_v2(xml.as_bytes()).is_err());
    }

    /// Without `encoding-type=url` the key is XML-escaped and nothing more, so the five
    /// predefined entities are the whole of the decoding this needs - and getting it
    /// wrong means a download of the *undecoded* key, which 404s.
    #[test]
    fn an_escaped_key_is_unescaped() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Key>reports/Q1 &amp; Q2 &lt;draft&gt;.pdf</Key>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <Size>7</Size>
  </Contents>
  <CommonPrefixes><Prefix>a &amp; b/</Prefix></CommonPrefixes>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert_eq!(page.objects[0].key, "reports/Q1 & Q2 <draft>.pdf");
        assert_eq!(page.common_prefixes, ["a & b/"]);
    }

    /// Hetzner runs Ceph RGW: a different element order, `<Contents>` before
    /// `<IsTruncated>`, no `<KeyCount>`, and prefixes interleaved with the objects
    /// rather than grouped after them. Looking elements up by name instead of walking
    /// them would read this one wrong.
    #[test]
    fn a_ceph_style_answer_reads_the_same_as_the_aws_one() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?>
<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">
  <Name>my-bucket</Name>
  <Prefix>photos/</Prefix>
  <MaxKeys>1000</MaxKeys>
  <Delimiter>/</Delimiter>
  <CommonPrefixes><Prefix>photos/2023/</Prefix></CommonPrefixes>
  <Contents>
    <Key>photos/a.jpg</Key>
    <LastModified>2024-07-01T12:34:56.000Z</LastModified>
    <ETag>&quot;aaa&quot;</ETag>
    <Size>10</Size>
    <StorageClass>STANDARD</StorageClass>
  </Contents>
  <CommonPrefixes><Prefix>photos/2024/</Prefix></CommonPrefixes>
  <Contents>
    <Key>photos/b.jpg</Key>
    <LastModified>2024-07-02T00:00:00.000Z</LastModified>
    <Size>20</Size>
  </Contents>
  <IsTruncated>false</IsTruncated>
  <Marker></Marker>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert_eq!(page.common_prefixes, ["photos/2023/", "photos/2024/"]);
        assert_eq!(
            page.objects
                .iter()
                .map(|o| o.key.as_str())
                .collect::<Vec<_>>(),
            ["photos/a.jpg", "photos/b.jpg"]
        );
        assert_eq!(page.objects[0].size, 10);
        assert_eq!(page.objects[0].etag.as_deref(), Some("\"aaa\""));
        // An implementation that omits the ETag must not invent one.
        assert_eq!(page.objects[1].etag, None);
        assert_eq!(page.objects[1].size, 20);
    }

    /// MinIO answers with no whitespace at all and `<Owner>` carrying a self-closing
    /// `<DisplayName/>`. A self-closing element inside a skipped subtree must not throw
    /// the walker off the following siblings.
    #[test]
    fn a_minio_style_answer_survives_self_closing_elements() {
        let xml = r#"<?xml version="1.0" encoding="UTF-8"?><ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/"><Name>b</Name><Prefix/><KeyCount>1</KeyCount><MaxKeys>1000</MaxKeys><Delimiter/><IsTruncated>false</IsTruncated><Contents><Key>x.bin</Key><LastModified>2024-07-01T12:34:56.000Z</LastModified><ETag>&quot;e&quot;</ETag><Size>3</Size><Owner><ID>minio</ID><DisplayName/></Owner><StorageClass>STANDARD</StorageClass></Contents></ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "x.bin");
        assert_eq!(page.objects[0].size, 3);
    }

    /// A whole empty listing can come back as a self-closing root - which has no closing
    /// tag to stop the walk at, so the trailing newline behind it used to be enough to
    /// make the reader report a failure.
    #[test]
    fn a_self_closing_root_is_an_empty_page() {
        let page = parse_list_objects_v2(b"<ListBucketResult/>\n").unwrap();

        assert!(page.objects.is_empty());
        assert!(page.common_prefixes.is_empty());
    }

    /// The elements are matched by name, and the reader underneath matches a name at
    /// **any** depth. `<Contents>` carries an `<Owner>` subtree, so a listing whose
    /// owner block happens to hold a wanted name must not have it read as the object's
    /// own - the object here has one key, and it is not `owner-key`.
    #[test]
    fn a_field_buried_in_a_skipped_subtree_is_not_the_objects_own() {
        let xml = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents>
    <Owner><ID>x</ID><Key>owner-key</Key></Owner>
    <Key>real-key</Key>
    <LastModified>2024-01-01T00:00:00.000Z</LastModified>
    <Size>5</Size>
  </Contents>
</ListBucketResult>"#;

        let page = parse_list_objects_v2(xml.as_bytes()).unwrap();

        assert_eq!(page.objects.len(), 1);
        assert_eq!(page.objects[0].key, "real-key");
    }

    /// A listing cut short by a dropped connection is the worst-behaved malformed body
    /// there is: the entries that did arrive are complete and well formed, so the page
    /// would come back as a success holding part of the bucket. A caller has no way to
    /// tell that from a bucket that really does hold two objects.
    #[test]
    fn a_listing_cut_short_is_an_error_not_a_shorter_page() {
        let complete = r#"<ListBucketResult>
  <IsTruncated>false</IsTruncated>
  <Contents><Key>a</Key><LastModified>t</LastModified><Size>1</Size></Contents>
  <Contents><Key>b</Key><LastModified>t</LastModified><Size>2</Size></Contents>
</ListBucketResult>"#;

        assert_eq!(
            parse_list_objects_v2(complete.as_bytes())
                .unwrap()
                .objects
                .len(),
            2
        );

        // The same answer, with the connection dying after the first entry.
        let cut = &complete[..complete.find("<Contents><Key>b").unwrap()];

        assert!(
            parse_list_objects_v2(cut.as_bytes()).is_err(),
            "a half-delivered listing must not read as a complete short one"
        );
    }

    /// Every one of these is a body the server could hand us; none may abort the
    /// process, and none may be read as an empty-but-valid listing.
    #[test]
    fn a_mangled_body_is_an_error_not_a_panic() {
        let truncated_mid_key = b"<ListBucketResult><Contents><Key>half".as_slice();
        let mut invalid_utf8 = b"<ListBucketResult><Contents><Key>".to_vec();
        invalid_utf8.extend_from_slice(&[0xFF, 0xFE]);
        invalid_utf8.extend_from_slice(b"</Key></Contents></ListBucketResult>");

        for body in [
            b"".as_slice(),
            b"502 Bad Gateway".as_slice(),
            b"<html><body>nope</body></html>".as_slice(),
            b"<Error><Code>AccessDenied</Code></Error>".as_slice(),
            truncated_mid_key,
            b"<ListBucketResult><Contents></Wrong></ListBucketResult>".as_slice(),
            // A closing tag with nothing open aborts the underlying reader outright.
            b"</ListBucketResult>".as_slice(),
            b"</div><ListBucketResult></ListBucketResult>".as_slice(),
            invalid_utf8.as_slice(),
            // A `<Contents>` with no key at all is not an object we can act on.
            b"<ListBucketResult><Contents><Size>1</Size></Contents></ListBucketResult>".as_slice(),
            // Nor is one whose size is not a number.
            b"<ListBucketResult><Contents><Key>a</Key><LastModified>x</LastModified><Size>huge</Size></Contents></ListBucketResult>".as_slice(),
            // A folder entry with nothing in it.
            b"<ListBucketResult><CommonPrefixes></CommonPrefixes></ListBucketResult>".as_slice(),
        ] {
            assert!(
                parse_list_objects_v2(body).is_err(),
                "{:?} must not read as a listing",
                String::from_utf8_lossy(body)
            );
        }
    }
}
