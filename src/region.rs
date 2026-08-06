//! The region a client is configured for, as a catalogue of the ones that exist plus
//! an escape hatch for the ones nobody has written down yet.

/// The region an [`crate::S3Client`] talks to.
///
/// The region is not decoration. It appears in two places on the wire, and a server
/// compares both byte-for-byte:
///
/// * the SigV4 credential scope of **every** request - a wrong value is
///   `403 SignatureDoesNotMatch`;
/// * the `LocationConstraint` of `CreateBucket` - a value that disagrees with the
///   endpoint is `400 IllegalLocationConstraintException`.
///
/// So [`Self::as_str`] is the one definition of what the value is, and every variant
/// round-trips through [`Self::from_str`] unchanged.
///
/// The named variants are a **catalogue, not a whitelist**: anything not listed lands
/// in [`Self::Other`] and behaves identically, because the string is all that ever
/// leaves the process. Adding a variant documents that a region exists; it never
/// enables anything, and leaving one out never breaks anything.
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum S3Region {
    // -----------------------------------------------------------------------
    // AWS - the Americas
    // -----------------------------------------------------------------------
    /// `us-east-1` - N. Virginia. S3's historical default, and the one region that is
    /// stated on `CreateBucket` by sending **no** `LocationConstraint` - see
    /// [`Self::is_us_east_1`].
    AwsUsEast1,
    /// `us-east-2` - Ohio.
    AwsUsEast2,
    /// `us-west-1` - N. California.
    AwsUsWest1,
    /// `us-west-2` - Oregon.
    AwsUsWest2,
    /// `ca-central-1` - Central Canada (Montreal).
    AwsCaCentral1,
    /// `ca-west-1` - Calgary.
    AwsCaWest1,
    /// `mx-central-1` - Mexico.
    AwsMxCentral1,
    /// `sa-east-1` - Sao Paulo.
    AwsSaEast1,

    // -----------------------------------------------------------------------
    // AWS - Europe
    // -----------------------------------------------------------------------
    /// `eu-west-1` - Ireland.
    AwsEuWest1,
    /// `eu-west-2` - London.
    AwsEuWest2,
    /// `eu-west-3` - Paris.
    AwsEuWest3,
    /// `eu-central-1` - Frankfurt.
    AwsEuCentral1,
    /// `eu-central-2` - Zurich.
    AwsEuCentral2,
    /// `eu-north-1` - Stockholm.
    AwsEuNorth1,
    /// `eu-south-1` - Milan.
    AwsEuSouth1,
    /// `eu-south-2` - Spain.
    AwsEuSouth2,

    // -----------------------------------------------------------------------
    // AWS - Asia Pacific, Middle East, Africa
    // -----------------------------------------------------------------------
    /// `ap-east-1` - Hong Kong.
    AwsApEast1,
    /// `ap-south-1` - Mumbai.
    AwsApSouth1,
    /// `ap-south-2` - Hyderabad.
    AwsApSouth2,
    /// `ap-southeast-1` - Singapore.
    AwsApSoutheast1,
    /// `ap-southeast-2` - Sydney.
    AwsApSoutheast2,
    /// `ap-southeast-3` - Jakarta.
    AwsApSoutheast3,
    /// `ap-southeast-4` - Melbourne.
    AwsApSoutheast4,
    /// `ap-northeast-1` - Tokyo.
    AwsApNortheast1,
    /// `ap-northeast-2` - Seoul.
    AwsApNortheast2,
    /// `ap-northeast-3` - Osaka.
    AwsApNortheast3,
    /// `me-central-1` - UAE.
    AwsMeCentral1,
    /// `me-south-1` - Bahrain.
    AwsMeSouth1,
    /// `il-central-1` - Tel Aviv.
    AwsIlCentral1,
    /// `af-south-1` - Cape Town.
    AwsAfSouth1,

    // -----------------------------------------------------------------------
    // AWS - partitions of their own. These do not share the credential
    // namespace with the commercial regions above.
    // -----------------------------------------------------------------------
    /// `us-gov-east-1` - AWS GovCloud (US-East).
    AwsUsGovEast1,
    /// `us-gov-west-1` - AWS GovCloud (US-West).
    AwsUsGovWest1,
    /// `cn-north-1` - Beijing.
    AwsCnNorth1,
    /// `cn-northwest-1` - Ningxia.
    AwsCnNorthwest1,

    // -----------------------------------------------------------------------
    // Hetzner Object Storage (Ceph/RGW). The location is part of the endpoint
    // host - `https://fsn1.your-objectstorage.com` - and Hetzner's own docs
    // create buckets with `--region fsn1`, so the same string is what the
    // `LocationConstraint` has to carry.
    // -----------------------------------------------------------------------
    /// `fsn1` - Falkenstein.
    HetznerFsn1,
    /// `nbg1` - Nuremberg.
    HetznerNbg1,
    /// `hel1` - Helsinki.
    HetznerHel1,

    /// Any region this catalogue does not name - another provider (MinIO, Ceph,
    /// DigitalOcean, Wasabi, ...), a private deployment, or an AWS region added after
    /// this list was written.
    ///
    /// Owned rather than borrowed on purpose: the value comes from configuration read
    /// at runtime, and the alternatives were leaking it to get a `&'static str` or
    /// putting a lifetime on [`crate::S3Client`] and everything that holds one.
    Other(String),
}

impl S3Region {
    /// The region exactly as it goes on the wire - into the credential scope and into
    /// the `LocationConstraint`.
    pub fn as_str(&self) -> &str {
        match self {
            Self::AwsUsEast1 => "us-east-1",
            Self::AwsUsEast2 => "us-east-2",
            Self::AwsUsWest1 => "us-west-1",
            Self::AwsUsWest2 => "us-west-2",
            Self::AwsCaCentral1 => "ca-central-1",
            Self::AwsCaWest1 => "ca-west-1",
            Self::AwsMxCentral1 => "mx-central-1",
            Self::AwsSaEast1 => "sa-east-1",

            Self::AwsEuWest1 => "eu-west-1",
            Self::AwsEuWest2 => "eu-west-2",
            Self::AwsEuWest3 => "eu-west-3",
            Self::AwsEuCentral1 => "eu-central-1",
            Self::AwsEuCentral2 => "eu-central-2",
            Self::AwsEuNorth1 => "eu-north-1",
            Self::AwsEuSouth1 => "eu-south-1",
            Self::AwsEuSouth2 => "eu-south-2",

            Self::AwsApEast1 => "ap-east-1",
            Self::AwsApSouth1 => "ap-south-1",
            Self::AwsApSouth2 => "ap-south-2",
            Self::AwsApSoutheast1 => "ap-southeast-1",
            Self::AwsApSoutheast2 => "ap-southeast-2",
            Self::AwsApSoutheast3 => "ap-southeast-3",
            Self::AwsApSoutheast4 => "ap-southeast-4",
            Self::AwsApNortheast1 => "ap-northeast-1",
            Self::AwsApNortheast2 => "ap-northeast-2",
            Self::AwsApNortheast3 => "ap-northeast-3",
            Self::AwsMeCentral1 => "me-central-1",
            Self::AwsMeSouth1 => "me-south-1",
            Self::AwsIlCentral1 => "il-central-1",
            Self::AwsAfSouth1 => "af-south-1",

            Self::AwsUsGovEast1 => "us-gov-east-1",
            Self::AwsUsGovWest1 => "us-gov-west-1",
            Self::AwsCnNorth1 => "cn-north-1",
            Self::AwsCnNorthwest1 => "cn-northwest-1",

            Self::HetznerFsn1 => "fsn1",
            Self::HetznerNbg1 => "nbg1",
            Self::HetznerHel1 => "hel1",

            Self::Other(region) => region.as_str(),
        }
    }

    /// Reads a region out of configuration.
    ///
    /// This cannot fail: an unrecognised value becomes [`Self::Other`], carried
    /// verbatim. Rejecting it would only mean this crate refusing to talk to a storage
    /// it is perfectly able to talk to, the day a provider adds a location.
    ///
    /// The value is **not** normalised - not trimmed, not lowercased - because it has
    /// to reach the credential scope as the operator wrote it. A region with stray
    /// whitespace is a broken configuration, and silently repairing it here would hide
    /// that behind a `403` from the server instead.
    // Deliberately not `std::str::FromStr`: that returns a `Result`, and there is no
    // failure to report. Handing back `Result<Self, Infallible>` would only make every
    // call site unwrap something that cannot happen.
    #[allow(clippy::should_implement_trait)]
    pub fn from_str(src: &str) -> Self {
        match src {
            "us-east-1" => Self::AwsUsEast1,
            "us-east-2" => Self::AwsUsEast2,
            "us-west-1" => Self::AwsUsWest1,
            "us-west-2" => Self::AwsUsWest2,
            "ca-central-1" => Self::AwsCaCentral1,
            "ca-west-1" => Self::AwsCaWest1,
            "mx-central-1" => Self::AwsMxCentral1,
            "sa-east-1" => Self::AwsSaEast1,

            "eu-west-1" => Self::AwsEuWest1,
            "eu-west-2" => Self::AwsEuWest2,
            "eu-west-3" => Self::AwsEuWest3,
            "eu-central-1" => Self::AwsEuCentral1,
            "eu-central-2" => Self::AwsEuCentral2,
            "eu-north-1" => Self::AwsEuNorth1,
            "eu-south-1" => Self::AwsEuSouth1,
            "eu-south-2" => Self::AwsEuSouth2,

            "ap-east-1" => Self::AwsApEast1,
            "ap-south-1" => Self::AwsApSouth1,
            "ap-south-2" => Self::AwsApSouth2,
            "ap-southeast-1" => Self::AwsApSoutheast1,
            "ap-southeast-2" => Self::AwsApSoutheast2,
            "ap-southeast-3" => Self::AwsApSoutheast3,
            "ap-southeast-4" => Self::AwsApSoutheast4,
            "ap-northeast-1" => Self::AwsApNortheast1,
            "ap-northeast-2" => Self::AwsApNortheast2,
            "ap-northeast-3" => Self::AwsApNortheast3,
            "me-central-1" => Self::AwsMeCentral1,
            "me-south-1" => Self::AwsMeSouth1,
            "il-central-1" => Self::AwsIlCentral1,
            "af-south-1" => Self::AwsAfSouth1,

            "us-gov-east-1" => Self::AwsUsGovEast1,
            "us-gov-west-1" => Self::AwsUsGovWest1,
            "cn-north-1" => Self::AwsCnNorth1,
            "cn-northwest-1" => Self::AwsCnNorthwest1,

            "fsn1" => Self::HetznerFsn1,
            "nbg1" => Self::HetznerNbg1,
            "hel1" => Self::HetznerHel1,

            other => Self::Other(other.to_string()),
        }
    }

    /// Whether this is S3's historical default region.
    ///
    /// `CreateBucket` states `us-east-1` by sending **no** `LocationConstraint`, and
    /// AWS rejects the element when it names `us-east-1` explicitly - so this is the
    /// one region whose body is empty.
    ///
    /// Decided on the string rather than on the variant, so an [`Self::Other`] built by
    /// hand out of `"us-east-1"` is treated as what it says it is.
    pub fn is_us_east_1(&self) -> bool {
        self.as_str() == "us-east-1"
    }

    /// Whether a region was configured at all. An empty one is not a region: it cannot
    /// sign a request, and `<LocationConstraint></LocationConstraint>` is only a
    /// malformed way of writing the `us-east-1` default.
    pub fn is_empty(&self) -> bool {
        self.as_str().is_empty()
    }
}

impl std::fmt::Display for S3Region {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

impl From<&'_ str> for S3Region {
    fn from(value: &str) -> Self {
        Self::from_str(value)
    }
}

impl From<String> for S3Region {
    fn from(value: String) -> Self {
        // Reuses the owned string when nothing matches, instead of parsing into `Other`
        // and allocating the very same bytes a second time.
        match Self::from_str(value.as_str()) {
            Self::Other(_) => Self::Other(value),
            known => known,
        }
    }
}

impl From<&'_ String> for S3Region {
    fn from(value: &String) -> Self {
        Self::from_str(value.as_str())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The parsed value has to come back out byte-identical: it is signed into the
    /// credential scope, so a single changed character is a 403.
    #[test]
    fn every_known_region_round_trips() {
        for region in [
            "us-east-1",
            "us-east-2",
            "us-west-1",
            "us-west-2",
            "ca-central-1",
            "ca-west-1",
            "mx-central-1",
            "sa-east-1",
            "eu-west-1",
            "eu-west-2",
            "eu-west-3",
            "eu-central-1",
            "eu-central-2",
            "eu-north-1",
            "eu-south-1",
            "eu-south-2",
            "ap-east-1",
            "ap-south-1",
            "ap-south-2",
            "ap-southeast-1",
            "ap-southeast-2",
            "ap-southeast-3",
            "ap-southeast-4",
            "ap-northeast-1",
            "ap-northeast-2",
            "ap-northeast-3",
            "me-central-1",
            "me-south-1",
            "il-central-1",
            "af-south-1",
            "us-gov-east-1",
            "us-gov-west-1",
            "cn-north-1",
            "cn-northwest-1",
            "fsn1",
            "nbg1",
            "hel1",
        ] {
            let parsed = S3Region::from_str(region);

            assert_eq!(parsed.as_str(), region);
            assert!(
                !matches!(parsed, S3Region::Other(_)),
                "{} is in the catalogue and must not fall through to Other",
                region
            );
        }
    }

    /// The catalogue is not a whitelist - an unlisted region has to keep working, which
    /// is what makes it safe for the list to be incomplete.
    #[test]
    fn an_unknown_region_is_carried_verbatim() {
        let region = S3Region::from_str("mars-north-7");

        assert_eq!(region, S3Region::Other("mars-north-7".to_string()));
        assert_eq!(region.as_str(), "mars-north-7");
    }

    /// The region reaches the signature as written: trimming or lowercasing here would
    /// turn a broken configuration into a 403 from the server with nothing pointing
    /// back at the typo.
    #[test]
    fn parsing_does_not_normalise() {
        assert_eq!(S3Region::from_str(" eu-west-1").as_str(), " eu-west-1");
        assert_eq!(S3Region::from_str("EU-WEST-1").as_str(), "EU-WEST-1");
    }

    #[test]
    fn conversions_agree_with_from_str() {
        assert_eq!(S3Region::from("fsn1"), S3Region::HetznerFsn1);
        assert_eq!(S3Region::from("fsn1".to_string()), S3Region::HetznerFsn1);
        assert_eq!(
            S3Region::from("whatever-1".to_string()),
            S3Region::Other("whatever-1".to_string())
        );
        assert_eq!(S3Region::HetznerFsn1.to_string(), "fsn1");
    }

    /// The `CreateBucket` body hangs off this, and it is decided by what the region
    /// *says*, so a hand-built `Other` is not a way to sneak past the rule.
    #[test]
    fn us_east_1_is_recognised_however_it_was_built() {
        assert!(S3Region::AwsUsEast1.is_us_east_1());
        assert!(S3Region::Other("us-east-1".to_string()).is_us_east_1());

        assert!(!S3Region::AwsEuWest1.is_us_east_1());
        assert!(!S3Region::HetznerFsn1.is_us_east_1());
    }

    #[test]
    fn an_unconfigured_region_is_empty() {
        assert!(S3Region::from_str("").is_empty());
        assert!(!S3Region::HetznerFsn1.is_empty());
    }
}
