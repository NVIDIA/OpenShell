#![allow(
    unused_imports,
    unused_qualifications,
    unused_extern_crates,
    clippy::all
)]

#[cfg(feature = "buildkit")]
use prost::Message;
use serde::de::{DeserializeOwned, Deserializer};
use serde::ser::{Serializer, SerializeMap};
use serde::{Deserialize, Serialize};
use serde_repr::{Serialize_repr, Deserialize_repr};

use std::cmp::Eq;
use std::collections::HashMap;
use std::default::Default;
use std::hash::Hash;

use crate::serde_ext;

fn deserialize_nonoptional_vec<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> Result<Vec<T>, D::Error> {
    serde::Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or(Vec::new()))
}

fn deserialize_nonoptional_map<'de, D: Deserializer<'de>, T: DeserializeOwned>(
    d: D,
) -> Result<HashMap<String, T>, D::Error> {
    serde::Deserialize::deserialize(d).map(|x: Option<_>| x.unwrap_or(HashMap::new()))
}

#[cfg(feature = "time")]
pub type BollardDate = time::OffsetDateTime;
#[cfg(all(feature = "chrono", not(feature = "time")))]
pub type BollardDate = chrono::DateTime<chrono::Utc>;
#[cfg(not(any(feature = "chrono", feature = "time")))]
pub type BollardDate = String;

#[cfg(feature = "time")]
fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    d: D
) -> Result<Option<BollardDate>, D::Error> {
    let opt: Option<String> = serde::Deserialize::deserialize(d)?;
    if let Some(s) = opt {
        Ok(Some(
            time::OffsetDateTime::parse(&s, &time::format_description::well_known::Rfc3339)
                .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?,
        ))
    } else {
        Ok(None)
    }
}

#[cfg(not(feature = "time"))]
fn deserialize_timestamp<'de, D: Deserializer<'de>>(
    d: D
) -> Result<Option<BollardDate>, D::Error> {
    serde::Deserialize::deserialize(d)
}

#[cfg(feature = "time")]
fn serialize_timestamp<S: Serializer>(date: &Option<BollardDate>, s: S) -> Result<S::Ok, S::Error> {
    match date {
        Some(inner) => Ok(s.serialize_str(&inner.format(&time::format_description::well_known::Rfc3339)
                                          .map_err(|e| serde::ser::Error::custom(format!("{:?}", e)))?)?),
        None => Ok(s.serialize_str("")?)
    }
}

#[cfg(not(feature = "time"))]
fn serialize_timestamp<S: Serializer>(date: &Option<BollardDate>, s: S) -> Result<S::Ok, S::Error> {
    match date {
        Some(inner) => s.serialize_some(inner),
        None => s.serialize_none()
    }
}

#[cfg(feature = "buildkit")]
fn deserialize_buildinfo_aux<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<crate::moby::buildkit::v1::StatusResponse, D::Error> {
    let aux: String = serde::Deserialize::deserialize(d)?;
    let raw = base64::Engine::decode(&base64::engine::general_purpose::STANDARD, &aux)
        .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
    let buf = bytes::BytesMut::from(&raw[..]);

    let res = crate::moby::buildkit::v1::StatusResponse::decode(buf)
        .map_err(|e| serde::de::Error::custom(format!("{:?}", e)))?;
    Ok(res)
}

pub fn serialize_hashmap_string_hashmap_empty<S: Serializer>(
    opt: &Option<Vec<String>>,
    s: S,
) -> Result<S::Ok, S::Error> {
    if let Some(vec) = opt {
        let mut map = s.serialize_map(Some(vec.len()))?;
        for entry in vec {
            map.serialize_entry(entry, &HashMap::<(), ()>::new())?;
        }
        map.end()
    } else {
        let mut map = s.serialize_map(Some(0))?;
        map.end()
    }
}

pub fn deserialize_hashmap_string_hashmap_empty<'de, D: Deserializer<'de>>(
    d: D,
) -> Result<Option<Vec<String>>, D::Error> {
    match serde::Deserialize::deserialize(d) {
        Ok::<Option<HashMap<String, HashMap<(), ()>>>, D::Error>(Some(mut hsh)) => {
            let mut res = vec![];
            for (key, _) in hsh.drain() {
                res.push(key);
            }
            Ok(Some(res))
        }
        Ok(None) => Ok(Some(vec![])),
        Err(e) => Err(e),
    }
}

#[cfg(feature = "buildkit")]
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(untagged)]
pub enum BuildInfoAux {
    #[serde(deserialize_with = "deserialize_buildinfo_aux")]
    BuildKit(crate::moby::buildkit::v1::StatusResponse),
    Default(ImageId)
}


/// Address represents an IPv4 or IPv6 IP address.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Address {
    /// IP address.
    #[serde(rename = "Addr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

    /// Mask length of the IP address.
    #[serde(rename = "PrefixLen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prefix_len: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthConfig {
    #[serde(rename = "username")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,

    #[serde(rename = "password")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,

    #[serde(rename = "serveraddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub serveraddress: Option<String>,

}

/// An identity token was generated successfully. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct AuthResponse {
    /// The status of the authentication
    #[serde(rename = "Status")]
    pub status: String,

    /// An opaque token used to authenticate a user after a successful login
    #[serde(rename = "IdentityToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub identity_token: Option<String>,

}

/// Volume configuration
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Body {
    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<ClusterVolumeSpec>,

}

/// BuildCache contains information about a build cache record. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BuildCache {
    /// Unique ID of the build cache record. 
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// List of parent build cache record IDs. 
    #[serde(rename = "Parents")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parents: Option<Vec<String>>,

    /// Cache record type. 
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<BuildCacheTypeEnum>,

    /// Description of the build-step that produced the build cache. 
    #[serde(rename = "Description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    /// Indicates if the build cache is in use. 
    #[serde(rename = "InUse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub in_use: Option<bool>,

    /// Indicates if the build cache is shared. 
    #[serde(rename = "Shared")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shared: Option<bool>,

    /// Amount of disk space used by the build cache (in bytes). 
    #[serde(rename = "Size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,

    /// Date and time at which the build cache was created in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    /// Date and time at which the build cache was last used in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "LastUsedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub last_used_at: Option<BollardDate>,

    #[serde(rename = "UsageCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_count: Option<i64>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum BuildCacheTypeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "internal")]
    INTERNAL,
    #[serde(rename = "frontend")]
    FRONTEND,
    #[serde(rename = "source.local")]
    SOURCE_LOCAL,
    #[serde(rename = "source.git.checkout")]
    SOURCE_GIT_CHECKOUT,
    #[serde(rename = "exec.cachemount")]
    EXEC_CACHEMOUNT,
    #[serde(rename = "regular")]
    REGULAR,
}

impl ::std::fmt::Display for BuildCacheTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            BuildCacheTypeEnum::EMPTY => write!(f, ""),
            BuildCacheTypeEnum::INTERNAL => write!(f, "{}", "internal"),
            BuildCacheTypeEnum::FRONTEND => write!(f, "{}", "frontend"),
            BuildCacheTypeEnum::SOURCE_LOCAL => write!(f, "{}", "source.local"),
            BuildCacheTypeEnum::SOURCE_GIT_CHECKOUT => write!(f, "{}", "source.git.checkout"),
            BuildCacheTypeEnum::EXEC_CACHEMOUNT => write!(f, "{}", "exec.cachemount"),
            BuildCacheTypeEnum::REGULAR => write!(f, "{}", "regular"),

        }
    }
}

impl ::std::str::FromStr for BuildCacheTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(BuildCacheTypeEnum::EMPTY),
            "internal" => Ok(BuildCacheTypeEnum::INTERNAL),
            "frontend" => Ok(BuildCacheTypeEnum::FRONTEND),
            "source.local" => Ok(BuildCacheTypeEnum::SOURCE_LOCAL),
            "source.git.checkout" => Ok(BuildCacheTypeEnum::SOURCE_GIT_CHECKOUT),
            "exec.cachemount" => Ok(BuildCacheTypeEnum::EXEC_CACHEMOUNT),
            "regular" => Ok(BuildCacheTypeEnum::REGULAR),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for BuildCacheTypeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            BuildCacheTypeEnum::EMPTY => "",
            BuildCacheTypeEnum::INTERNAL => "internal",
            BuildCacheTypeEnum::FRONTEND => "frontend",
            BuildCacheTypeEnum::SOURCE_LOCAL => "source.local",
            BuildCacheTypeEnum::SOURCE_GIT_CHECKOUT => "source.git.checkout",
            BuildCacheTypeEnum::EXEC_CACHEMOUNT => "exec.cachemount",
            BuildCacheTypeEnum::REGULAR => "regular",
        }
    }
}

/// represents system data usage for build cache resources. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BuildCacheDiskUsage {
    /// Count of active build cache records. 
    #[serde(rename = "ActiveCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_count: Option<i64>,

    /// Count of all build cache records. 
    #[serde(rename = "TotalCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,

    /// Disk space that can be reclaimed by removing inactive build cache records. 
    #[serde(rename = "Reclaimable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<i64>,

    /// Disk space in use by build cache records. 
    #[serde(rename = "TotalSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,

    /// List of build cache records. 
    #[serde(rename = "Items")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<serde_json::Value>>,

}

#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
pub struct BuildInfo {
    #[serde(rename = "id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "stream")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stream: Option<String>,

    #[serde(rename = "errorDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<ErrorDetail>,

    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "progressDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_detail: Option<ProgressDetail>,

    #[serde(rename = "aux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(feature = "buildkit")]
    pub aux: Option<BuildInfoAux>,

    #[serde(rename = "aux")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[cfg(not(feature = "buildkit"))]
    pub aux: Option<ImageId>,
    
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct BuildPruneResponse {
    #[serde(rename = "CachesDeleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub caches_deleted: Option<Vec<String>>,

    /// Disk space reclaimed in bytes
    #[serde(rename = "SpaceReclaimed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_reclaimed: Option<i64>,

}

/// Kind of change  Can be one of:  - `0`: Modified (\"C\") - `1`: Added (\"A\") - `2`: Deleted (\"D\") 
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(i32)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize_repr, Deserialize_repr, Eq, Ord)]
pub enum ChangeType { 
    _0 = 0,
    _1 = 1,
    _2 = 2,
}

impl ::std::fmt::Display for ChangeType {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ChangeType::_0 => write!(f, "{}", 0),
            ChangeType::_1 => write!(f, "{}", 1),
            ChangeType::_2 => write!(f, "{}", 2),
        }
    }
}

impl std::default::Default for ChangeType {
    fn default() -> Self { 
        ChangeType::_0
    }
}

/// ClusterInfo represents information about the swarm as is returned by the \"/info\" endpoint. Join-tokens are not included. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterInfo {
    /// The ID of the swarm.
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    /// Date and time at which the swarm was initialised in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    /// Date and time at which the swarm was last updated in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSpec>,

    #[serde(rename = "TLSInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,

    /// Whether there is currently a root CA rotation in progress for the swarm 
    #[serde(rename = "RootRotationInProgress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_rotation_in_progress: Option<bool>,

    /// DataPathPort specifies the data path port number for data traffic. Acceptable port range is 1024 to 49151. If no port is set or is set to 0, the default port (4789) is used. 
    #[serde(rename = "DataPathPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path_port: Option<u32>,

    /// Default Address Pool specifies default subnet pools for global scope networks. 
    #[serde(rename = "DefaultAddrPool")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_addr_pool: Option<Vec<String>>,

    /// SubnetSize specifies the subnet size of the networks created from the default subnet pool. 
    #[serde(rename = "SubnetSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_size: Option<u32>,

}

/// Options and information specific to, and only present on, Swarm CSI cluster volumes. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolume {
    /// The Swarm ID of this volume. Because cluster volumes are Swarm objects, they have an ID, unlike non-cluster volumes. This ID can be used to refer to the Volume instead of the name. 
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<ClusterVolumeSpec>,

    #[serde(rename = "Info")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<ClusterVolumeInfo>,

    /// The status of the volume as it pertains to its publishing and use on specific nodes 
    #[serde(rename = "PublishStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_status: Option<Vec<ClusterVolumePublishStatus>>,

}

/// Information about the global status of the volume. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeInfo {
    /// The capacity of the volume in bytes. A value of 0 indicates that the capacity is unknown. 
    #[serde(rename = "CapacityBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_bytes: Option<i64>,

    /// A map of strings to strings returned from the storage plugin when the volume is created. 
    #[serde(rename = "VolumeContext")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_context: Option<HashMap<String, String>>,

    /// The ID of the volume as returned by the CSI storage plugin. This is distinct from the volume's ID as provided by Docker. This ID is never used by the user when communicating with Docker to refer to this volume. If the ID is blank, then the Volume has not been successfully created in the plugin yet. 
    #[serde(rename = "VolumeID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_id: Option<String>,

    /// The topology this volume is actually accessible from. 
    #[serde(rename = "AccessibleTopology")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessible_topology: Option<Vec<Topology>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumePublishStatus {
    /// The ID of the Swarm node the volume is published on. 
    #[serde(rename = "NodeID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// The published state of the volume. * `pending-publish` The volume should be published to this node, but the call to the controller plugin to do so has not yet been successfully completed. * `published` The volume is published successfully to the node. * `pending-node-unpublish` The volume should be unpublished from the node, and the manager is awaiting confirmation from the worker that it has done so. * `pending-controller-unpublish` The volume is successfully unpublished from the node, but has not yet been successfully unpublished on the controller. 
    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ClusterVolumePublishStatusStateEnum>,

    /// A map of strings to strings returned by the CSI controller plugin when a volume is published. 
    #[serde(rename = "PublishContext")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_context: Option<HashMap<String, String>>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ClusterVolumePublishStatusStateEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "pending-publish")]
    PENDING_PUBLISH,
    #[serde(rename = "published")]
    PUBLISHED,
    #[serde(rename = "pending-node-unpublish")]
    PENDING_NODE_UNPUBLISH,
    #[serde(rename = "pending-controller-unpublish")]
    PENDING_CONTROLLER_UNPUBLISH,
}

impl ::std::fmt::Display for ClusterVolumePublishStatusStateEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ClusterVolumePublishStatusStateEnum::EMPTY => write!(f, ""),
            ClusterVolumePublishStatusStateEnum::PENDING_PUBLISH => write!(f, "{}", "pending-publish"),
            ClusterVolumePublishStatusStateEnum::PUBLISHED => write!(f, "{}", "published"),
            ClusterVolumePublishStatusStateEnum::PENDING_NODE_UNPUBLISH => write!(f, "{}", "pending-node-unpublish"),
            ClusterVolumePublishStatusStateEnum::PENDING_CONTROLLER_UNPUBLISH => write!(f, "{}", "pending-controller-unpublish"),

        }
    }
}

impl ::std::str::FromStr for ClusterVolumePublishStatusStateEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ClusterVolumePublishStatusStateEnum::EMPTY),
            "pending-publish" => Ok(ClusterVolumePublishStatusStateEnum::PENDING_PUBLISH),
            "published" => Ok(ClusterVolumePublishStatusStateEnum::PUBLISHED),
            "pending-node-unpublish" => Ok(ClusterVolumePublishStatusStateEnum::PENDING_NODE_UNPUBLISH),
            "pending-controller-unpublish" => Ok(ClusterVolumePublishStatusStateEnum::PENDING_CONTROLLER_UNPUBLISH),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ClusterVolumePublishStatusStateEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ClusterVolumePublishStatusStateEnum::EMPTY => "",
            ClusterVolumePublishStatusStateEnum::PENDING_PUBLISH => "pending-publish",
            ClusterVolumePublishStatusStateEnum::PUBLISHED => "published",
            ClusterVolumePublishStatusStateEnum::PENDING_NODE_UNPUBLISH => "pending-node-unpublish",
            ClusterVolumePublishStatusStateEnum::PENDING_CONTROLLER_UNPUBLISH => "pending-controller-unpublish",
        }
    }
}

/// Cluster-specific options used to create the volume. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeSpec {
    /// Group defines the volume group of this volume. Volumes belonging to the same group can be referred to by group name when creating Services.  Referring to a volume by group instructs Swarm to treat volumes in that group interchangeably for the purpose of scheduling. Volumes with an empty string for a group technically all belong to the same, emptystring group. 
    #[serde(rename = "Group")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,

    #[serde(rename = "AccessMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub access_mode: Option<ClusterVolumeSpecAccessMode>,

}

/// Defines how the volume is used by tasks. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeSpecAccessMode {
    /// The set of nodes this volume can be used on at one time. - `single` The volume may only be scheduled to one node at a time. - `multi` the volume may be scheduled to any supported number of nodes at a time. 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<ClusterVolumeSpecAccessModeScopeEnum>,

    /// The number and way that different tasks can use this volume at one time. - `none` The volume may only be used by one task at a time. - `readonly` The volume may be used by any number of tasks, but they all must mount the volume as readonly - `onewriter` The volume may be used by any number of tasks, but only one may mount it as read/write. - `all` The volume may have any number of readers and writers. 
    #[serde(rename = "Sharing")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sharing: Option<ClusterVolumeSpecAccessModeSharingEnum>,

    /// Options for using this volume as a Mount-type volume.      Either MountVolume or BlockVolume, but not both, must be     present.   properties:     FsType:       type: \"string\"       description: |         Specifies the filesystem type for the mount volume.         Optional.     MountFlags:       type: \"array\"       description: |         Flags to pass when mounting the volume. Optional.       items:         type: \"string\" BlockVolume:   type: \"object\"   description: |     Options for using this volume as a Block-type volume.     Intentionally empty. 
    #[serde(rename = "MountVolume")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_volume: Option<HashMap<(), ()>>,

    /// Swarm Secrets that are passed to the CSI storage plugin when operating on this volume. 
    #[serde(rename = "Secrets")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<ClusterVolumeSpecAccessModeSecrets>>,

    #[serde(rename = "AccessibilityRequirements")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub accessibility_requirements: Option<ClusterVolumeSpecAccessModeAccessibilityRequirements>,

    #[serde(rename = "CapacityRange")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capacity_range: Option<ClusterVolumeSpecAccessModeCapacityRange>,

    /// The availability of the volume for use in tasks. - `active` The volume is fully available for scheduling on the cluster - `pause` No new workloads should use the volume, but existing workloads are not stopped. - `drain` All workloads using this volume should be stopped and rescheduled, and no new ones should be started. 
    #[serde(rename = "Availability")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<ClusterVolumeSpecAccessModeAvailabilityEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ClusterVolumeSpecAccessModeScopeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "single")]
    SINGLE,
    #[serde(rename = "multi")]
    MULTI,
}

impl ::std::fmt::Display for ClusterVolumeSpecAccessModeScopeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ClusterVolumeSpecAccessModeScopeEnum::EMPTY => write!(f, ""),
            ClusterVolumeSpecAccessModeScopeEnum::SINGLE => write!(f, "{}", "single"),
            ClusterVolumeSpecAccessModeScopeEnum::MULTI => write!(f, "{}", "multi"),

        }
    }
}

impl ::std::str::FromStr for ClusterVolumeSpecAccessModeScopeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ClusterVolumeSpecAccessModeScopeEnum::EMPTY),
            "single" => Ok(ClusterVolumeSpecAccessModeScopeEnum::SINGLE),
            "multi" => Ok(ClusterVolumeSpecAccessModeScopeEnum::MULTI),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ClusterVolumeSpecAccessModeScopeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ClusterVolumeSpecAccessModeScopeEnum::EMPTY => "",
            ClusterVolumeSpecAccessModeScopeEnum::SINGLE => "single",
            ClusterVolumeSpecAccessModeScopeEnum::MULTI => "multi",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ClusterVolumeSpecAccessModeSharingEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "none")]
    NONE,
    #[serde(rename = "readonly")]
    READONLY,
    #[serde(rename = "onewriter")]
    ONEWRITER,
    #[serde(rename = "all")]
    ALL,
}

impl ::std::fmt::Display for ClusterVolumeSpecAccessModeSharingEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ClusterVolumeSpecAccessModeSharingEnum::EMPTY => write!(f, ""),
            ClusterVolumeSpecAccessModeSharingEnum::NONE => write!(f, "{}", "none"),
            ClusterVolumeSpecAccessModeSharingEnum::READONLY => write!(f, "{}", "readonly"),
            ClusterVolumeSpecAccessModeSharingEnum::ONEWRITER => write!(f, "{}", "onewriter"),
            ClusterVolumeSpecAccessModeSharingEnum::ALL => write!(f, "{}", "all"),

        }
    }
}

impl ::std::str::FromStr for ClusterVolumeSpecAccessModeSharingEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ClusterVolumeSpecAccessModeSharingEnum::EMPTY),
            "none" => Ok(ClusterVolumeSpecAccessModeSharingEnum::NONE),
            "readonly" => Ok(ClusterVolumeSpecAccessModeSharingEnum::READONLY),
            "onewriter" => Ok(ClusterVolumeSpecAccessModeSharingEnum::ONEWRITER),
            "all" => Ok(ClusterVolumeSpecAccessModeSharingEnum::ALL),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ClusterVolumeSpecAccessModeSharingEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ClusterVolumeSpecAccessModeSharingEnum::EMPTY => "",
            ClusterVolumeSpecAccessModeSharingEnum::NONE => "none",
            ClusterVolumeSpecAccessModeSharingEnum::READONLY => "readonly",
            ClusterVolumeSpecAccessModeSharingEnum::ONEWRITER => "onewriter",
            ClusterVolumeSpecAccessModeSharingEnum::ALL => "all",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ClusterVolumeSpecAccessModeAvailabilityEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "active")]
    ACTIVE,
    #[serde(rename = "pause")]
    PAUSE,
    #[serde(rename = "drain")]
    DRAIN,
}

impl ::std::fmt::Display for ClusterVolumeSpecAccessModeAvailabilityEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ClusterVolumeSpecAccessModeAvailabilityEnum::EMPTY => write!(f, ""),
            ClusterVolumeSpecAccessModeAvailabilityEnum::ACTIVE => write!(f, "{}", "active"),
            ClusterVolumeSpecAccessModeAvailabilityEnum::PAUSE => write!(f, "{}", "pause"),
            ClusterVolumeSpecAccessModeAvailabilityEnum::DRAIN => write!(f, "{}", "drain"),

        }
    }
}

impl ::std::str::FromStr for ClusterVolumeSpecAccessModeAvailabilityEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ClusterVolumeSpecAccessModeAvailabilityEnum::EMPTY),
            "active" => Ok(ClusterVolumeSpecAccessModeAvailabilityEnum::ACTIVE),
            "pause" => Ok(ClusterVolumeSpecAccessModeAvailabilityEnum::PAUSE),
            "drain" => Ok(ClusterVolumeSpecAccessModeAvailabilityEnum::DRAIN),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ClusterVolumeSpecAccessModeAvailabilityEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ClusterVolumeSpecAccessModeAvailabilityEnum::EMPTY => "",
            ClusterVolumeSpecAccessModeAvailabilityEnum::ACTIVE => "active",
            ClusterVolumeSpecAccessModeAvailabilityEnum::PAUSE => "pause",
            ClusterVolumeSpecAccessModeAvailabilityEnum::DRAIN => "drain",
        }
    }
}

/// Requirements for the accessible topology of the volume. These fields are optional. For an in-depth description of what these fields mean, see the CSI specification. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeSpecAccessModeAccessibilityRequirements {
    /// A list of required topologies, at least one of which the volume must be accessible from. 
    #[serde(rename = "Requisite")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub requisite: Option<Vec<Topology>>,

    /// A list of topologies that the volume should attempt to be provisioned in. 
    #[serde(rename = "Preferred")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferred: Option<Vec<Topology>>,

}

/// The desired capacity that the volume should be created with. If empty, the plugin will decide the capacity. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeSpecAccessModeCapacityRange {
    /// The volume must be at least this big. The value of 0 indicates an unspecified minimum 
    #[serde(rename = "RequiredBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub required_bytes: Option<i64>,

    /// The volume must not be bigger than this. The value of 0 indicates an unspecified maximum. 
    #[serde(rename = "LimitBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit_bytes: Option<i64>,

}

/// One cluster volume secret entry. Defines a key-value pair that is passed to the plugin. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ClusterVolumeSpecAccessModeSecrets {
    /// Key is the name of the key of the key-value pair passed to the plugin. 
    #[serde(rename = "Key")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key: Option<String>,

    /// Secret is the swarm Secret object from which to read data. This can be a Secret name or ID. The Secret data is retrieved by swarm and used as the value of the key-value pair passed to the plugin. 
    #[serde(rename = "Secret")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret: Option<String>,

}

/// Commit holds the Git-commit (SHA1) that a binary was built from, as reported in the version-string of external tools, such as `containerd`, or `runC`. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Commit {
    /// Actual commit ID of external tool.
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Config {
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<ConfigSpec>,

}

/// The config-only network source to provide the configuration for this network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConfigReference {
    /// The name of the config-only network that provides the network's configuration. The specified network must be an existing config-only network. Only network names are allowed, not network IDs. 
    #[serde(rename = "Network")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ConfigSpec {
    /// User-defined name of the config.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Data is the data to store as a config, formatted as a Base64-url-safe-encoded ([RFC 4648](https://tools.ietf.org/html/rfc4648#section-5)) string. The maximum allowed size is 1000KB, as defined in [MaxConfigSize](https://pkg.go.dev/github.com/moby/swarmkit/v2@v2.0.0-20250103191802-8c1959736554/manager/controlapi#MaxConfigSize). 
    #[serde(rename = "Data")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// Templating driver, if applicable  Templating controls whether and how to evaluate the config payload as a template. If no driver is set, no templating is used. 
    #[serde(rename = "Templating")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templating: Option<Driver>,

}

/// Blkio stats entry.  This type is Linux-specific and omitted for Windows containers. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerBlkioStatEntry {
    #[serde(rename = "major")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub major: Option<u64>,

    #[serde(rename = "minor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub minor: Option<u64>,

    #[serde(rename = "op")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub op: Option<String>,

    #[serde(rename = "value")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<u64>,

}

/// BlkioStats stores all IO service stats for data read and write.  This type is Linux-specific and holds many fields that are specific to cgroups v1. On a cgroup v2 host, all fields other than `io_service_bytes_recursive` are omitted or `null`.  This type is only populated on Linux and omitted for Windows containers. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerBlkioStats {
    #[serde(rename = "io_service_bytes_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_service_bytes_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_serviced_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_serviced_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_queue_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_queue_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_service_time_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_service_time_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_wait_time_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_wait_time_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_merged_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_merged_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "io_time_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_time_recursive: Option<Vec<ContainerBlkioStatEntry>>,

    /// This field is only available when using Linux containers with cgroups v1. It is omitted or `null` when using cgroups v2. 
    #[serde(rename = "sectors_recursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sectors_recursive: Option<Vec<ContainerBlkioStatEntry>>,

}

/// Configuration for a container that is portable between hosts. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerConfig {
    /// The hostname to use for the container, as a valid RFC 1123 hostname. 
    #[serde(rename = "Hostname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// The domain name to use for the container. 
    #[serde(rename = "Domainname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,

    /// Commands run as this user inside the container. If omitted, commands run as the user specified in the image the container was started from.  Can be either user-name or UID, and optional group-name or GID, separated by a colon (`<user-name|UID>[<:group-name|GID>]`).
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Whether to attach to `stdin`.
    #[serde(rename = "AttachStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdin: Option<bool>,

    /// Whether to attach to `stdout`.
    #[serde(rename = "AttachStdout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdout: Option<bool>,

    /// Whether to attach to `stderr`.
    #[serde(rename = "AttachStderr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stderr: Option<bool>,

    /// An object mapping ports to an empty object in the form:  `{\"<port>/<tcp|udp|sctp>\": {}}` 
    #[serde(rename = "ExposedPorts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub exposed_ports: Option<Vec<String>>,

    /// Attach standard streams to a TTY, including `stdin` if it is not closed. 
    #[serde(rename = "Tty")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// Open `stdin`
    #[serde(rename = "OpenStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdin: Option<bool>,

    /// Close `stdin` after one attached client disconnects
    #[serde(rename = "StdinOnce")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_once: Option<bool>,

    /// A list of environment variables to set inside the container in the form `[\"VAR=value\", ...]`. A variable without `=` is removed from the environment, rather than to have an empty value. 
    #[serde(rename = "Env")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// Command to run specified as a string or an array of strings. 
    #[serde(rename = "Cmd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    #[serde(rename = "Healthcheck")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthConfig>,

    /// Command is already escaped (Windows only)
    #[serde(rename = "ArgsEscaped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_escaped: Option<bool>,

    /// The name (or reference) of the image to use when creating the container, or which was used when the container was created. 
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// An object mapping mount point paths inside the container to empty objects. 
    #[serde(rename = "Volumes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub volumes: Option<Vec<String>>,

    /// The working directory for commands to run in.
    #[serde(rename = "WorkingDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// The entry point for the container as a string or an array of strings.  If the array consists of exactly one empty string (`[\"\"]`) then the entry point is reset to system default (i.e., the entry point used by docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`). 
    #[serde(rename = "Entrypoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,

    /// Disable networking for the container.
    #[serde(rename = "NetworkDisabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_disabled: Option<bool>,

    /// `ONBUILD` metadata that were defined in the image's `Dockerfile`. 
    #[serde(rename = "OnBuild")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_build: Option<Vec<String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Signal to stop a container as a string or unsigned integer. 
    #[serde(rename = "StopSignal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,

    /// Timeout to stop a container in seconds.
    #[serde(rename = "StopTimeout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_timeout: Option<i64>,

    /// Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. 
    #[serde(rename = "Shell")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<Vec<String>>,

}

/// CPU related info of the container 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerCpuStats {
    #[serde(rename = "cpu_usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_usage: Option<ContainerCpuUsage>,

    /// System Usage.  This field is Linux-specific and omitted for Windows containers. 
    #[serde(rename = "system_cpu_usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_cpu_usage: Option<u64>,

    /// Number of online CPUs.  This field is Linux-specific and omitted for Windows containers. 
    #[serde(rename = "online_cpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub online_cpus: Option<u32>,

    #[serde(rename = "throttling_data")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttling_data: Option<ContainerThrottlingData>,

}

/// All CPU stats aggregated since container inception. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerCpuUsage {
    /// Total CPU time consumed in nanoseconds (Linux) or 100's of nanoseconds (Windows). 
    #[serde(rename = "total_usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_usage: Option<u64>,

    /// Total CPU time (in nanoseconds) consumed per core (Linux).  This field is Linux-specific when using cgroups v1. It is omitted when using cgroups v2 and Windows containers. 
    #[serde(rename = "percpu_usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub percpu_usage: Option<Vec<u64>>,

    /// Time (in nanoseconds) spent by tasks of the cgroup in kernel mode (Linux), or time spent (in 100's of nanoseconds) by all container processes in kernel mode (Windows).  Not populated for Windows containers using Hyper-V isolation. 
    #[serde(rename = "usage_in_kernelmode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_in_kernelmode: Option<u64>,

    /// Time (in nanoseconds) spent by tasks of the cgroup in user mode (Linux), or time spent (in 100's of nanoseconds) by all container processes in kernel mode (Windows).  Not populated for Windows containers using Hyper-V isolation. 
    #[serde(rename = "usage_in_usermode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_in_usermode: Option<u64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerCreateBody {
    /// The hostname to use for the container, as a valid RFC 1123 hostname. 
    #[serde(rename = "Hostname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// The domain name to use for the container. 
    #[serde(rename = "Domainname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub domainname: Option<String>,

    /// Commands run as this user inside the container. If omitted, commands run as the user specified in the image the container was started from.  Can be either user-name or UID, and optional group-name or GID, separated by a colon (`<user-name|UID>[<:group-name|GID>]`).
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// Whether to attach to `stdin`.
    #[serde(rename = "AttachStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdin: Option<bool>,

    /// Whether to attach to `stdout`.
    #[serde(rename = "AttachStdout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdout: Option<bool>,

    /// Whether to attach to `stderr`.
    #[serde(rename = "AttachStderr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stderr: Option<bool>,

    /// An object mapping ports to an empty object in the form:  `{\"<port>/<tcp|udp|sctp>\": {}}` 
    #[serde(rename = "ExposedPorts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub exposed_ports: Option<Vec<String>>,

    /// Attach standard streams to a TTY, including `stdin` if it is not closed. 
    #[serde(rename = "Tty")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// Open `stdin`
    #[serde(rename = "OpenStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdin: Option<bool>,

    /// Close `stdin` after one attached client disconnects
    #[serde(rename = "StdinOnce")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stdin_once: Option<bool>,

    /// A list of environment variables to set inside the container in the form `[\"VAR=value\", ...]`. A variable without `=` is removed from the environment, rather than to have an empty value. 
    #[serde(rename = "Env")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// Command to run specified as a string or an array of strings. 
    #[serde(rename = "Cmd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    #[serde(rename = "Healthcheck")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthConfig>,

    /// Command is already escaped (Windows only)
    #[serde(rename = "ArgsEscaped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_escaped: Option<bool>,

    /// The name (or reference) of the image to use when creating the container, or which was used when the container was created. 
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// An object mapping mount point paths inside the container to empty objects. 
    #[serde(rename = "Volumes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub volumes: Option<Vec<String>>,

    /// The working directory for commands to run in.
    #[serde(rename = "WorkingDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// The entry point for the container as a string or an array of strings.  If the array consists of exactly one empty string (`[\"\"]`) then the entry point is reset to system default (i.e., the entry point used by docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`). 
    #[serde(rename = "Entrypoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,

    /// Disable networking for the container.
    #[serde(rename = "NetworkDisabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_disabled: Option<bool>,

    /// `ONBUILD` metadata that were defined in the image's `Dockerfile`. 
    #[serde(rename = "OnBuild")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_build: Option<Vec<String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Signal to stop a container as a string or unsigned integer. 
    #[serde(rename = "StopSignal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,

    /// Timeout to stop a container in seconds.
    #[serde(rename = "StopTimeout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_timeout: Option<i64>,

    /// Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. 
    #[serde(rename = "Shell")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<Vec<String>>,

    #[serde(rename = "HostConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<HostConfig>,

    #[serde(rename = "NetworkingConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networking_config: Option<NetworkingConfig>,

}

/// OK response to ContainerCreate operation
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerCreateResponse {
    /// The ID of the created container
    #[serde(rename = "Id")]
    pub id: String,

    /// Warnings encountered when creating the container
    #[serde(rename = "Warnings")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub warnings: Vec<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerInspectResponse {
    /// The ID of this container as a 128-bit (64-character) hexadecimal string (32 bytes).
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Date and time at which the container was created, formatted in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created: Option<BollardDate>,

    /// The path to the command being run
    #[serde(rename = "Path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// The arguments to the command being run
    #[serde(rename = "Args")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ContainerState>,

    /// The ID (digest) of the image that this container was created from.
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// Location of the `/etc/resolv.conf` generated for the container on the host.  This file is managed through the docker daemon, and should not be accessed or modified by other tools.
    #[serde(rename = "ResolvConfPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resolv_conf_path: Option<String>,

    /// Location of the `/etc/hostname` generated for the container on the host.  This file is managed through the docker daemon, and should not be accessed or modified by other tools.
    #[serde(rename = "HostnamePath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname_path: Option<String>,

    /// Location of the `/etc/hosts` generated for the container on the host.  This file is managed through the docker daemon, and should not be accessed or modified by other tools.
    #[serde(rename = "HostsPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts_path: Option<String>,

    /// Location of the file used to buffer the container's logs. Depending on the logging-driver used for the container, this field may be omitted.  This file is managed through the docker daemon, and should not be accessed or modified by other tools.
    #[serde(rename = "LogPath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_path: Option<String>,

    /// The name associated with this container.  For historic reasons, the name may be prefixed with a forward-slash (`/`).
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Number of times the container was restarted since it was created, or since daemon was started.
    #[serde(rename = "RestartCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_count: Option<i64>,

    /// The storage-driver used for the container's filesystem (graph-driver or snapshotter).
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// The platform (operating system) for which the container was created.  This field was introduced for the experimental \"LCOW\" (Linux Containers On Windows) features, which has been removed. In most cases, this field is equal to the host's operating system (`linux` or `windows`).
    #[serde(rename = "Platform")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<String>,

    /// OCI descriptor of the platform-specific manifest of the image the container was created from.  Note: Only available if the daemon provides a multi-platform image store.
    #[serde(rename = "ImageManifestDescriptor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_manifest_descriptor: Option<OciDescriptor>,

    /// SELinux mount label set for the container.
    #[serde(rename = "MountLabel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mount_label: Option<String>,

    /// SELinux process label set for the container.
    #[serde(rename = "ProcessLabel")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_label: Option<String>,

    /// The AppArmor profile set for the container.
    #[serde(rename = "AppArmorProfile")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_armor_profile: Option<String>,

    /// IDs of exec instances that are running in the container.
    #[serde(rename = "ExecIDs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exec_ids: Option<Vec<String>>,

    #[serde(rename = "HostConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<HostConfig>,

    #[serde(rename = "GraphDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_driver: Option<DriverData>,

    #[serde(rename = "Storage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage: Option<Storage>,

    /// The size of files that have been created or changed by this container.  This field is omitted by default, and only set when size is requested in the API request.
    #[serde(rename = "SizeRw")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_rw: Option<i64>,

    /// The total size of all files in the read-only layers from the image that the container uses. These layers can be shared between containers.  This field is omitted by default, and only set when size is requested in the API request.
    #[serde(rename = "SizeRootFs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_root_fs: Option<i64>,

    /// List of mounts used by the container.
    #[serde(rename = "Mounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountPoint>>,

    #[serde(rename = "Config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ContainerConfig>,

    #[serde(rename = "NetworkSettings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_settings: Option<NetworkSettings>,

}

/// Aggregates all memory stats since container inception on Linux. Windows returns stats for commit and private working set only. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerMemoryStats {
    /// Current `res_counter` usage for memory.  This field is Linux-specific and omitted for Windows containers. 
    #[serde(rename = "usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage: Option<u64>,

    /// Maximum usage ever recorded.  This field is Linux-specific and only supported on cgroups v1. It is omitted when using cgroups v2 and for Windows containers. 
    #[serde(rename = "max_usage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_usage: Option<u64>,

    /// All the stats exported via memory.stat. when using cgroups v2.  This field is Linux-specific and omitted for Windows containers. 
    #[serde(rename = "stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stats: Option<HashMap<String, u64>>,

    /// Number of times memory usage hits limits.  This field is Linux-specific and only supported on cgroups v1. It is omitted when using cgroups v2 and for Windows containers. 
    #[serde(rename = "failcnt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failcnt: Option<u64>,

    /// This field is Linux-specific and omitted for Windows containers. 
    #[serde(rename = "limit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,

    /// Committed bytes.  This field is Windows-specific and omitted for Linux containers. 
    #[serde(rename = "commitbytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitbytes: Option<u64>,

    /// Peak committed bytes.  This field is Windows-specific and omitted for Linux containers. 
    #[serde(rename = "commitpeakbytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub commitpeakbytes: Option<u64>,

    /// Private working set.  This field is Windows-specific and omitted for Linux containers. 
    #[serde(rename = "privateworkingset")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privateworkingset: Option<u64>,

}

/// Aggregates the network stats of one container 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerNetworkStats {
    /// Bytes received. Windows and Linux. 
    #[serde(rename = "rx_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,

    /// Packets received. Windows and Linux. 
    #[serde(rename = "rx_packets")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_packets: Option<u64>,

    /// Received errors. Not used on Windows.  This field is Linux-specific and always zero for Windows containers. 
    #[serde(rename = "rx_errors")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_errors: Option<u64>,

    /// Incoming packets dropped. Windows and Linux. 
    #[serde(rename = "rx_dropped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_dropped: Option<u64>,

    /// Bytes sent. Windows and Linux. 
    #[serde(rename = "tx_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,

    /// Packets sent. Windows and Linux. 
    #[serde(rename = "tx_packets")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_packets: Option<u64>,

    /// Sent errors. Not used on Windows.  This field is Linux-specific and always zero for Windows containers. 
    #[serde(rename = "tx_errors")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_errors: Option<u64>,

    /// Outgoing packets dropped. Windows and Linux. 
    #[serde(rename = "tx_dropped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_dropped: Option<u64>,

    /// Endpoint ID. Not used on Linux.  This field is Windows-specific and omitted for Linux containers. 
    #[serde(rename = "endpoint_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    /// Instance ID. Not used on Linux.  This field is Windows-specific and omitted for Linux containers. 
    #[serde(rename = "instance_id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance_id: Option<String>,

}

/// PidsStats contains Linux-specific stats of a container's process-IDs (PIDs).  This type is Linux-specific and omitted for Windows containers. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerPidsStats {
    /// Current is the number of PIDs in the cgroup. 
    #[serde(rename = "current")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<u64>,

    /// Limit is the hard limit on the number of pids in the cgroup. A \"Limit\" of 0 means that there is no limit. 
    #[serde(rename = "limit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limit: Option<u64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerPruneResponse {
    /// Container IDs that were deleted
    #[serde(rename = "ContainersDeleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_deleted: Option<Vec<String>>,

    /// Disk space reclaimed in bytes
    #[serde(rename = "SpaceReclaimed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_reclaimed: Option<i64>,

}

/// ContainerState stores container's running state. It's part of ContainerJSONBase and will be returned by the \"inspect\" command. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerState {
    /// String representation of the container state. Can be one of \"created\", \"running\", \"paused\", \"restarting\", \"removing\", \"exited\", or \"dead\". 
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ContainerStateStatusEnum>,

    /// Whether this container is running.  Note that a running container can be _paused_. The `Running` and `Paused` booleans are not mutually exclusive:  When pausing a container (on Linux), the freezer cgroup is used to suspend all processes in the container. Freezing the process requires the process to be running. As a result, paused containers are both `Running` _and_ `Paused`.  Use the `Status` field instead to determine if a container's state is \"running\". 
    #[serde(rename = "Running")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,

    /// Whether this container is paused.
    #[serde(rename = "Paused")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub paused: Option<bool>,

    /// Whether this container is restarting.
    #[serde(rename = "Restarting")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restarting: Option<bool>,

    /// Whether a process within this container has been killed because it ran out of memory since the container was last started. 
    #[serde(rename = "OOMKilled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_killed: Option<bool>,

    #[serde(rename = "Dead")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dead: Option<bool>,

    /// The process ID of this container
    #[serde(rename = "Pid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,

    /// The last exit code of this container
    #[serde(rename = "ExitCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,

    #[serde(rename = "Error")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// The time when this container was last started.
    #[serde(rename = "StartedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub started_at: Option<String>,

    /// The time when this container last exited.
    #[serde(rename = "FinishedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_at: Option<String>,

    #[serde(rename = "Health")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<Health>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ContainerStateStatusEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "created")]
    CREATED,
    #[serde(rename = "running")]
    RUNNING,
    #[serde(rename = "paused")]
    PAUSED,
    #[serde(rename = "restarting")]
    RESTARTING,
    #[serde(rename = "removing")]
    REMOVING,
    #[serde(rename = "exited")]
    EXITED,
    #[serde(rename = "dead")]
    DEAD,
}

impl ::std::fmt::Display for ContainerStateStatusEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ContainerStateStatusEnum::EMPTY => write!(f, ""),
            ContainerStateStatusEnum::CREATED => write!(f, "{}", "created"),
            ContainerStateStatusEnum::RUNNING => write!(f, "{}", "running"),
            ContainerStateStatusEnum::PAUSED => write!(f, "{}", "paused"),
            ContainerStateStatusEnum::RESTARTING => write!(f, "{}", "restarting"),
            ContainerStateStatusEnum::REMOVING => write!(f, "{}", "removing"),
            ContainerStateStatusEnum::EXITED => write!(f, "{}", "exited"),
            ContainerStateStatusEnum::DEAD => write!(f, "{}", "dead"),

        }
    }
}

impl ::std::str::FromStr for ContainerStateStatusEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ContainerStateStatusEnum::EMPTY),
            "created" => Ok(ContainerStateStatusEnum::CREATED),
            "running" => Ok(ContainerStateStatusEnum::RUNNING),
            "paused" => Ok(ContainerStateStatusEnum::PAUSED),
            "restarting" => Ok(ContainerStateStatusEnum::RESTARTING),
            "removing" => Ok(ContainerStateStatusEnum::REMOVING),
            "exited" => Ok(ContainerStateStatusEnum::EXITED),
            "dead" => Ok(ContainerStateStatusEnum::DEAD),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ContainerStateStatusEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ContainerStateStatusEnum::EMPTY => "",
            ContainerStateStatusEnum::CREATED => "created",
            ContainerStateStatusEnum::RUNNING => "running",
            ContainerStateStatusEnum::PAUSED => "paused",
            ContainerStateStatusEnum::RESTARTING => "restarting",
            ContainerStateStatusEnum::REMOVING => "removing",
            ContainerStateStatusEnum::EXITED => "exited",
            ContainerStateStatusEnum::DEAD => "dead",
        }
    }
}

/// Statistics sample for a container. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerStatsResponse {
    /// ID of the container for which the stats were collected. 
    #[serde(rename = "id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Name of the container for which the stats were collected. 
    #[serde(rename = "name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// OSType is the OS of the container (\"linux\" or \"windows\") to allow platform-specific handling of stats. 
    #[serde(rename = "os_type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,

    /// Date and time at which this sample was collected. The value is formatted as [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) with nano-seconds. 
    #[serde(rename = "read")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub read: Option<BollardDate>,

    #[serde(rename = "cpu_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_stats: Option<ContainerCpuStats>,

    #[serde(rename = "memory_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_stats: Option<ContainerMemoryStats>,

    /// Network statistics for the container per interface.  This field is omitted if the container has no networking enabled. 
    #[serde(rename = "networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<HashMap<String, ContainerNetworkStats>>,

    #[serde(rename = "pids_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_stats: Option<ContainerPidsStats>,

    #[serde(rename = "blkio_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_stats: Option<ContainerBlkioStats>,

    /// The number of processors on the system.  This field is Windows-specific and always zero for Linux containers. 
    #[serde(rename = "num_procs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub num_procs: Option<u32>,

    #[serde(rename = "storage_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_stats: Option<ContainerStorageStats>,

    /// Date and time at which this first sample was collected. This field is not propagated if the \"one-shot\" option is set. If the \"one-shot\" option is set, this field may be omitted, empty, or set to a default date (`0001-01-01T00:00:00Z`).  The value is formatted as [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) with nano-seconds. 
    #[serde(rename = "preread")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub preread: Option<BollardDate>,

    #[serde(rename = "precpu_stats")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub precpu_stats: Option<ContainerCpuStats>,

}

/// represents the status of a container.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerStatus {
    #[serde(rename = "ContainerID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    #[serde(rename = "PID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,

    #[serde(rename = "ExitCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,

}

/// StorageStats is the disk I/O stats for read/write on Windows.  This type is Windows-specific and omitted for Linux containers. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerStorageStats {
    #[serde(rename = "read_count_normalized")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_count_normalized: Option<u64>,

    #[serde(rename = "read_size_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_size_bytes: Option<u64>,

    #[serde(rename = "write_count_normalized")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_count_normalized: Option<u64>,

    #[serde(rename = "write_size_bytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub write_size_bytes: Option<u64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummary {
    /// The ID of this container as a 128-bit (64-character) hexadecimal string (32 bytes).
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// The names associated with this container. Most containers have a single name, but when using legacy \"links\", the container can have multiple names.  For historic reasons, names are prefixed with a forward-slash (`/`).
    #[serde(rename = "Names")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub names: Option<Vec<String>>,

    /// The name or ID of the image used to create the container.  This field shows the image reference as was specified when creating the container, which can be in its canonical form (e.g., `docker.io/library/ubuntu:latest` or `docker.io/library/ubuntu@sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782`), short form (e.g., `ubuntu:latest`)), or the ID(-prefix) of the image (e.g., `72297848456d`).  The content of this field can be updated at runtime if the image used to create the container is untagged, in which case the field is updated to contain the the image ID (digest) it was resolved to in its canonical, non-truncated form (e.g., `sha256:72297848456d5d37d1262630108ab308d3e9ec7ed1c3286a32fe09856619a782`).
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// The ID (digest) of the image that this container was created from.
    #[serde(rename = "ImageID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_id: Option<String>,

    /// OCI descriptor of the platform-specific manifest of the image the container was created from.  Note: Only available if the daemon provides a multi-platform image store.  This field is not populated in the `GET /system/df` endpoint. 
    #[serde(rename = "ImageManifestDescriptor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_manifest_descriptor: Option<OciDescriptor>,

    /// Command to run when starting the container
    #[serde(rename = "Command")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<String>,

    /// Date and time at which the container was created as a Unix timestamp (number of seconds since EPOCH).
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub created: Option<i64>,

    /// Port-mappings for the container.
    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<PortSummary>>,

    /// The size of files that have been created or changed by this container.  This field is omitted by default, and only set when size is requested in the API request.
    #[serde(rename = "SizeRw")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_rw: Option<i64>,

    /// The total size of all files in the read-only layers from the image that the container uses. These layers can be shared between containers.  This field is omitted by default, and only set when size is requested in the API request.
    #[serde(rename = "SizeRootFs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_root_fs: Option<i64>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// The state of this container. 
    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ContainerSummaryStateEnum>,

    /// Additional human-readable status of this container (e.g. `Exit 0`)
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "HostConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_config: Option<ContainerSummaryHostConfig>,

    #[serde(rename = "NetworkSettings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_settings: Option<ContainerSummaryNetworkSettings>,

    /// List of mounts used by the container.
    #[serde(rename = "Mounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<MountPoint>>,

    #[serde(rename = "Health")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health: Option<ContainerSummaryHealth>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ContainerSummaryStateEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "created")]
    CREATED,
    #[serde(rename = "running")]
    RUNNING,
    #[serde(rename = "paused")]
    PAUSED,
    #[serde(rename = "restarting")]
    RESTARTING,
    #[serde(rename = "exited")]
    EXITED,
    #[serde(rename = "removing")]
    REMOVING,
    #[serde(rename = "dead")]
    DEAD,
}

impl ::std::fmt::Display for ContainerSummaryStateEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ContainerSummaryStateEnum::EMPTY => write!(f, ""),
            ContainerSummaryStateEnum::CREATED => write!(f, "{}", "created"),
            ContainerSummaryStateEnum::RUNNING => write!(f, "{}", "running"),
            ContainerSummaryStateEnum::PAUSED => write!(f, "{}", "paused"),
            ContainerSummaryStateEnum::RESTARTING => write!(f, "{}", "restarting"),
            ContainerSummaryStateEnum::EXITED => write!(f, "{}", "exited"),
            ContainerSummaryStateEnum::REMOVING => write!(f, "{}", "removing"),
            ContainerSummaryStateEnum::DEAD => write!(f, "{}", "dead"),

        }
    }
}

impl ::std::str::FromStr for ContainerSummaryStateEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ContainerSummaryStateEnum::EMPTY),
            "created" => Ok(ContainerSummaryStateEnum::CREATED),
            "running" => Ok(ContainerSummaryStateEnum::RUNNING),
            "paused" => Ok(ContainerSummaryStateEnum::PAUSED),
            "restarting" => Ok(ContainerSummaryStateEnum::RESTARTING),
            "exited" => Ok(ContainerSummaryStateEnum::EXITED),
            "removing" => Ok(ContainerSummaryStateEnum::REMOVING),
            "dead" => Ok(ContainerSummaryStateEnum::DEAD),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ContainerSummaryStateEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ContainerSummaryStateEnum::EMPTY => "",
            ContainerSummaryStateEnum::CREATED => "created",
            ContainerSummaryStateEnum::RUNNING => "running",
            ContainerSummaryStateEnum::PAUSED => "paused",
            ContainerSummaryStateEnum::RESTARTING => "restarting",
            ContainerSummaryStateEnum::EXITED => "exited",
            ContainerSummaryStateEnum::REMOVING => "removing",
            ContainerSummaryStateEnum::DEAD => "dead",
        }
    }
}

/// Summary of health status  Added in v1.52, before that version all container summary not include Health. After this attribute introduced, it includes containers with no health checks configured, or containers that are not running with none
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummaryHealth {
    /// the health status of the container
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<ContainerSummaryHealthStatusEnum>,

    /// FailingStreak is the number of consecutive failures
    #[serde(rename = "FailingStreak")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_streak: Option<i64>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ContainerSummaryHealthStatusEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "none")]
    NONE,
    #[serde(rename = "starting")]
    STARTING,
    #[serde(rename = "healthy")]
    HEALTHY,
    #[serde(rename = "unhealthy")]
    UNHEALTHY,
}

impl ::std::fmt::Display for ContainerSummaryHealthStatusEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ContainerSummaryHealthStatusEnum::EMPTY => write!(f, ""),
            ContainerSummaryHealthStatusEnum::NONE => write!(f, "{}", "none"),
            ContainerSummaryHealthStatusEnum::STARTING => write!(f, "{}", "starting"),
            ContainerSummaryHealthStatusEnum::HEALTHY => write!(f, "{}", "healthy"),
            ContainerSummaryHealthStatusEnum::UNHEALTHY => write!(f, "{}", "unhealthy"),

        }
    }
}

impl ::std::str::FromStr for ContainerSummaryHealthStatusEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ContainerSummaryHealthStatusEnum::EMPTY),
            "none" => Ok(ContainerSummaryHealthStatusEnum::NONE),
            "starting" => Ok(ContainerSummaryHealthStatusEnum::STARTING),
            "healthy" => Ok(ContainerSummaryHealthStatusEnum::HEALTHY),
            "unhealthy" => Ok(ContainerSummaryHealthStatusEnum::UNHEALTHY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ContainerSummaryHealthStatusEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ContainerSummaryHealthStatusEnum::EMPTY => "",
            ContainerSummaryHealthStatusEnum::NONE => "none",
            ContainerSummaryHealthStatusEnum::STARTING => "starting",
            ContainerSummaryHealthStatusEnum::HEALTHY => "healthy",
            ContainerSummaryHealthStatusEnum::UNHEALTHY => "unhealthy",
        }
    }
}

/// Summary of host-specific runtime information of the container. This is a reduced set of information in the container's \"HostConfig\" as available in the container \"inspect\" response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummaryHostConfig {
    /// Networking mode (`host`, `none`, `container:<id>`) or name of the primary network the container is using.  This field is primarily for backward compatibility. The container can be connected to multiple networks for which information can be found in the `NetworkSettings.Networks` field, which enumerates settings per network.
    #[serde(rename = "NetworkMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,

    /// Arbitrary key-value metadata attached to the container.
    #[serde(rename = "Annotations")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,

}

/// Summary of the container's network settings
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerSummaryNetworkSettings {
    /// Summary of network-settings for each network the container is attached to.
    #[serde(rename = "Networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<HashMap<String, EndpointSettings>>,

}

/// CPU throttling stats of the container.  This type is Linux-specific and omitted for Windows containers. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerThrottlingData {
    /// Number of periods with throttling active. 
    #[serde(rename = "periods")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub periods: Option<u64>,

    /// Number of periods when the container hit its throttling limit. 
    #[serde(rename = "throttled_periods")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttled_periods: Option<u64>,

    /// Aggregated time (in nanoseconds) the container was throttled for. 
    #[serde(rename = "throttled_time")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub throttled_time: Option<u64>,

}

/// Container \"top\" response.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerTopResponse {
    /// The ps column titles
    #[serde(rename = "Titles")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub titles: Option<Vec<String>>,

    /// Each process running in the container, where each process is an array of values corresponding to the titles.
    #[serde(rename = "Processes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub processes: Option<Vec<Vec<String>>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerUpdateBody {
    /// An integer value representing this container's relative CPU weight versus other containers. 
    #[serde(rename = "CpuShares")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<i64>,

    /// Memory limit in bytes.
    #[serde(rename = "Memory")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,

    /// Path to `cgroups` under which the container's `cgroup` is created. If the path is not absolute, the path is considered to be relative to the `cgroups` path of the init process. Cgroups are created if they do not already exist. 
    #[serde(rename = "CgroupParent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,

    /// Block IO weight (relative weight).
    #[serde(rename = "BlkioWeight")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight: Option<u16>,

    /// Block IO weight (relative device weight) in the form:  ``` [{\"Path\": \"device_path\", \"Weight\": weight}] ``` 
    #[serde(rename = "BlkioWeightDevice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight_device: Option<Vec<ResourcesBlkioWeightDevice>>,

    /// Limit read rate (bytes per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_bps: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (bytes per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_bps: Option<Vec<ThrottleDevice>>,

    /// Limit read rate (IO per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_iops: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (IO per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_iops: Option<Vec<ThrottleDevice>>,

    /// The length of a CPU period in microseconds.
    #[serde(rename = "CpuPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<i64>,

    /// Microseconds of CPU time that the container can get in a CPU period. 
    #[serde(rename = "CpuQuota")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,

    /// The length of a CPU real-time period in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimePeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_period: Option<i64>,

    /// The length of a CPU real-time runtime in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimeRuntime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_runtime: Option<i64>,

    /// CPUs in which to allow execution (e.g., `0-3`, `0,1`). 
    #[serde(rename = "CpusetCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_cpus: Option<String>,

    /// Memory nodes (MEMs) in which to allow execution (0-3, 0,1). Only effective on NUMA systems. 
    #[serde(rename = "CpusetMems")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_mems: Option<String>,

    /// A list of devices to add to the container.
    #[serde(rename = "Devices")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<DeviceMapping>>,

    /// a list of cgroup rules to apply to the container
    #[serde(rename = "DeviceCgroupRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_cgroup_rules: Option<Vec<String>>,

    /// A list of requests for devices to be sent to device drivers. 
    #[serde(rename = "DeviceRequests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_requests: Option<Vec<DeviceRequest>>,

    /// Memory soft limit in bytes.
    #[serde(rename = "MemoryReservation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_reservation: Option<i64>,

    /// Total memory limit (memory + swap). Set as `-1` to enable unlimited swap. 
    #[serde(rename = "MemorySwap")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swap: Option<i64>,

    /// Tune a container's memory swappiness behavior. Accepts an integer between 0 and 100. 
    #[serde(rename = "MemorySwappiness")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swappiness: Option<i64>,

    /// CPU quota in units of 10<sup>-9</sup> CPUs.
    #[serde(rename = "NanoCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,

    /// Disable OOM Killer for the container.
    #[serde(rename = "OomKillDisable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill_disable: Option<bool>,

    /// Run an init inside the container that forwards signals and reaps processes. This field is omitted if empty, and the default (as configured on the daemon) is used. 
    #[serde(rename = "Init")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Tune a container's PIDs limit. Set `0` or `-1` for unlimited, or `null` to not change. 
    #[serde(rename = "PidsLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,

    /// A list of resource limits to set in the container. For example:  ``` {\"Name\": \"nofile\", \"Soft\": 1024, \"Hard\": 2048} ``` 
    #[serde(rename = "Ulimits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<Vec<ResourcesUlimits>>,

    /// The number of usable CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i64>,

    /// The usable percentage of the available CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuPercent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<i64>,

    /// Maximum IOps for the container system drive (Windows only)
    #[serde(rename = "IOMaximumIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_iops: Option<i64>,

    /// Maximum IO in bytes per second for the container system drive (Windows only). 
    #[serde(rename = "IOMaximumBandwidth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_bandwidth: Option<i64>,

    #[serde(rename = "RestartPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,

}

/// Response for a successful container-update.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerUpdateResponse {
    /// Warnings encountered when updating the container.
    #[serde(rename = "Warnings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

}

/// container waiting error, if any
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitExitError {
    /// Details of an error
    #[serde(rename = "Message")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

}

/// OK response to ContainerWait operation
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerWaitResponse {
    /// Exit code of the container
    #[serde(rename = "StatusCode")]
    pub status_code: i64,

    #[serde(rename = "Error")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<ContainerWaitExitError>,

}

/// Information for connecting to the containerd instance that is used by the daemon. This is included for debugging purposes only. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerdInfo {
    /// The address of the containerd socket.
    #[serde(rename = "Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub address: Option<String>,

    #[serde(rename = "Namespaces")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub namespaces: Option<ContainerdInfoNamespaces>,

}

/// The namespaces that the daemon uses for running containers and plugins in containerd. These namespaces can be configured in the daemon configuration, and are considered to be used exclusively by the daemon, Tampering with the containerd instance may cause unexpected behavior.  As these namespaces are considered to be exclusively accessed by the daemon, it is not recommended to change these values, or to change them to a value that is used by other systems, such as cri-containerd. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainerdInfoNamespaces {
    /// The default containerd namespace used for containers managed by the daemon.  The default namespace for containers is \"moby\", but will be suffixed with the `<uid>.<gid>` of the remapped `root` if user-namespaces are enabled and the containerd image-store is used. 
    #[serde(rename = "Containers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<String>,

    /// The default containerd namespace used for plugins managed by the daemon.  The default namespace for plugins is \"plugins.moby\", but will be suffixed with the `<uid>.<gid>` of the remapped `root` if user-namespaces are enabled and the containerd image-store is used. 
    #[serde(rename = "Plugins")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugins: Option<String>,

}

/// represents system data usage information for container resources. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ContainersDiskUsage {
    /// Count of active containers. 
    #[serde(rename = "ActiveCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_count: Option<i64>,

    /// Count of all containers. 
    #[serde(rename = "TotalCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,

    /// Disk space that can be reclaimed by removing inactive containers. 
    #[serde(rename = "Reclaimable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<i64>,

    /// Disk space in use by containers. 
    #[serde(rename = "TotalSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,

    /// List of container summaries. 
    #[serde(rename = "Items")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<serde_json::Value>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct CreateImageInfo {
    #[serde(rename = "id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "errorDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<ErrorDetail>,

    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "progressDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_detail: Option<ProgressDetail>,

}

/// DeviceInfo represents a device that can be used by a container. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceInfo {
    /// The origin device driver. 
    #[serde(rename = "Source")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// The unique identifier for the device within its source driver. For CDI devices, this would be an FQDN like \"vendor.com/gpu=0\". 
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

}

/// A device mapping between the host and container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceMapping {
    #[serde(rename = "PathOnHost")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_on_host: Option<String>,

    #[serde(rename = "PathInContainer")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path_in_container: Option<String>,

    #[serde(rename = "CgroupPermissions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_permissions: Option<String>,

}

/// A request for devices to be sent to device drivers
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DeviceRequest {
    /// The name of the device driver to use for this request.  Note that if this is specified the capabilities are ignored when selecting a device driver. 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    #[serde(rename = "Count")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub count: Option<i64>,

    #[serde(rename = "DeviceIDs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_ids: Option<Vec<String>>,

    /// A list of capabilities; an OR list of AND lists of capabilities.  Note that if a driver is specified the capabilities have no effect on selecting a driver as the driver name is used directly.  Note that if no driver is specified the capabilities are used to select a driver with the required capabilities. 
    #[serde(rename = "Capabilities")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capabilities: Option<Vec<Vec<String>>>,

    /// Driver-specific options, specified as a key/value pairs. These options are passed directly to the driver. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

/// Describes the result obtained from contacting the registry to retrieve image metadata. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DistributionInspect {
    #[serde(rename = "Descriptor")]
    pub descriptor: OciDescriptor,

    /// An array containing all platforms supported by the image. 
    #[serde(rename = "Platforms")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub platforms: Vec<OciPlatform>,

}

/// Driver represents a driver (network, logging, secrets).
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Driver {
    /// Name of the driver.
    #[serde(rename = "Name")]
    pub name: String,

    /// Key/value map of driver-specific options.
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

/// Information about the storage driver used to store the container's and image's filesystem. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct DriverData {
    /// Name of the storage driver.
    #[serde(rename = "Name")]
    pub name: String,

    /// Low-level storage metadata, provided as key/value pairs.  This information is driver-specific, and depends on the storage-driver in use, and should be used for informational purposes only. 
    #[serde(rename = "Data")]
    #[serde(deserialize_with = "deserialize_nonoptional_map")]
    pub data: HashMap<String, String>,

}

/// EndpointIPAMConfig represents an endpoint's IPAM configuration. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointIpamConfig {
    #[serde(rename = "IPv4Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,

    #[serde(rename = "IPv6Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,

    #[serde(rename = "LinkLocalIPs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub link_local_ips: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointPortConfig {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "Protocol")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<EndpointPortConfigProtocolEnum>,

    /// The port inside the container.
    #[serde(rename = "TargetPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target_port: Option<i64>,

    /// The port on the swarm hosts.
    #[serde(rename = "PublishedPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub published_port: Option<i64>,

    /// The mode in which port is published.  <p><br /></p>  - \"ingress\" makes the target port accessible on every node,   regardless of whether there is a task for the service running on   that node or not. - \"host\" bypasses the routing mesh and publish the port directly on   the swarm node where that service is running. 
    #[serde(rename = "PublishMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_mode: Option<EndpointPortConfigPublishModeEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum EndpointPortConfigProtocolEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "sctp")]
    SCTP,
}

impl ::std::fmt::Display for EndpointPortConfigProtocolEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            EndpointPortConfigProtocolEnum::EMPTY => write!(f, ""),
            EndpointPortConfigProtocolEnum::TCP => write!(f, "{}", "tcp"),
            EndpointPortConfigProtocolEnum::UDP => write!(f, "{}", "udp"),
            EndpointPortConfigProtocolEnum::SCTP => write!(f, "{}", "sctp"),

        }
    }
}

impl ::std::str::FromStr for EndpointPortConfigProtocolEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(EndpointPortConfigProtocolEnum::EMPTY),
            "tcp" => Ok(EndpointPortConfigProtocolEnum::TCP),
            "udp" => Ok(EndpointPortConfigProtocolEnum::UDP),
            "sctp" => Ok(EndpointPortConfigProtocolEnum::SCTP),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for EndpointPortConfigProtocolEnum {
    fn as_ref(&self) -> &str {
        match self { 
            EndpointPortConfigProtocolEnum::EMPTY => "",
            EndpointPortConfigProtocolEnum::TCP => "tcp",
            EndpointPortConfigProtocolEnum::UDP => "udp",
            EndpointPortConfigProtocolEnum::SCTP => "sctp",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum EndpointPortConfigPublishModeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "ingress")]
    INGRESS,
    #[serde(rename = "host")]
    HOST,
}

impl ::std::fmt::Display for EndpointPortConfigPublishModeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            EndpointPortConfigPublishModeEnum::EMPTY => write!(f, ""),
            EndpointPortConfigPublishModeEnum::INGRESS => write!(f, "{}", "ingress"),
            EndpointPortConfigPublishModeEnum::HOST => write!(f, "{}", "host"),

        }
    }
}

impl ::std::str::FromStr for EndpointPortConfigPublishModeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(EndpointPortConfigPublishModeEnum::EMPTY),
            "ingress" => Ok(EndpointPortConfigPublishModeEnum::INGRESS),
            "host" => Ok(EndpointPortConfigPublishModeEnum::HOST),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for EndpointPortConfigPublishModeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            EndpointPortConfigPublishModeEnum::EMPTY => "",
            EndpointPortConfigPublishModeEnum::INGRESS => "ingress",
            EndpointPortConfigPublishModeEnum::HOST => "host",
        }
    }
}

/// contains network resources allocated and used for a container in a network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointResource {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "EndpointID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    #[serde(rename = "MacAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,

    #[serde(rename = "IPv4Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_address: Option<String>,

    #[serde(rename = "IPv6Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_address: Option<String>,

}

/// Configuration for a network endpoint.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointSettings {
    #[serde(rename = "IPAMConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam_config: Option<EndpointIpamConfig>,

    #[serde(rename = "Links")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,

    /// MAC address for the endpoint on this network. The network driver might ignore this parameter. 
    #[serde(rename = "MacAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mac_address: Option<String>,

    #[serde(rename = "Aliases")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// DriverOpts is a mapping of driver options and values. These options are passed directly to the driver and are driver specific. 
    #[serde(rename = "DriverOpts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_opts: Option<HashMap<String, String>>,

    /// This property determines which endpoint will provide the default gateway for a container. The endpoint with the highest priority will be used. If multiple endpoints have the same priority, endpoints are lexicographically sorted based on their network name, and the one that sorts first is picked. 
    #[serde(rename = "GwPriority")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gw_priority: Option<i64>,

    /// Unique ID of the network. 
    #[serde(rename = "NetworkID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    /// Unique ID for the service endpoint in a Sandbox. 
    #[serde(rename = "EndpointID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    /// Gateway address for this network. 
    #[serde(rename = "Gateway")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,

    /// IPv4 address. 
    #[serde(rename = "IPAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_address: Option<String>,

    /// Mask length of the IPv4 address. 
    #[serde(rename = "IPPrefixLen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_prefix_len: Option<i64>,

    /// IPv6 gateway address. 
    #[serde(rename = "IPv6Gateway")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv6_gateway: Option<String>,

    /// Global IPv6 address. 
    #[serde(rename = "GlobalIPv6Address")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_ipv6_address: Option<String>,

    /// Mask length of the global IPv6 address. 
    #[serde(rename = "GlobalIPv6PrefixLen")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_ipv6_prefix_len: Option<i64>,

    /// List of all DNS names an endpoint has on a specific network. This list is based on the container name, network aliases, container short ID, and hostname.  These DNS names are non-fully qualified but can contain several dots. You can get fully qualified DNS names by appending `.<network-name>`. For instance, if container name is `my.ctr` and the network is named `testnet`, `DNSNames` will contain `my.ctr` and the FQDN will be `my.ctr.testnet`. 
    #[serde(rename = "DNSNames")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_names: Option<Vec<String>>,

}

/// Properties that can be configured to access and load balance a service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EndpointSpec {
    /// The mode of resolution to use for internal load balancing between tasks. 
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<EndpointSpecModeEnum>,

    /// List of exposed ports that this service is accessible on from the outside. Ports can only be provided if `vip` resolution mode is used. 
    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<EndpointPortConfig>>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum EndpointSpecModeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "vip")]
    VIP,
    #[serde(rename = "dnsrr")]
    DNSRR,
}

impl ::std::fmt::Display for EndpointSpecModeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            EndpointSpecModeEnum::EMPTY => write!(f, ""),
            EndpointSpecModeEnum::VIP => write!(f, "{}", "vip"),
            EndpointSpecModeEnum::DNSRR => write!(f, "{}", "dnsrr"),

        }
    }
}

impl ::std::str::FromStr for EndpointSpecModeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(EndpointSpecModeEnum::EMPTY),
            "vip" => Ok(EndpointSpecModeEnum::VIP),
            "dnsrr" => Ok(EndpointSpecModeEnum::DNSRR),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for EndpointSpecModeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            EndpointSpecModeEnum::EMPTY => "",
            EndpointSpecModeEnum::VIP => "vip",
            EndpointSpecModeEnum::DNSRR => "dnsrr",
        }
    }
}

/// EngineDescription provides information about an engine.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineDescription {
    #[serde(rename = "EngineVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine_version: Option<String>,

    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "Plugins")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugins: Option<Vec<EngineDescriptionPlugins>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EngineDescriptionPlugins {
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ErrorDetail {
    #[serde(rename = "code")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub code: Option<i64>,

    #[serde(rename = "message")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

}

/// Represents an error.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ErrorResponse {
    /// The error message.
    #[serde(rename = "message")]
    pub message: String,

}

/// Actor describes something that generates events, like a container, network, or a volume. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventActor {
    /// The ID of the object emitting the event
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Various key/value attributes of the object, depending on its type. 
    #[serde(rename = "Attributes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attributes: Option<HashMap<String, String>>,

}

/// EventMessage represents the information an event contains. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct EventMessage {
    /// The type of object emitting the event
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<EventMessageTypeEnum>,

    /// The type of event
    #[serde(rename = "Action")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub action: Option<String>,

    #[serde(rename = "Actor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub actor: Option<EventActor>,

    /// Scope of the event. Engine events are `local` scope. Cluster (Swarm) events are `swarm` scope. 
    #[serde(rename = "scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<EventMessageScopeEnum>,

    /// Timestamp of event
    #[serde(rename = "time")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time: Option<i64>,

    /// Timestamp of event, with nanosecond accuracy
    #[serde(rename = "timeNano")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub time_nano: Option<i64>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum EventMessageTypeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "builder")]
    BUILDER,
    #[serde(rename = "config")]
    CONFIG,
    #[serde(rename = "container")]
    CONTAINER,
    #[serde(rename = "daemon")]
    DAEMON,
    #[serde(rename = "image")]
    IMAGE,
    #[serde(rename = "network")]
    NETWORK,
    #[serde(rename = "node")]
    NODE,
    #[serde(rename = "plugin")]
    PLUGIN,
    #[serde(rename = "secret")]
    SECRET,
    #[serde(rename = "service")]
    SERVICE,
    #[serde(rename = "volume")]
    VOLUME,
}

impl ::std::fmt::Display for EventMessageTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            EventMessageTypeEnum::EMPTY => write!(f, ""),
            EventMessageTypeEnum::BUILDER => write!(f, "{}", "builder"),
            EventMessageTypeEnum::CONFIG => write!(f, "{}", "config"),
            EventMessageTypeEnum::CONTAINER => write!(f, "{}", "container"),
            EventMessageTypeEnum::DAEMON => write!(f, "{}", "daemon"),
            EventMessageTypeEnum::IMAGE => write!(f, "{}", "image"),
            EventMessageTypeEnum::NETWORK => write!(f, "{}", "network"),
            EventMessageTypeEnum::NODE => write!(f, "{}", "node"),
            EventMessageTypeEnum::PLUGIN => write!(f, "{}", "plugin"),
            EventMessageTypeEnum::SECRET => write!(f, "{}", "secret"),
            EventMessageTypeEnum::SERVICE => write!(f, "{}", "service"),
            EventMessageTypeEnum::VOLUME => write!(f, "{}", "volume"),

        }
    }
}

impl ::std::str::FromStr for EventMessageTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(EventMessageTypeEnum::EMPTY),
            "builder" => Ok(EventMessageTypeEnum::BUILDER),
            "config" => Ok(EventMessageTypeEnum::CONFIG),
            "container" => Ok(EventMessageTypeEnum::CONTAINER),
            "daemon" => Ok(EventMessageTypeEnum::DAEMON),
            "image" => Ok(EventMessageTypeEnum::IMAGE),
            "network" => Ok(EventMessageTypeEnum::NETWORK),
            "node" => Ok(EventMessageTypeEnum::NODE),
            "plugin" => Ok(EventMessageTypeEnum::PLUGIN),
            "secret" => Ok(EventMessageTypeEnum::SECRET),
            "service" => Ok(EventMessageTypeEnum::SERVICE),
            "volume" => Ok(EventMessageTypeEnum::VOLUME),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for EventMessageTypeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            EventMessageTypeEnum::EMPTY => "",
            EventMessageTypeEnum::BUILDER => "builder",
            EventMessageTypeEnum::CONFIG => "config",
            EventMessageTypeEnum::CONTAINER => "container",
            EventMessageTypeEnum::DAEMON => "daemon",
            EventMessageTypeEnum::IMAGE => "image",
            EventMessageTypeEnum::NETWORK => "network",
            EventMessageTypeEnum::NODE => "node",
            EventMessageTypeEnum::PLUGIN => "plugin",
            EventMessageTypeEnum::SECRET => "secret",
            EventMessageTypeEnum::SERVICE => "service",
            EventMessageTypeEnum::VOLUME => "volume",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum EventMessageScopeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "local")]
    LOCAL,
    #[serde(rename = "swarm")]
    SWARM,
}

impl ::std::fmt::Display for EventMessageScopeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            EventMessageScopeEnum::EMPTY => write!(f, ""),
            EventMessageScopeEnum::LOCAL => write!(f, "{}", "local"),
            EventMessageScopeEnum::SWARM => write!(f, "{}", "swarm"),

        }
    }
}

impl ::std::str::FromStr for EventMessageScopeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(EventMessageScopeEnum::EMPTY),
            "local" => Ok(EventMessageScopeEnum::LOCAL),
            "swarm" => Ok(EventMessageScopeEnum::SWARM),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for EventMessageScopeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            EventMessageScopeEnum::EMPTY => "",
            EventMessageScopeEnum::LOCAL => "local",
            EventMessageScopeEnum::SWARM => "swarm",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecConfig {
    /// Attach to `stdin` of the exec command.
    #[serde(rename = "AttachStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdin: Option<bool>,

    /// Attach to `stdout` of the exec command.
    #[serde(rename = "AttachStdout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stdout: Option<bool>,

    /// Attach to `stderr` of the exec command.
    #[serde(rename = "AttachStderr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attach_stderr: Option<bool>,

    /// Initial console size, as an `[height, width]` array.
    #[serde(rename = "ConsoleSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Vec<usize>>,

    /// Override the key sequence for detaching a container. Format is a single character `[a-Z]` or `ctrl-<value>` where `<value>` is one of: `a-z`, `@`, `^`, `[`, `,` or `_`. 
    #[serde(rename = "DetachKeys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detach_keys: Option<String>,

    /// Allocate a pseudo-TTY.
    #[serde(rename = "Tty")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// A list of environment variables in the form `[\"VAR=value\", ...]`. 
    #[serde(rename = "Env")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// Command to run, as a string or array of strings.
    #[serde(rename = "Cmd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    /// Runs the exec process with extended privileges.
    #[serde(rename = "Privileged")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// The user, and optionally, group to run the exec process inside the container. Format is one of: `user`, `user:group`, `uid`, or `uid:gid`. 
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// The working directory for the exec process inside the container. 
    #[serde(rename = "WorkingDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecInspectResponse {
    #[serde(rename = "CanRemove")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub can_remove: Option<bool>,

    #[serde(rename = "DetachKeys")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detach_keys: Option<String>,

    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Running")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running: Option<bool>,

    #[serde(rename = "ExitCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,

    #[serde(rename = "ProcessConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub process_config: Option<ProcessConfig>,

    #[serde(rename = "OpenStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdin: Option<bool>,

    #[serde(rename = "OpenStderr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stderr: Option<bool>,

    #[serde(rename = "OpenStdout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdout: Option<bool>,

    #[serde(rename = "ContainerID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

    /// The system process ID for the exec process.
    #[serde(rename = "Pid")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ExecStartConfig {
    /// Detach from the command.
    #[serde(rename = "Detach")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub detach: Option<bool>,

    /// Allocate a pseudo-TTY.
    #[serde(rename = "Tty")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// Initial console size, as an `[height, width]` array.
    #[serde(rename = "ConsoleSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Vec<usize>>,

}

/// Change in the container's filesystem. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FilesystemChange {
    /// Path to file or directory that has changed. 
    #[serde(rename = "Path")]
    pub path: String,

    #[serde(rename = "Kind")]
    pub kind: ChangeType,

}

/// Information about the daemon's firewalling configuration.  This field is currently only used on Linux, and omitted on other platforms. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct FirewallInfo {
    /// The name of the firewall backend driver. 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Information about the firewall backend, provided as \"label\" / \"value\" pairs.  <p><br /></p>  > **Note**: The information returned in this field, including the > formatting of values and labels, should not be considered stable, > and may change without notice. 
    #[serde(rename = "Info")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<Vec<Vec<String>>>,

}

/// User-defined resources can be either Integer resources (e.g, `SSD=3`) or String resources (e.g, `GPU=UUID1`). 

pub type GenericResources = Vec<GenericResourcesInner>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenericResourcesInner {
    #[serde(rename = "NamedResourceSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub named_resource_spec: Option<GenericResourcesInnerNamedResourceSpec>,

    #[serde(rename = "DiscreteResourceSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discrete_resource_spec: Option<GenericResourcesInnerDiscreteResourceSpec>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenericResourcesInnerDiscreteResourceSpec {
    #[serde(rename = "Kind")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(rename = "Value")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct GenericResourcesInnerNamedResourceSpec {
    #[serde(rename = "Kind")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kind: Option<String>,

    #[serde(rename = "Value")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<String>,

}

/// Health stores information about the container's healthcheck results. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Health {
    /// Status is one of `none`, `starting`, `healthy` or `unhealthy`  - \"none\"      Indicates there is no healthcheck - \"starting\"  Starting indicates that the container is not yet ready - \"healthy\"   Healthy indicates that the container is running correctly - \"unhealthy\" Unhealthy indicates that the container has a problem 
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<HealthStatusEnum>,

    /// FailingStreak is the number of consecutive failures
    #[serde(rename = "FailingStreak")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failing_streak: Option<i64>,

    /// Log contains the last few results (oldest first) 
    #[serde(rename = "Log")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<HealthcheckResult>>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum HealthStatusEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "none")]
    NONE,
    #[serde(rename = "starting")]
    STARTING,
    #[serde(rename = "healthy")]
    HEALTHY,
    #[serde(rename = "unhealthy")]
    UNHEALTHY,
}

impl ::std::fmt::Display for HealthStatusEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            HealthStatusEnum::EMPTY => write!(f, ""),
            HealthStatusEnum::NONE => write!(f, "{}", "none"),
            HealthStatusEnum::STARTING => write!(f, "{}", "starting"),
            HealthStatusEnum::HEALTHY => write!(f, "{}", "healthy"),
            HealthStatusEnum::UNHEALTHY => write!(f, "{}", "unhealthy"),

        }
    }
}

impl ::std::str::FromStr for HealthStatusEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(HealthStatusEnum::EMPTY),
            "none" => Ok(HealthStatusEnum::NONE),
            "starting" => Ok(HealthStatusEnum::STARTING),
            "healthy" => Ok(HealthStatusEnum::HEALTHY),
            "unhealthy" => Ok(HealthStatusEnum::UNHEALTHY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for HealthStatusEnum {
    fn as_ref(&self) -> &str {
        match self { 
            HealthStatusEnum::EMPTY => "",
            HealthStatusEnum::NONE => "none",
            HealthStatusEnum::STARTING => "starting",
            HealthStatusEnum::HEALTHY => "healthy",
            HealthStatusEnum::UNHEALTHY => "unhealthy",
        }
    }
}

/// A test to perform to check that the container is healthy.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HealthConfig {
    /// The test to perform. Possible values are:  - `[]` inherit healthcheck from image or parent image - `[\"NONE\"]` disable healthcheck - `[\"CMD\", args...]` exec arguments directly - `[\"CMD-SHELL\", command]` run command with system's default shell 
    #[serde(rename = "Test")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub test: Option<Vec<String>>,

    /// The time to wait between checks in nanoseconds. It should be 0 or at least 1000000 (1 ms). 0 means inherit. 
    #[serde(rename = "Interval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub interval: Option<i64>,

    /// The time to wait before considering the check to have hung. It should be 0 or at least 1000000 (1 ms). 0 means inherit. 
    #[serde(rename = "Timeout")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout: Option<i64>,

    /// The number of consecutive failures needed to consider a container as unhealthy. 0 means inherit. 
    #[serde(rename = "Retries")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retries: Option<i64>,

    /// Start period for the container to initialize before starting health-retries countdown in nanoseconds. It should be 0 or at least 1000000 (1 ms). 0 means inherit. 
    #[serde(rename = "StartPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_period: Option<i64>,

    /// The time to wait between checks in nanoseconds during the start period. It should be 0 or at least 1000000 (1 ms). 0 means inherit. 
    #[serde(rename = "StartInterval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub start_interval: Option<i64>,

}

/// HealthcheckResult stores information about a single run of a healthcheck probe 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HealthcheckResult {
    /// Date and time at which this check started in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "Start")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub start: Option<BollardDate>,

    /// Date and time at which this check ended in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "End")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub end: Option<BollardDate>,

    /// ExitCode meanings:  - `0` healthy - `1` unhealthy - `2` reserved (considered unhealthy) - other values: error running probe 
    #[serde(rename = "ExitCode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<i64>,

    /// Output from last check
    #[serde(rename = "Output")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub output: Option<String>,

}

/// individual image layer information in response to ImageHistory operation
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HistoryResponseItem {
    #[serde(rename = "Id")]
    pub id: String,

    #[serde(rename = "Created")]
    pub created: i64,

    #[serde(rename = "CreatedBy")]
    pub created_by: String,

    #[serde(rename = "Tags")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub tags: Vec<String>,

    #[serde(rename = "Size")]
    pub size: i64,

    #[serde(rename = "Comment")]
    pub comment: String,

}

/// Container configuration that depends on the host we are running on
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostConfig {
    /// An integer value representing this container's relative CPU weight versus other containers. 
    #[serde(rename = "CpuShares")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<i64>,

    /// Memory limit in bytes.
    #[serde(rename = "Memory")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,

    /// Path to `cgroups` under which the container's `cgroup` is created. If the path is not absolute, the path is considered to be relative to the `cgroups` path of the init process. Cgroups are created if they do not already exist. 
    #[serde(rename = "CgroupParent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,

    /// Block IO weight (relative weight).
    #[serde(rename = "BlkioWeight")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight: Option<u16>,

    /// Block IO weight (relative device weight) in the form:  ``` [{\"Path\": \"device_path\", \"Weight\": weight}] ``` 
    #[serde(rename = "BlkioWeightDevice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight_device: Option<Vec<ResourcesBlkioWeightDevice>>,

    /// Limit read rate (bytes per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_bps: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (bytes per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_bps: Option<Vec<ThrottleDevice>>,

    /// Limit read rate (IO per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_iops: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (IO per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_iops: Option<Vec<ThrottleDevice>>,

    /// The length of a CPU period in microseconds.
    #[serde(rename = "CpuPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<i64>,

    /// Microseconds of CPU time that the container can get in a CPU period. 
    #[serde(rename = "CpuQuota")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,

    /// The length of a CPU real-time period in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimePeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_period: Option<i64>,

    /// The length of a CPU real-time runtime in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimeRuntime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_runtime: Option<i64>,

    /// CPUs in which to allow execution (e.g., `0-3`, `0,1`). 
    #[serde(rename = "CpusetCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_cpus: Option<String>,

    /// Memory nodes (MEMs) in which to allow execution (0-3, 0,1). Only effective on NUMA systems. 
    #[serde(rename = "CpusetMems")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_mems: Option<String>,

    /// A list of devices to add to the container.
    #[serde(rename = "Devices")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<DeviceMapping>>,

    /// a list of cgroup rules to apply to the container
    #[serde(rename = "DeviceCgroupRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_cgroup_rules: Option<Vec<String>>,

    /// A list of requests for devices to be sent to device drivers. 
    #[serde(rename = "DeviceRequests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_requests: Option<Vec<DeviceRequest>>,

    /// Memory soft limit in bytes.
    #[serde(rename = "MemoryReservation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_reservation: Option<i64>,

    /// Total memory limit (memory + swap). Set as `-1` to enable unlimited swap. 
    #[serde(rename = "MemorySwap")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swap: Option<i64>,

    /// Tune a container's memory swappiness behavior. Accepts an integer between 0 and 100. 
    #[serde(rename = "MemorySwappiness")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swappiness: Option<i64>,

    /// CPU quota in units of 10<sup>-9</sup> CPUs.
    #[serde(rename = "NanoCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,

    /// Disable OOM Killer for the container.
    #[serde(rename = "OomKillDisable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill_disable: Option<bool>,

    /// Run an init inside the container that forwards signals and reaps processes. This field is omitted if empty, and the default (as configured on the daemon) is used. 
    #[serde(rename = "Init")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Tune a container's PIDs limit. Set `0` or `-1` for unlimited, or `null` to not change. 
    #[serde(rename = "PidsLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,

    /// A list of resource limits to set in the container. For example:  ``` {\"Name\": \"nofile\", \"Soft\": 1024, \"Hard\": 2048} ``` 
    #[serde(rename = "Ulimits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<Vec<ResourcesUlimits>>,

    /// The number of usable CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i64>,

    /// The usable percentage of the available CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuPercent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<i64>,

    /// Maximum IOps for the container system drive (Windows only)
    #[serde(rename = "IOMaximumIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_iops: Option<i64>,

    /// Maximum IO in bytes per second for the container system drive (Windows only). 
    #[serde(rename = "IOMaximumBandwidth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_bandwidth: Option<i64>,

    /// A list of volume bindings for this container. Each volume binding is a string in one of these forms:  - `host-src:container-dest[:options]` to bind-mount a host path   into the container. Both `host-src`, and `container-dest` must   be an _absolute_ path. - `volume-name:container-dest[:options]` to bind-mount a volume   managed by a volume driver into the container. `container-dest`   must be an _absolute_ path.  `options` is an optional, comma-delimited list of:  - `nocopy` disables automatic copying of data from the container   path to the volume. The `nocopy` flag only applies to named volumes. - `[ro|rw]` mounts a volume read-only or read-write, respectively.   If omitted or set to `rw`, volumes are mounted read-write. - `[z|Z]` applies SELinux labels to allow or deny multiple containers   to read and write to the same volume.     - `z`: a _shared_ content label is applied to the content. This       label indicates that multiple containers can share the volume       content, for both reading and writing.     - `Z`: a _private unshared_ label is applied to the content.       This label indicates that only the current container can use       a private volume. Labeling systems such as SELinux require       proper labels to be placed on volume content that is mounted       into a container. Without a label, the security system can       prevent a container's processes from using the content. By       default, the labels set by the host operating system are not       modified. - `[[r]shared|[r]slave|[r]private]` specifies mount   [propagation behavior](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt).   This only applies to bind-mounted volumes, not internal volumes   or named volumes. Mount propagation requires the source mount   point (the location where the source directory is mounted in the   host operating system) to have the correct propagation properties.   For shared volumes, the source mount point must be set to `shared`.   For slave volumes, the mount must be set to either `shared` or   `slave`. 
    #[serde(rename = "Binds")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub binds: Option<Vec<String>>,

    /// Path to a file where the container ID is written
    #[serde(rename = "ContainerIDFile")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id_file: Option<String>,

    #[serde(rename = "LogConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_config: Option<HostConfigLogConfig>,

    /// Network mode to use for this container. Supported standard values are: `bridge`, `host`, `none`, and `container:<name|id>`. Any other value is taken as a custom network's name to which this container should connect to. 
    #[serde(rename = "NetworkMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_mode: Option<String>,

    #[serde(rename = "PortBindings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_bindings: Option<PortMap>,

    #[serde(rename = "RestartPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<RestartPolicy>,

    /// Automatically remove the container when the container's process exits. This has no effect if `RestartPolicy` is set. 
    #[serde(rename = "AutoRemove")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_remove: Option<bool>,

    /// Driver that this container uses to mount volumes.
    #[serde(rename = "VolumeDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_driver: Option<String>,

    /// A list of volumes to inherit from another container, specified in the form `<container name>[:<ro|rw>]`. 
    #[serde(rename = "VolumesFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes_from: Option<Vec<String>>,

    /// Specification for mounts to be added to the container. 
    #[serde(rename = "Mounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<Mount>>,

    /// Initial console size, as an `[height, width]` array. 
    #[serde(rename = "ConsoleSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub console_size: Option<Vec<usize>>,

    /// Arbitrary non-identifying metadata attached to container and provided to the runtime when the container is started. 
    #[serde(rename = "Annotations")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,

    /// A list of kernel capabilities to add to the container. Conflicts with option 'Capabilities'. 
    #[serde(rename = "CapAdd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_add: Option<Vec<String>>,

    /// A list of kernel capabilities to drop from the container. Conflicts with option 'Capabilities'. 
    #[serde(rename = "CapDrop")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cap_drop: Option<Vec<String>>,

    /// cgroup namespace mode for the container. Possible values are:  - `\"private\"`: the container runs in its own private cgroup namespace - `\"host\"`: use the host system's cgroup namespace  If not specified, the daemon default is used, which can either be `\"private\"` or `\"host\"`, depending on daemon version, kernel support and configuration. 
    #[serde(rename = "CgroupnsMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroupns_mode: Option<HostConfigCgroupnsModeEnum>,

    /// A list of DNS servers for the container to use.
    #[serde(rename = "Dns")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns: Option<Vec<String>>,

    /// A list of DNS options.
    #[serde(rename = "DnsOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_options: Option<Vec<String>>,

    /// A list of DNS search domains.
    #[serde(rename = "DnsSearch")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_search: Option<Vec<String>>,

    /// A list of hostnames/IP mappings to add to the container's `/etc/hosts` file. Specified in the form `[\"hostname:IP\"]`. 
    #[serde(rename = "ExtraHosts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub extra_hosts: Option<Vec<String>>,

    /// A list of additional groups that the container process will run as. 
    #[serde(rename = "GroupAdd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub group_add: Option<Vec<String>>,

    /// IPC sharing mode for the container. Possible values are:  - `\"none\"`: own private IPC namespace, with /dev/shm not mounted - `\"private\"`: own private IPC namespace - `\"shareable\"`: own private IPC namespace, with a possibility to share it with other containers - `\"container:<name|id>\"`: join another (shareable) container's IPC namespace - `\"host\"`: use the host system's IPC namespace  If not specified, daemon default is used, which can either be `\"private\"` or `\"shareable\"`, depending on daemon version and configuration. 
    #[serde(rename = "IpcMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipc_mode: Option<String>,

    /// Cgroup to use for the container.
    #[serde(rename = "Cgroup")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup: Option<String>,

    /// A list of links for the container in the form `container_name:alias`. 
    #[serde(rename = "Links")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub links: Option<Vec<String>>,

    /// An integer value containing the score given to the container in order to tune OOM killer preferences. 
    #[serde(rename = "OomScoreAdj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i64>,

    /// Set the PID (Process) Namespace mode for the container. It can be either:  - `\"container:<name|id>\"`: joins another container's PID namespace - `\"host\"`: use the host's PID namespace inside the container 
    #[serde(rename = "PidMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pid_mode: Option<String>,

    /// Gives the container full access to the host.
    #[serde(rename = "Privileged")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    /// Allocates an ephemeral host port for all of a container's exposed ports.  Ports are de-allocated when the container stops and allocated when the container starts. The allocated port might be changed when restarting the container.  The port is selected from the ephemeral port range that depends on the kernel. For example, on Linux the range is defined by `/proc/sys/net/ipv4/ip_local_port_range`. 
    #[serde(rename = "PublishAllPorts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub publish_all_ports: Option<bool>,

    /// Mount the container's root filesystem as read only.
    #[serde(rename = "ReadonlyRootfs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly_rootfs: Option<bool>,

    /// A list of string values to customize labels for MLS systems, such as SELinux. 
    #[serde(rename = "SecurityOpt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_opt: Option<Vec<String>>,

    /// Storage driver options for this container, in the form `{\"size\": \"120G\"}`. 
    #[serde(rename = "StorageOpt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub storage_opt: Option<HashMap<String, String>>,

    /// A map of container directories which should be replaced by tmpfs mounts, and their corresponding mount options. For example:  ``` { \"/run\": \"rw,noexec,nosuid,size=65536k\" } ``` 
    #[serde(rename = "Tmpfs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmpfs: Option<HashMap<String, String>>,

    /// UTS namespace to use for the container.
    #[serde(rename = "UTSMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uts_mode: Option<String>,

    /// Sets the usernamespace mode for the container when usernamespace remapping option is enabled. 
    #[serde(rename = "UsernsMode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub userns_mode: Option<String>,

    /// Size of `/dev/shm` in bytes. If omitted, the system uses 64MB. 
    #[serde(rename = "ShmSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shm_size: Option<i64>,

    /// A list of kernel parameters (sysctls) to set in the container.  This field is omitted if not set.
    #[serde(rename = "Sysctls")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysctls: Option<HashMap<String, String>>,

    /// Runtime to use with this container.
    #[serde(rename = "Runtime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,

    /// Isolation technology of the container. (Windows only) 
    #[serde(rename = "Isolation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<HostConfigIsolationEnum>,

    /// The list of paths to be masked inside the container (this overrides the default set of paths). 
    #[serde(rename = "MaskedPaths")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub masked_paths: Option<Vec<String>>,

    /// The list of paths to be set as read-only inside the container (this overrides the default set of paths). 
    #[serde(rename = "ReadonlyPaths")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub readonly_paths: Option<Vec<String>>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum HostConfigCgroupnsModeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "private")]
    PRIVATE,
    #[serde(rename = "host")]
    HOST,
}

impl ::std::fmt::Display for HostConfigCgroupnsModeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            HostConfigCgroupnsModeEnum::EMPTY => write!(f, ""),
            HostConfigCgroupnsModeEnum::PRIVATE => write!(f, "{}", "private"),
            HostConfigCgroupnsModeEnum::HOST => write!(f, "{}", "host"),

        }
    }
}

impl ::std::str::FromStr for HostConfigCgroupnsModeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(HostConfigCgroupnsModeEnum::EMPTY),
            "private" => Ok(HostConfigCgroupnsModeEnum::PRIVATE),
            "host" => Ok(HostConfigCgroupnsModeEnum::HOST),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for HostConfigCgroupnsModeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            HostConfigCgroupnsModeEnum::EMPTY => "",
            HostConfigCgroupnsModeEnum::PRIVATE => "private",
            HostConfigCgroupnsModeEnum::HOST => "host",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum HostConfigIsolationEnum { 
    #[serde(rename = "default")]
    DEFAULT,
    #[serde(rename = "process")]
    PROCESS,
    #[serde(rename = "hyperv")]
    HYPERV,
    #[serde(rename = "")]
    EMPTY,
}

impl ::std::fmt::Display for HostConfigIsolationEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            HostConfigIsolationEnum::DEFAULT => write!(f, "{}", "default"),
            HostConfigIsolationEnum::PROCESS => write!(f, "{}", "process"),
            HostConfigIsolationEnum::HYPERV => write!(f, "{}", "hyperv"),
            HostConfigIsolationEnum::EMPTY => write!(f, "{}", ""),

        }
    }
}

impl ::std::str::FromStr for HostConfigIsolationEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "default" => Ok(HostConfigIsolationEnum::DEFAULT),
            "process" => Ok(HostConfigIsolationEnum::PROCESS),
            "hyperv" => Ok(HostConfigIsolationEnum::HYPERV),
            "" => Ok(HostConfigIsolationEnum::EMPTY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for HostConfigIsolationEnum {
    fn as_ref(&self) -> &str {
        match self { 
            HostConfigIsolationEnum::DEFAULT => "default",
            HostConfigIsolationEnum::PROCESS => "process",
            HostConfigIsolationEnum::HYPERV => "hyperv",
            HostConfigIsolationEnum::EMPTY => "",
        }
    }
}

/// The logging configuration for this container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct HostConfigLogConfig {
    /// Name of the logging driver used for the container or \"none\" if logging is disabled.
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// Driver-specific configuration options for the logging driver.
    #[serde(rename = "Config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<HashMap<String, String>>,

}

/// Response to an API call that returns just an Id
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IdResponse {
    /// The id of the newly created object.
    #[serde(alias = "Id")]
    #[serde(alias = "ID")]
    
    pub id: String,

}

/// Configuration of the image. These fields are used as defaults when starting a container from the image. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageConfig {
    /// The user that commands are run as inside the container.
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// An object mapping ports to an empty object in the form:  `{\"<port>/<tcp|udp|sctp>\": {}}` 
    #[serde(rename = "ExposedPorts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub exposed_ports: Option<Vec<String>>,

    /// A list of environment variables to set inside the container in the form `[\"VAR=value\", ...]`. A variable without `=` is removed from the environment, rather than to have an empty value. 
    #[serde(rename = "Env")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// Command to run specified as a string or an array of strings. 
    #[serde(rename = "Cmd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cmd: Option<Vec<String>>,

    #[serde(rename = "Healthcheck")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub healthcheck: Option<HealthConfig>,

    /// Command is already escaped (Windows only)
    #[serde(rename = "ArgsEscaped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args_escaped: Option<bool>,

    /// An object mapping mount point paths inside the container to empty objects. 
    #[serde(rename = "Volumes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub volumes: Option<Vec<String>>,

    /// The working directory for commands to run in.
    #[serde(rename = "WorkingDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub working_dir: Option<String>,

    /// The entry point for the container as a string or an array of strings.  If the array consists of exactly one empty string (`[\"\"]`) then the entry point is reset to system default (i.e., the entry point used by docker when there is no `ENTRYPOINT` instruction in the `Dockerfile`). 
    #[serde(rename = "Entrypoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<Vec<String>>,

    /// `ONBUILD` metadata that were defined in the image's `Dockerfile`. 
    #[serde(rename = "OnBuild")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub on_build: Option<Vec<String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Signal to stop a container as a string or unsigned integer. 
    #[serde(rename = "StopSignal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,

    /// Shell for when `RUN`, `CMD`, and `ENTRYPOINT` uses a shell. 
    #[serde(rename = "Shell")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub shell: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageDeleteResponseItem {
    /// The image ID of an image that was untagged
    #[serde(rename = "Untagged")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub untagged: Option<String>,

    /// The image ID of an image that was deleted
    #[serde(rename = "Deleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub deleted: Option<String>,

}

/// Image ID or Digest
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageId {
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

}

/// Information about an image in the local image cache. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageInspect {
    /// ID is the content-addressable ID of an image.  This identifier is a content-addressable digest calculated from the image's configuration (which includes the digests of layers used by the image).  Note that this digest differs from the `RepoDigests` below, which holds digests of image manifests that reference the image. 
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Descriptor is an OCI descriptor of the image target. In case of a multi-platform image, this descriptor points to the OCI index or a manifest list.  This field is only present if the daemon provides a multi-platform image store.  WARNING: This is experimental and may change at any time without any backward compatibility. 
    #[serde(rename = "Descriptor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<OciDescriptor>,

    /// Manifests is a list of image manifests available in this image. It provides a more detailed view of the platform-specific image manifests or other image-attached data like build attestations.  Only available if the daemon provides a multi-platform image store and the `manifests` option is set in the inspect request.  WARNING: This is experimental and may change at any time without any backward compatibility. 
    #[serde(rename = "Manifests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifests: Option<Vec<ImageManifestSummary>>,

    /// List of image names/tags in the local image cache that reference this image.  Multiple image tags can refer to the same image, and this list may be empty if no tags reference the image, in which case the image is \"untagged\", in which case it can still be referenced by its ID. 
    #[serde(rename = "RepoTags")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_tags: Option<Vec<String>>,

    /// List of content-addressable digests of locally available image manifests that the image is referenced from. Multiple manifests can refer to the same image.  These digests are usually only available if the image was either pulled from a registry, or if the image was pushed to a registry, which is when the manifest is generated and its digest calculated. 
    #[serde(rename = "RepoDigests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub repo_digests: Option<Vec<String>>,

    /// Optional message that was set when committing or importing the image. 
    #[serde(rename = "Comment")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub comment: Option<String>,

    /// Date and time at which the image was created, formatted in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.  This information is only available if present in the image, and omitted otherwise. 
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created: Option<BollardDate>,

    /// Name of the author that was specified when committing the image, or as specified through MAINTAINER (deprecated) in the Dockerfile. 
    #[serde(rename = "Author")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub author: Option<String>,

    #[serde(rename = "Config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<ImageConfig>,

    /// Hardware CPU architecture that the image runs on. 
    #[serde(rename = "Architecture")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,

    /// CPU architecture variant (presently ARM-only). 
    #[serde(rename = "Variant")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

    /// Operating System the image is built to run on. 
    #[serde(rename = "Os")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// Operating System version the image is built to run on (especially for Windows). 
    #[serde(rename = "OsVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// Total size of the image including all layers it is composed of. 
    #[serde(rename = "Size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,

    #[serde(rename = "GraphDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub graph_driver: Option<DriverData>,

    #[serde(rename = "RootFS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_fs: Option<ImageInspectRootFs>,

    #[serde(rename = "Metadata")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub metadata: Option<ImageInspectMetadata>,

}

/// Additional metadata of the image in the local cache. This information is local to the daemon, and not part of the image itself. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageInspectMetadata {
    /// Date and time at which the image was last tagged in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds.  This information is only available if the image was tagged locally, and omitted otherwise. 
    #[serde(rename = "LastTagTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub last_tag_time: Option<BollardDate>,

}

/// Information about the image's RootFS, including the layer IDs. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageInspectRootFs {
    #[serde(rename = "Type")]
    pub typ: String,

    #[serde(rename = "Layers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub layers: Option<Vec<String>>,

}

/// ImageManifestSummary represents a summary of an image manifest. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageManifestSummary {
    /// ID is the content-addressable ID of an image and is the same as the digest of the image manifest. 
    #[serde(rename = "ID")]
    pub id: String,

    #[serde(rename = "Descriptor")]
    pub descriptor: OciDescriptor,

    /// Indicates whether all the child content (image config, layers) is fully available locally.
    #[serde(rename = "Available")]
    pub available: bool,

    #[serde(rename = "Size")]
    pub size: ImageManifestSummarySize,

    /// The kind of the manifest.  kind         | description -------------|----------------------------------------------------------- image        | Image manifest that can be used to start a container. attestation  | Attestation manifest produced by the Buildkit builder for a specific image manifest. 
    #[serde(rename = "Kind")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_ext::none_as_empty_string")]
    pub kind: Option<ImageManifestSummaryKindEnum>,

    #[serde(rename = "ImageData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_data: Option<ImageManifestSummaryImageData>,

    #[serde(rename = "AttestationData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attestation_data: Option<ImageManifestSummaryAttestationData>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ImageManifestSummaryKindEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "image")]
    IMAGE,
    #[serde(rename = "attestation")]
    ATTESTATION,
    #[serde(rename = "unknown")]
    UNKNOWN,
}

impl ::std::fmt::Display for ImageManifestSummaryKindEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ImageManifestSummaryKindEnum::EMPTY => write!(f, ""),
            ImageManifestSummaryKindEnum::IMAGE => write!(f, "{}", "image"),
            ImageManifestSummaryKindEnum::ATTESTATION => write!(f, "{}", "attestation"),
            ImageManifestSummaryKindEnum::UNKNOWN => write!(f, "{}", "unknown"),

        }
    }
}

impl ::std::str::FromStr for ImageManifestSummaryKindEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ImageManifestSummaryKindEnum::EMPTY),
            "image" => Ok(ImageManifestSummaryKindEnum::IMAGE),
            "attestation" => Ok(ImageManifestSummaryKindEnum::ATTESTATION),
            "unknown" => Ok(ImageManifestSummaryKindEnum::UNKNOWN),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ImageManifestSummaryKindEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ImageManifestSummaryKindEnum::EMPTY => "",
            ImageManifestSummaryKindEnum::IMAGE => "image",
            ImageManifestSummaryKindEnum::ATTESTATION => "attestation",
            ImageManifestSummaryKindEnum::UNKNOWN => "unknown",
        }
    }
}

/// The image data for the attestation manifest. This field is only populated when Kind is \"attestation\". 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageManifestSummaryAttestationData {
    /// The digest of the image manifest that this attestation is for. 
    #[serde(rename = "For")]
    pub _for: String,

}

/// The image data for the image manifest. This field is only populated when Kind is \"image\". 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageManifestSummaryImageData {
    /// OCI platform of the image. This will be the platform specified in the manifest descriptor from the index/manifest list. If it's not available, it will be obtained from the image config. 
    #[serde(rename = "Platform")]
    pub platform: OciPlatform,

    /// The IDs of the containers that are using this image. 
    #[serde(rename = "Containers")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub containers: Vec<String>,

    #[serde(rename = "Size")]
    pub size: ImageManifestSummaryImageDataSize,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageManifestSummaryImageDataSize {
    /// Unpacked is the size (in bytes) of the locally unpacked (uncompressed) image content that's directly usable by the containers running this image. It's independent of the distributable content - e.g. the image might still have an unpacked data that's still used by some container even when the distributable/compressed content is already gone. 
    #[serde(rename = "Unpacked")]
    pub unpacked: i64,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageManifestSummarySize {
    /// Total is the total size (in bytes) of all the locally present data (both distributable and non-distributable) that's related to this manifest and its children. This equal to the sum of [Content] size AND all the sizes in the [Size] struct present in the Kind-specific data struct. For example, for an image kind (Kind == \"image\") this would include the size of the image content and unpacked image snapshots ([Size.Content] + [ImageData.Size.Unpacked]). 
    #[serde(rename = "Total")]
    pub total: i64,

    /// Content is the size (in bytes) of all the locally present content in the content store (e.g. image config, layers) referenced by this manifest and its children. This only includes blobs in the content store. 
    #[serde(rename = "Content")]
    pub content: i64,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImagePruneResponse {
    /// Images that were deleted
    #[serde(rename = "ImagesDeleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images_deleted: Option<Vec<ImageDeleteResponseItem>>,

    /// Disk space reclaimed in bytes
    #[serde(rename = "SpaceReclaimed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_reclaimed: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageSearchResponseItem {
    #[serde(rename = "description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "is_official")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_official: Option<bool>,

    /// Whether this repository has automated builds enabled.  <p><br /></p>  > **Deprecated**: This field is deprecated and will always be \"false\". 
    #[serde(rename = "is_automated")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub is_automated: Option<bool>,

    #[serde(rename = "name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "star_count")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub star_count: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImageSummary {
    /// ID is the content-addressable ID of an image.  This identifier is a content-addressable digest calculated from the image's configuration (which includes the digests of layers used by the image).  Note that this digest differs from the `RepoDigests` below, which holds digests of image manifests that reference the image. 
    #[serde(rename = "Id")]
    pub id: String,

    /// ID of the parent image.  Depending on how the image was created, this field may be empty and is only set for images that were built/created locally. This field is empty if the image was pulled from an image registry. 
    #[serde(rename = "ParentId")]
    pub parent_id: String,

    /// List of image names/tags in the local image cache that reference this image.  Multiple image tags can refer to the same image, and this list may be empty if no tags reference the image, in which case the image is \"untagged\", in which case it can still be referenced by its ID. 
    #[serde(rename = "RepoTags")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub repo_tags: Vec<String>,

    /// List of content-addressable digests of locally available image manifests that the image is referenced from. Multiple manifests can refer to the same image.  These digests are usually only available if the image was either pulled from a registry, or if the image was pushed to a registry, which is when the manifest is generated and its digest calculated. 
    #[serde(rename = "RepoDigests")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub repo_digests: Vec<String>,

    /// Date and time at which the image was created as a Unix timestamp (number of seconds since EPOCH). 
    #[serde(rename = "Created")]
    pub created: i64,

    /// Total size of the image including all layers it is composed of. 
    #[serde(rename = "Size")]
    pub size: i64,

    /// Total size of image layers that are shared between this image and other images.  This size is not calculated by default. `-1` indicates that the value has not been set / calculated. 
    #[serde(rename = "SharedSize")]
    pub shared_size: i64,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(deserialize_with = "deserialize_nonoptional_map")]
    pub labels: HashMap<String, String>,

    /// Number of containers using this image. Includes both stopped and running containers.  `-1` indicates that the value has not been set / calculated. 
    #[serde(rename = "Containers")]
    pub containers: i64,

    /// Manifests is a list of manifests available in this image. It provides a more detailed view of the platform-specific image manifests or other image-attached data like build attestations.  WARNING: This is experimental and may change at any time without any backward compatibility. 
    #[serde(rename = "Manifests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manifests: Option<Vec<ImageManifestSummary>>,

    /// Descriptor is an OCI descriptor of the image target. In case of a multi-platform image, this descriptor points to the OCI index or a manifest list.  This field is only present if the daemon provides a multi-platform image store.  WARNING: This is experimental and may change at any time without any backward compatibility. 
    #[serde(rename = "Descriptor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub descriptor: Option<OciDescriptor>,

}

/// represents system data usage for image resources. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ImagesDiskUsage {
    /// Count of active images. 
    #[serde(rename = "ActiveCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_count: Option<i64>,

    /// Count of all images. 
    #[serde(rename = "TotalCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,

    /// Disk space that can be reclaimed by removing unused images. 
    #[serde(rename = "Reclaimable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<i64>,

    /// Disk space in use by images. 
    #[serde(rename = "TotalSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,

    /// List of image summaries. 
    #[serde(rename = "Items")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<serde_json::Value>>,

}

/// IndexInfo contains information about a registry.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IndexInfo {
    /// Name of the registry, such as \"docker.io\". 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// List of mirrors, expressed as URIs. 
    #[serde(rename = "Mirrors")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<Vec<String>>,

    /// Indicates if the registry is part of the list of insecure registries.  If `false`, the registry is insecure. Insecure registries accept un-encrypted (HTTP) and/or untrusted (HTTPS with certificates from unknown CAs) communication.  > **Warning**: Insecure registries can be useful when running a local > registry. However, because its use creates security vulnerabilities > it should ONLY be enabled for testing purposes. For increased > security, users should add their CA to their system's list of > trusted CAs instead of enabling this option. 
    #[serde(rename = "Secure")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secure: Option<bool>,

    /// Indicates whether this is an official registry (i.e., Docker Hub / docker.io) 
    #[serde(rename = "Official")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub official: Option<bool>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Ipam {
    /// Name of the IPAM driver to use.
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// List of IPAM configuration options, specified as a map:  ``` {\"Subnet\": <CIDR>, \"IPRange\": <CIDR>, \"Gateway\": <IP address>, \"AuxAddress\": <device_name:IP address>} ``` 
    #[serde(rename = "Config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<Vec<IpamConfig>>,

    /// Driver-specific options, specified as a map.
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IpamConfig {
    #[serde(rename = "Subnet")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet: Option<String>,

    #[serde(rename = "IPRange")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip_range: Option<String>,

    #[serde(rename = "Gateway")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gateway: Option<String>,

    #[serde(rename = "AuxiliaryAddresses")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auxiliary_addresses: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct IpamStatus {
    #[serde(rename = "Subnets")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnets: Option<HashMap<String, SubnetStatus>>,

}

/// JoinTokens contains the tokens workers and managers need to join the swarm. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct JoinTokens {
    /// The token workers can use to join the swarm. 
    #[serde(rename = "Worker")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub worker: Option<String>,

    /// The token managers can use to join the swarm. 
    #[serde(rename = "Manager")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager: Option<String>,

}

/// An object describing a limit on resources which can be requested by a task. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Limit {
    #[serde(rename = "NanoCPUs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,

    #[serde(rename = "MemoryBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<i64>,

    /// Limits the maximum number of PIDs in the container. Set `0` for unlimited. 
    #[serde(rename = "Pids")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids: Option<i64>,

}

/// Current local status of this node.
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum LocalNodeState { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "inactive")]
    INACTIVE,
    #[serde(rename = "pending")]
    PENDING,
    #[serde(rename = "active")]
    ACTIVE,
    #[serde(rename = "error")]
    ERROR,
    #[serde(rename = "locked")]
    LOCKED,
}

impl ::std::fmt::Display for LocalNodeState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            LocalNodeState::EMPTY => write!(f, "{}", ""),
            LocalNodeState::INACTIVE => write!(f, "{}", "inactive"),
            LocalNodeState::PENDING => write!(f, "{}", "pending"),
            LocalNodeState::ACTIVE => write!(f, "{}", "active"),
            LocalNodeState::ERROR => write!(f, "{}", "error"),
            LocalNodeState::LOCKED => write!(f, "{}", "locked"),
        }
    }
}

impl ::std::str::FromStr for LocalNodeState {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "" => Ok(LocalNodeState::EMPTY),
            "inactive" => Ok(LocalNodeState::INACTIVE),
            "pending" => Ok(LocalNodeState::PENDING),
            "active" => Ok(LocalNodeState::ACTIVE),
            "error" => Ok(LocalNodeState::ERROR),
            "locked" => Ok(LocalNodeState::LOCKED),
            _ => Err(()),
        }
    }
}

impl std::default::Default for LocalNodeState {
    fn default() -> Self { 
        LocalNodeState::EMPTY
    }
}

/// ManagerStatus represents the status of a manager.  It provides the current status of a node's manager component, if the node is a manager. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ManagerStatus {
    #[serde(rename = "Leader")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub leader: Option<bool>,

    #[serde(rename = "Reachability")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reachability: Option<Reachability>,

    /// The IP address and port at which the manager is reachable. 
    #[serde(rename = "Addr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Mount {
    /// Container path.
    #[serde(rename = "Target")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Mount source (e.g. a volume name, a host path).
    #[serde(rename = "Source")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// The mount type. Available types:  - `bind` Mounts a file or directory from the host into the container. Must exist prior to creating the container. - `volume` Creates a volume with the given name and options (or uses a pre-existing volume with the same name and options). These are **not** removed when the container is removed. - `image` Mounts an image. - `tmpfs` Create a tmpfs with the given options. The mount source cannot be specified for tmpfs. - `npipe` Mounts a named pipe from the host into the container. Must exist prior to creating the container. - `cluster` a Swarm cluster volume 
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<MountTypeEnum>,

    /// Whether the mount should be read-only.
    #[serde(rename = "ReadOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,

    /// The consistency requirement for the mount: `default`, `consistent`, `cached`, or `delegated`.
    #[serde(rename = "Consistency")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub consistency: Option<String>,

    #[serde(rename = "BindOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub bind_options: Option<MountBindOptions>,

    #[serde(rename = "VolumeOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume_options: Option<MountVolumeOptions>,

    #[serde(rename = "ImageOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image_options: Option<MountImageOptions>,

    #[serde(rename = "TmpfsOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tmpfs_options: Option<MountTmpfsOptions>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum MountTypeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "bind")]
    BIND,
    #[serde(rename = "volume")]
    VOLUME,
    #[serde(rename = "image")]
    IMAGE,
    #[serde(rename = "tmpfs")]
    TMPFS,
    #[serde(rename = "npipe")]
    NPIPE,
    #[serde(rename = "cluster")]
    CLUSTER,
}

impl ::std::fmt::Display for MountTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            MountTypeEnum::EMPTY => write!(f, ""),
            MountTypeEnum::BIND => write!(f, "{}", "bind"),
            MountTypeEnum::VOLUME => write!(f, "{}", "volume"),
            MountTypeEnum::IMAGE => write!(f, "{}", "image"),
            MountTypeEnum::TMPFS => write!(f, "{}", "tmpfs"),
            MountTypeEnum::NPIPE => write!(f, "{}", "npipe"),
            MountTypeEnum::CLUSTER => write!(f, "{}", "cluster"),

        }
    }
}

impl ::std::str::FromStr for MountTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(MountTypeEnum::EMPTY),
            "bind" => Ok(MountTypeEnum::BIND),
            "volume" => Ok(MountTypeEnum::VOLUME),
            "image" => Ok(MountTypeEnum::IMAGE),
            "tmpfs" => Ok(MountTypeEnum::TMPFS),
            "npipe" => Ok(MountTypeEnum::NPIPE),
            "cluster" => Ok(MountTypeEnum::CLUSTER),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for MountTypeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            MountTypeEnum::EMPTY => "",
            MountTypeEnum::BIND => "bind",
            MountTypeEnum::VOLUME => "volume",
            MountTypeEnum::IMAGE => "image",
            MountTypeEnum::TMPFS => "tmpfs",
            MountTypeEnum::NPIPE => "npipe",
            MountTypeEnum::CLUSTER => "cluster",
        }
    }
}

/// Optional configuration for the `bind` type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountBindOptions {
    /// A propagation mode with the value `[r]private`, `[r]shared`, or `[r]slave`.
    #[serde(rename = "Propagation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation: Option<MountBindOptionsPropagationEnum>,

    /// Disable recursive bind mount.
    #[serde(rename = "NonRecursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub non_recursive: Option<bool>,

    /// Create mount point on host if missing
    #[serde(rename = "CreateMountpoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub create_mountpoint: Option<bool>,

    /// Make the mount non-recursively read-only, but still leave the mount recursive (unless NonRecursive is set to `true` in conjunction).  Added in v1.44, before that version all read-only mounts were non-recursive by default. To match the previous behaviour this will default to `true` for clients on versions prior to v1.44. 
    #[serde(rename = "ReadOnlyNonRecursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_non_recursive: Option<bool>,

    /// Raise an error if the mount cannot be made recursively read-only.
    #[serde(rename = "ReadOnlyForceRecursive")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only_force_recursive: Option<bool>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum MountBindOptionsPropagationEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "private")]
    PRIVATE,
    #[serde(rename = "rprivate")]
    RPRIVATE,
    #[serde(rename = "shared")]
    SHARED,
    #[serde(rename = "rshared")]
    RSHARED,
    #[serde(rename = "slave")]
    SLAVE,
    #[serde(rename = "rslave")]
    RSLAVE,
}

impl ::std::fmt::Display for MountBindOptionsPropagationEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            MountBindOptionsPropagationEnum::EMPTY => write!(f, ""),
            MountBindOptionsPropagationEnum::PRIVATE => write!(f, "{}", "private"),
            MountBindOptionsPropagationEnum::RPRIVATE => write!(f, "{}", "rprivate"),
            MountBindOptionsPropagationEnum::SHARED => write!(f, "{}", "shared"),
            MountBindOptionsPropagationEnum::RSHARED => write!(f, "{}", "rshared"),
            MountBindOptionsPropagationEnum::SLAVE => write!(f, "{}", "slave"),
            MountBindOptionsPropagationEnum::RSLAVE => write!(f, "{}", "rslave"),

        }
    }
}

impl ::std::str::FromStr for MountBindOptionsPropagationEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(MountBindOptionsPropagationEnum::EMPTY),
            "private" => Ok(MountBindOptionsPropagationEnum::PRIVATE),
            "rprivate" => Ok(MountBindOptionsPropagationEnum::RPRIVATE),
            "shared" => Ok(MountBindOptionsPropagationEnum::SHARED),
            "rshared" => Ok(MountBindOptionsPropagationEnum::RSHARED),
            "slave" => Ok(MountBindOptionsPropagationEnum::SLAVE),
            "rslave" => Ok(MountBindOptionsPropagationEnum::RSLAVE),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for MountBindOptionsPropagationEnum {
    fn as_ref(&self) -> &str {
        match self { 
            MountBindOptionsPropagationEnum::EMPTY => "",
            MountBindOptionsPropagationEnum::PRIVATE => "private",
            MountBindOptionsPropagationEnum::RPRIVATE => "rprivate",
            MountBindOptionsPropagationEnum::SHARED => "shared",
            MountBindOptionsPropagationEnum::RSHARED => "rshared",
            MountBindOptionsPropagationEnum::SLAVE => "slave",
            MountBindOptionsPropagationEnum::RSLAVE => "rslave",
        }
    }
}

/// Optional configuration for the `image` type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountImageOptions {
    /// Source path inside the image. Must be relative without any back traversals.
    #[serde(rename = "Subpath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,

}

/// MountPoint represents a mount point configuration inside the container. This is used for reporting the mountpoints in use by a container. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountPoint {
    /// The mount type:  - `bind` a mount of a file or directory from the host into the container. - `volume` a docker volume with the given `Name`. - `image` a docker image - `tmpfs` a `tmpfs`. - `npipe` a named pipe from the host into the container. - `cluster` a Swarm cluster volume 
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<MountPointTypeEnum>,

    /// Name is the name reference to the underlying data defined by `Source` e.g., the volume name. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Source location of the mount.  For volumes, this contains the storage location of the volume (within `/var/lib/docker/volumes/`). For bind-mounts, and `npipe`, this contains the source (host) part of the bind-mount. For `tmpfs` mount points, this field is empty. 
    #[serde(rename = "Source")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub source: Option<String>,

    /// Destination is the path relative to the container root (`/`) where the `Source` is mounted inside the container. 
    #[serde(rename = "Destination")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub destination: Option<String>,

    /// Driver is the volume driver used to create the volume (if it is a volume). 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Mode is a comma separated list of options supplied by the user when creating the bind/volume mount.  The default is platform-specific (`\"z\"` on Linux, empty on Windows). 
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<String>,

    /// Whether the mount is mounted writable (read-write). 
    #[serde(rename = "RW")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rw: Option<bool>,

    /// Propagation describes how mounts are propagated from the host into the mount point, and vice-versa. Refer to the [Linux kernel documentation](https://www.kernel.org/doc/Documentation/filesystems/sharedsubtree.txt) for details. This field is not used on Windows. 
    #[serde(rename = "Propagation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub propagation: Option<String>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum MountPointTypeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "bind")]
    BIND,
    #[serde(rename = "volume")]
    VOLUME,
    #[serde(rename = "image")]
    IMAGE,
    #[serde(rename = "tmpfs")]
    TMPFS,
    #[serde(rename = "npipe")]
    NPIPE,
    #[serde(rename = "cluster")]
    CLUSTER,
}

impl ::std::fmt::Display for MountPointTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            MountPointTypeEnum::EMPTY => write!(f, ""),
            MountPointTypeEnum::BIND => write!(f, "{}", "bind"),
            MountPointTypeEnum::VOLUME => write!(f, "{}", "volume"),
            MountPointTypeEnum::IMAGE => write!(f, "{}", "image"),
            MountPointTypeEnum::TMPFS => write!(f, "{}", "tmpfs"),
            MountPointTypeEnum::NPIPE => write!(f, "{}", "npipe"),
            MountPointTypeEnum::CLUSTER => write!(f, "{}", "cluster"),

        }
    }
}

impl ::std::str::FromStr for MountPointTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(MountPointTypeEnum::EMPTY),
            "bind" => Ok(MountPointTypeEnum::BIND),
            "volume" => Ok(MountPointTypeEnum::VOLUME),
            "image" => Ok(MountPointTypeEnum::IMAGE),
            "tmpfs" => Ok(MountPointTypeEnum::TMPFS),
            "npipe" => Ok(MountPointTypeEnum::NPIPE),
            "cluster" => Ok(MountPointTypeEnum::CLUSTER),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for MountPointTypeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            MountPointTypeEnum::EMPTY => "",
            MountPointTypeEnum::BIND => "bind",
            MountPointTypeEnum::VOLUME => "volume",
            MountPointTypeEnum::IMAGE => "image",
            MountPointTypeEnum::TMPFS => "tmpfs",
            MountPointTypeEnum::NPIPE => "npipe",
            MountPointTypeEnum::CLUSTER => "cluster",
        }
    }
}

/// Optional configuration for the `tmpfs` type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountTmpfsOptions {
    /// The size for the tmpfs mount in bytes.
    #[serde(rename = "SizeBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size_bytes: Option<i64>,

    /// The permission mode for the tmpfs mount in an integer.
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<i64>,

    /// The options to be passed to the tmpfs mount. An array of arrays. Flag options should be provided as 1-length arrays. Other types should be provided as as 2-length arrays, where the first item is the key and the second the value. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<Vec<String>>>,

}

/// Optional configuration for the `volume` type.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountVolumeOptions {
    /// Populate volume with data from the target.
    #[serde(rename = "NoCopy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_copy: Option<bool>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "DriverConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_config: Option<MountVolumeOptionsDriverConfig>,

    /// Source path inside the volume. Must be relative without any back traversals.
    #[serde(rename = "Subpath")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subpath: Option<String>,

}

/// Map of driver specific options
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MountVolumeOptionsDriverConfig {
    /// Name of the driver to use to create the volume.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// key/value map of driver specific options.
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Network {
    /// Name of the network. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// ID that uniquely identifies a network on a single machine. 
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Date and time at which the network was created in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created: Option<BollardDate>,

    /// The level at which the network exists (e.g. `swarm` for cluster-wide or `local` for machine level) 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The name of the driver used to create the network (e.g. `bridge`, `overlay`). 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Whether the network was created with IPv4 enabled. 
    #[serde(rename = "EnableIPv4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv4: Option<bool>,

    /// Whether the network was created with IPv6 enabled. 
    #[serde(rename = "EnableIPv6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv6: Option<bool>,

    /// The network's IP Address Management. 
    #[serde(rename = "IPAM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,

    /// Whether the network is created to only allow internal networking connectivity. 
    #[serde(rename = "Internal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,

    /// Whether a global / swarm scope network is manually attachable by regular containers from workers in swarm mode. 
    #[serde(rename = "Attachable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachable: Option<bool>,

    /// Whether the network is providing the routing-mesh for the swarm cluster. 
    #[serde(rename = "Ingress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<bool>,

    #[serde(rename = "ConfigFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_from: Option<ConfigReference>,

    /// Whether the network is a config-only network. Config-only networks are placeholder networks for network configurations to be used by other networks. Config-only networks cannot be used directly to run containers or services. 
    #[serde(rename = "ConfigOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_only: Option<bool>,

    /// Network-specific options uses when creating the network. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

    /// Metadata specific to the network being created. 
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// List of peer nodes for an overlay network. This field is only present for overlay networks, and omitted for other network types. 
    #[serde(rename = "Peers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerInfo>>,

}

/// Specifies how a service should be attached to a particular network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkAttachmentConfig {
    /// The target network for attachment. Must be a network name or ID. 
    #[serde(rename = "Target")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,

    /// Discoverable alternate names for the service on this network. 
    #[serde(rename = "Aliases")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub aliases: Option<Vec<String>>,

    /// Driver attachment options for the network target. 
    #[serde(rename = "DriverOpts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_opts: Option<HashMap<String, String>>,

}

/// NetworkConnectRequest represents the data to be used to connect a container to a network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkConnectRequest {
    /// The ID or name of the container to connect to the network.
    #[serde(rename = "Container")]
    pub container: String,

    #[serde(rename = "EndpointConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_config: Option<EndpointSettings>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkCreateRequest {
    /// The network's name.
    #[serde(rename = "Name")]
    pub name: String,

    /// Name of the network driver plugin to use.
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// The level at which the network exists (e.g. `swarm` for cluster-wide or `local` for machine level). 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// Restrict external access to the network.
    #[serde(rename = "Internal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,

    /// Globally scoped network is manually attachable by regular containers from workers in swarm mode. 
    #[serde(rename = "Attachable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachable: Option<bool>,

    /// Ingress network is the network which provides the routing-mesh in swarm mode. 
    #[serde(rename = "Ingress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<bool>,

    /// Creates a config-only network. Config-only networks are placeholder networks for network configurations to be used by other networks. Config-only networks cannot be used directly to run containers or services. 
    #[serde(rename = "ConfigOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_only: Option<bool>,

    /// Specifies the source which will provide the configuration for this network. The specified network must be an existing config-only network; see ConfigOnly. 
    #[serde(rename = "ConfigFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_from: Option<ConfigReference>,

    /// Optional custom IP scheme for the network.
    #[serde(rename = "IPAM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,

    /// Enable IPv4 on the network.
    #[serde(rename = "EnableIPv4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv4: Option<bool>,

    /// Enable IPv6 on the network.
    #[serde(rename = "EnableIPv6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv6: Option<bool>,

    /// Network specific options to be used by the drivers.
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

}

/// OK response to NetworkCreate operation
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkCreateResponse {
    /// The ID of the created network.
    #[serde(rename = "Id")]
    pub id: String,

    /// Warnings encountered when creating the container
    #[serde(rename = "Warning")]
    pub warning: String,

}

/// NetworkDisconnectRequest represents the data to be used to disconnect a container from a network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkDisconnectRequest {
    /// The ID or name of the container to disconnect from the network.
    #[serde(rename = "Container")]
    pub container: String,

    /// Force the container to disconnect from the network.
    #[serde(rename = "Force")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force: Option<bool>,

}

/// The body of the \"get network\" http response message.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkInspect {
    /// Name of the network. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// ID that uniquely identifies a network on a single machine. 
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Date and time at which the network was created in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created: Option<BollardDate>,

    /// The level at which the network exists (e.g. `swarm` for cluster-wide or `local` for machine level) 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The name of the driver used to create the network (e.g. `bridge`, `overlay`). 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Whether the network was created with IPv4 enabled. 
    #[serde(rename = "EnableIPv4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv4: Option<bool>,

    /// Whether the network was created with IPv6 enabled. 
    #[serde(rename = "EnableIPv6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv6: Option<bool>,

    /// The network's IP Address Management. 
    #[serde(rename = "IPAM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,

    /// Whether the network is created to only allow internal networking connectivity. 
    #[serde(rename = "Internal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,

    /// Whether a global / swarm scope network is manually attachable by regular containers from workers in swarm mode. 
    #[serde(rename = "Attachable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachable: Option<bool>,

    /// Whether the network is providing the routing-mesh for the swarm cluster. 
    #[serde(rename = "Ingress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<bool>,

    #[serde(rename = "ConfigFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_from: Option<ConfigReference>,

    /// Whether the network is a config-only network. Config-only networks are placeholder networks for network configurations to be used by other networks. Config-only networks cannot be used directly to run containers or services. 
    #[serde(rename = "ConfigOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_only: Option<bool>,

    /// Network-specific options uses when creating the network. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

    /// Metadata specific to the network being created. 
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// List of peer nodes for an overlay network. This field is only present for overlay networks, and omitted for other network types. 
    #[serde(rename = "Peers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerInfo>>,

    /// Contains endpoints attached to the network. 
    #[serde(rename = "Containers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<HashMap<String, EndpointResource>>,

    /// List of services using the network. This field is only present for swarm scope networks, and omitted for local scope networks. 
    #[serde(rename = "Services")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub services: Option<HashMap<String, serde_json::Value>>,

    /// provides runtime information about the network such as the number of allocated IPs. 
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<NetworkStatus>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkPruneResponse {
    /// Networks that were deleted
    #[serde(rename = "NetworksDeleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks_deleted: Option<Vec<String>>,

}

/// NetworkSettings exposes the network settings in the API
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkSettings {
    /// SandboxID uniquely represents a container's network stack.
    #[serde(rename = "SandboxID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_id: Option<String>,

    /// SandboxKey is the full path of the netns handle
    #[serde(rename = "SandboxKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sandbox_key: Option<String>,

    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<PortMap>,

    /// Information about all networks that the container is connected to. 
    #[serde(rename = "Networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<HashMap<String, EndpointSettings>>,

}

/// provides runtime information about the network such as the number of allocated IPs. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkStatus {
    #[serde(rename = "IPAM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<IpamStatus>,

}

/// Network list response item
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkSummary {
    /// Name of the network. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// ID that uniquely identifies a network on a single machine. 
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Date and time at which the network was created in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "Created")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created: Option<BollardDate>,

    /// The level at which the network exists (e.g. `swarm` for cluster-wide or `local` for machine level) 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub scope: Option<String>,

    /// The name of the driver used to create the network (e.g. `bridge`, `overlay`). 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Whether the network was created with IPv4 enabled. 
    #[serde(rename = "EnableIPv4")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv4: Option<bool>,

    /// Whether the network was created with IPv6 enabled. 
    #[serde(rename = "EnableIPv6")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub enable_ipv6: Option<bool>,

    /// The network's IP Address Management. 
    #[serde(rename = "IPAM")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipam: Option<Ipam>,

    /// Whether the network is created to only allow internal networking connectivity. 
    #[serde(rename = "Internal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub internal: Option<bool>,

    /// Whether a global / swarm scope network is manually attachable by regular containers from workers in swarm mode. 
    #[serde(rename = "Attachable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub attachable: Option<bool>,

    /// Whether the network is providing the routing-mesh for the swarm cluster. 
    #[serde(rename = "Ingress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ingress: Option<bool>,

    #[serde(rename = "ConfigFrom")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_from: Option<ConfigReference>,

    /// Whether the network is a config-only network. Config-only networks are placeholder networks for network configurations to be used by other networks. Config-only networks cannot be used directly to run containers or services. 
    #[serde(rename = "ConfigOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_only: Option<bool>,

    /// Network-specific options uses when creating the network. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

    /// Metadata specific to the network being created. 
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// List of peer nodes for an overlay network. This field is only present for overlay networks, and omitted for other network types. 
    #[serde(rename = "Peers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub peers: Option<Vec<PeerInfo>>,

}

/// carries the information about one backend task 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkTaskInfo {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "EndpointID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_id: Option<String>,

    #[serde(rename = "EndpointIP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_ip: Option<String>,

    #[serde(rename = "Info")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub info: Option<HashMap<String, String>>,

}

/// NetworkingConfig represents the container's networking configuration for each of its interfaces. It is used for the networking configs specified in the `docker create` and `docker network connect` commands. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NetworkingConfig {
    /// A mapping of network name to endpoint configuration for that network. The endpoint configuration can be left empty to connect to that network with no particular endpoint configuration. 
    #[serde(rename = "EndpointsConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoints_config: Option<HashMap<String, EndpointSettings>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Node {
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    /// Date and time at which the node was added to the swarm in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    /// Date and time at which the node was last updated in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<NodeSpec>,

    #[serde(rename = "Description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<NodeDescription>,

    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<NodeStatus>,

    #[serde(rename = "ManagerStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub manager_status: Option<ManagerStatus>,

}

/// NodeDescription encapsulates the properties of the Node as reported by the agent. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeDescription {
    #[serde(rename = "Hostname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    #[serde(rename = "Platform")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<Platform>,

    #[serde(rename = "Resources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<ResourceObject>,

    #[serde(rename = "Engine")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub engine: Option<EngineDescription>,

    #[serde(rename = "TLSInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeSpec {
    /// Name for the node.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Role of the node.
    #[serde(rename = "Role")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<NodeSpecRoleEnum>,

    /// Availability of the node.
    #[serde(rename = "Availability")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub availability: Option<NodeSpecAvailabilityEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum NodeSpecRoleEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "worker")]
    WORKER,
    #[serde(rename = "manager")]
    MANAGER,
}

impl ::std::fmt::Display for NodeSpecRoleEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            NodeSpecRoleEnum::EMPTY => write!(f, ""),
            NodeSpecRoleEnum::WORKER => write!(f, "{}", "worker"),
            NodeSpecRoleEnum::MANAGER => write!(f, "{}", "manager"),

        }
    }
}

impl ::std::str::FromStr for NodeSpecRoleEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(NodeSpecRoleEnum::EMPTY),
            "worker" => Ok(NodeSpecRoleEnum::WORKER),
            "manager" => Ok(NodeSpecRoleEnum::MANAGER),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for NodeSpecRoleEnum {
    fn as_ref(&self) -> &str {
        match self { 
            NodeSpecRoleEnum::EMPTY => "",
            NodeSpecRoleEnum::WORKER => "worker",
            NodeSpecRoleEnum::MANAGER => "manager",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum NodeSpecAvailabilityEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "active")]
    ACTIVE,
    #[serde(rename = "pause")]
    PAUSE,
    #[serde(rename = "drain")]
    DRAIN,
}

impl ::std::fmt::Display for NodeSpecAvailabilityEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            NodeSpecAvailabilityEnum::EMPTY => write!(f, ""),
            NodeSpecAvailabilityEnum::ACTIVE => write!(f, "{}", "active"),
            NodeSpecAvailabilityEnum::PAUSE => write!(f, "{}", "pause"),
            NodeSpecAvailabilityEnum::DRAIN => write!(f, "{}", "drain"),

        }
    }
}

impl ::std::str::FromStr for NodeSpecAvailabilityEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(NodeSpecAvailabilityEnum::EMPTY),
            "active" => Ok(NodeSpecAvailabilityEnum::ACTIVE),
            "pause" => Ok(NodeSpecAvailabilityEnum::PAUSE),
            "drain" => Ok(NodeSpecAvailabilityEnum::DRAIN),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for NodeSpecAvailabilityEnum {
    fn as_ref(&self) -> &str {
        match self { 
            NodeSpecAvailabilityEnum::EMPTY => "",
            NodeSpecAvailabilityEnum::ACTIVE => "active",
            NodeSpecAvailabilityEnum::PAUSE => "pause",
            NodeSpecAvailabilityEnum::DRAIN => "drain",
        }
    }
}

/// NodeState represents the state of a node.
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum NodeState { 
    #[serde(rename = "unknown")]
    UNKNOWN,
    #[serde(rename = "down")]
    DOWN,
    #[serde(rename = "ready")]
    READY,
    #[serde(rename = "disconnected")]
    DISCONNECTED,
}

impl ::std::fmt::Display for NodeState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            NodeState::UNKNOWN => write!(f, "{}", "unknown"),
            NodeState::DOWN => write!(f, "{}", "down"),
            NodeState::READY => write!(f, "{}", "ready"),
            NodeState::DISCONNECTED => write!(f, "{}", "disconnected"),
        }
    }
}

impl ::std::str::FromStr for NodeState {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(NodeState::UNKNOWN),
            "down" => Ok(NodeState::DOWN),
            "ready" => Ok(NodeState::READY),
            "disconnected" => Ok(NodeState::DISCONNECTED),
            _ => Err(()),
        }
    }
}

impl std::default::Default for NodeState {
    fn default() -> Self { 
        NodeState::UNKNOWN
    }
}

/// NodeStatus represents the status of a node.  It provides the current status of the node, as seen by the manager. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct NodeStatus {
    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<NodeState>,

    #[serde(rename = "Message")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    /// IP address of the node.
    #[serde(rename = "Addr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

}

/// The version number of the object such as node, service, etc. This is needed to avoid conflicting writes. The client must send the version number along with the modified specification when updating these objects.  This approach ensures safe concurrency and determinism in that the change on the object may not be applied if the version number has changed from the last read. In other words, if two update requests specify the same base version, only one of the requests can succeed. As a result, two separate update requests that happen at the same time will not unintentionally overwrite each other. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ObjectVersion {
    #[serde(rename = "Index")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index: Option<u64>,

}

/// A descriptor struct containing digest, media type, and size, as defined in the [OCI Content Descriptors Specification](https://github.com/opencontainers/image-spec/blob/v1.0.1/descriptor.md). 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OciDescriptor {
    /// The media type of the object this schema refers to. 
    #[serde(rename = "mediaType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub media_type: Option<String>,

    /// The digest of the targeted content. 
    #[serde(rename = "digest")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub digest: Option<String>,

    /// The size in bytes of the blob. 
    #[serde(rename = "size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,

    /// List of URLs from which this object MAY be downloaded.
    #[serde(rename = "urls")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub urls: Option<Vec<String>>,

    /// Arbitrary metadata relating to the targeted content.
    #[serde(rename = "annotations")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub annotations: Option<HashMap<String, String>>,

    /// Data is an embedding of the targeted content. This is encoded as a base64 string when marshalled to JSON (automatically, by encoding/json). If present, Data can be used directly to avoid fetching the targeted content.
    #[serde(rename = "data")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    #[serde(rename = "platform")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<OciPlatform>,

    /// ArtifactType is the IANA media type of this artifact.
    #[serde(rename = "artifactType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub artifact_type: Option<String>,

}

/// Describes the platform which the image in the manifest runs on, as defined in the [OCI Image Index Specification](https://github.com/opencontainers/image-spec/blob/v1.0.1/image-index.md). 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct OciPlatform {
    /// The CPU architecture, for example `amd64` or `ppc64`. 
    #[serde(rename = "architecture")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,

    /// The operating system, for example `linux` or `windows`. 
    #[serde(rename = "os")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// Optional field specifying the operating system version, for example on Windows `10.0.19041.1165`. 
    #[serde(rename = "os.version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// Optional field specifying an array of strings, each listing a required OS feature (for example on Windows `win32k`). 
    #[serde(rename = "os.features")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_features: Option<Vec<String>>,

    /// Optional field specifying a variant of the CPU, for example `v7` to specify ARMv7 when architecture is `arm`. 
    #[serde(rename = "variant")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub variant: Option<String>,

}

/// represents one peer of an overlay network. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerInfo {
    /// ID of the peer-node in the Swarm cluster.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// IP-address of the peer-node in the Swarm cluster.
    #[serde(rename = "IP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

}

/// Represents a peer-node in the swarm
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PeerNode {
    /// Unique identifier of for this node in the swarm.
    #[serde(rename = "NodeID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// IP address and ports at which this node can be reached. 
    #[serde(rename = "Addr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

}

/// Platform represents the platform (Arch/OS). 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Platform {
    /// Architecture represents the hardware architecture (for example, `x86_64`). 
    #[serde(rename = "Architecture")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,

    /// OS represents the Operating System (for example, `linux` or `windows`). 
    #[serde(rename = "OS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

}

/// A plugin for the Engine API
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Plugin {
    #[serde(rename = "Id")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Name")]
    pub name: String,

    /// True if the plugin is running. False if the plugin is not running, only installed.
    #[serde(rename = "Enabled")]
    pub enabled: bool,

    #[serde(rename = "Settings")]
    pub settings: PluginSettings,

    /// plugin remote reference used to push/pull the plugin
    #[serde(rename = "PluginReference")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_reference: Option<String>,

    #[serde(rename = "Config")]
    pub config: PluginConfig,

}

/// The config of a plugin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfig {
    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Documentation")]
    pub documentation: String,

    #[serde(rename = "Interface")]
    pub interface: PluginConfigInterface,

    #[serde(rename = "Entrypoint")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub entrypoint: Vec<String>,

    #[serde(rename = "WorkDir")]
    pub work_dir: String,

    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<PluginConfigUser>,

    #[serde(rename = "Network")]
    pub network: PluginConfigNetwork,

    #[serde(rename = "Linux")]
    pub linux: PluginConfigLinux,

    #[serde(rename = "PropagatedMount")]
    pub propagated_mount: String,

    #[serde(rename = "IpcHost")]
    pub ipc_host: bool,

    #[serde(rename = "PidHost")]
    pub pid_host: bool,

    #[serde(rename = "Mounts")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub mounts: Vec<PluginMount>,

    #[serde(rename = "Env")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub env: Vec<PluginEnv>,

    #[serde(rename = "Args")]
    pub args: PluginConfigArgs,

    #[serde(rename = "rootfs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rootfs: Option<PluginConfigRootfs>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigArgs {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Settable")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub settable: Vec<String>,

    #[serde(rename = "Value")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub value: Vec<String>,

}

/// The interface between Docker and the plugin
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigInterface {
    #[serde(rename = "Types")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub types: Vec<String>,

    #[serde(rename = "Socket")]
    pub socket: String,

    /// Protocol to use for clients connecting to the plugin.
    #[serde(rename = "ProtocolScheme")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol_scheme: Option<PluginConfigInterfaceProtocolSchemeEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum PluginConfigInterfaceProtocolSchemeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "moby.plugins.http/v1")]
    MOBY_PLUGINS_HTTP_V1,
}

impl ::std::fmt::Display for PluginConfigInterfaceProtocolSchemeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            PluginConfigInterfaceProtocolSchemeEnum::EMPTY => write!(f, "{}", ""),
            PluginConfigInterfaceProtocolSchemeEnum::MOBY_PLUGINS_HTTP_V1 => write!(f, "{}", "moby.plugins.http/v1"),

        }
    }
}

impl ::std::str::FromStr for PluginConfigInterfaceProtocolSchemeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(PluginConfigInterfaceProtocolSchemeEnum::EMPTY),
            "moby.plugins.http/v1" => Ok(PluginConfigInterfaceProtocolSchemeEnum::MOBY_PLUGINS_HTTP_V1),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for PluginConfigInterfaceProtocolSchemeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            PluginConfigInterfaceProtocolSchemeEnum::EMPTY => "",
            PluginConfigInterfaceProtocolSchemeEnum::MOBY_PLUGINS_HTTP_V1 => "moby.plugins.http/v1",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigLinux {
    #[serde(rename = "Capabilities")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub capabilities: Vec<String>,

    #[serde(rename = "AllowAllDevices")]
    pub allow_all_devices: bool,

    #[serde(rename = "Devices")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub devices: Vec<PluginDevice>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigNetwork {
    #[serde(rename = "Type")]
    pub typ: String,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigRootfs {
    #[serde(rename = "type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    #[serde(rename = "diff_ids")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub diff_ids: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginConfigUser {
    #[serde(rename = "UID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<u32>,

    #[serde(rename = "GID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<u32>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginDevice {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Settable")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub settable: Vec<String>,

    #[serde(rename = "Path")]
    pub path: String,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginEnv {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Settable")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub settable: Vec<String>,

    #[serde(rename = "Value")]
    pub value: String,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginMount {
    #[serde(rename = "Name")]
    pub name: String,

    #[serde(rename = "Description")]
    pub description: String,

    #[serde(rename = "Settable")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub settable: Vec<String>,

    #[serde(rename = "Source")]
    pub source: String,

    #[serde(rename = "Destination")]
    pub destination: String,

    #[serde(rename = "Type")]
    pub typ: String,

    #[serde(rename = "Options")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub options: Vec<String>,

}

/// Describes a permission the user has to accept upon installing the plugin. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginPrivilege {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "Description")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub description: Option<String>,

    #[serde(rename = "Value")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub value: Option<Vec<String>>,

}

/// user-configurable settings for the plugin.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginSettings {
    #[serde(rename = "Mounts")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub mounts: Vec<PluginMount>,

    #[serde(rename = "Env")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub env: Vec<String>,

    #[serde(rename = "Args")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub args: Vec<String>,

    #[serde(rename = "Devices")]
    #[serde(deserialize_with = "deserialize_nonoptional_vec")]
    pub devices: Vec<PluginDevice>,

}

/// Available plugins per type.  <p><br /></p>  > **Note**: Only unmanaged (V1) plugins are included in this list. > V1 plugins are \"lazily\" loaded, and are not returned in this list > if there is no resource using the plugin. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PluginsInfo {
    /// Names of available volume-drivers, and network-driver plugins.
    #[serde(rename = "Volume")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volume: Option<Vec<String>>,

    /// Names of available network-drivers, and network-driver plugins.
    #[serde(rename = "Network")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network: Option<Vec<String>>,

    /// Names of available authorization plugins.
    #[serde(rename = "Authorization")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub authorization: Option<Vec<String>>,

    /// Names of available logging-drivers, and logging-driver plugins.
    #[serde(rename = "Log")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log: Option<Vec<String>>,

}

/// PortBinding represents a binding between a host IP address and a host port. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PortBinding {
    /// Host IP address that the container's port is mapped to.
    #[serde(rename = "HostIp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_ip: Option<String>,

    /// Host port number that the container's port is mapped to.
    #[serde(rename = "HostPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub host_port: Option<String>,

}

/// PortMap describes the mapping of container ports to host ports, using the container's port-number and protocol as key in the format `<port>/<protocol>`, for example, `80/udp`.  If a container's port is mapped for multiple protocols, separate entries are added to the mapping table. 
// special-casing PortMap, cos swagger-codegen doesn't figure out this type
pub type PortMap = HashMap<String, Option<Vec<PortBinding>>>;

/// represents the port status of a task's host ports whose service has published host ports
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PortStatus {
    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<EndpointPortConfig>>,

}

/// Describes a port-mapping between the container and the host. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PortSummary {
    /// Host IP address that the container's port is mapped to
    #[serde(rename = "IP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ip: Option<String>,

    /// Port on the container
    #[serde(rename = "PrivatePort")]
    pub private_port: u16,

    /// Port exposed on the host
    #[serde(rename = "PublicPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_port: Option<u16>,

    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_ext::none_as_empty_string")]
    pub typ: Option<PortSummaryTypeEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum PortSummaryTypeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "tcp")]
    TCP,
    #[serde(rename = "udp")]
    UDP,
    #[serde(rename = "sctp")]
    SCTP,
}

impl ::std::fmt::Display for PortSummaryTypeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            PortSummaryTypeEnum::EMPTY => write!(f, ""),
            PortSummaryTypeEnum::TCP => write!(f, "{}", "tcp"),
            PortSummaryTypeEnum::UDP => write!(f, "{}", "udp"),
            PortSummaryTypeEnum::SCTP => write!(f, "{}", "sctp"),

        }
    }
}

impl ::std::str::FromStr for PortSummaryTypeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(PortSummaryTypeEnum::EMPTY),
            "tcp" => Ok(PortSummaryTypeEnum::TCP),
            "udp" => Ok(PortSummaryTypeEnum::UDP),
            "sctp" => Ok(PortSummaryTypeEnum::SCTP),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for PortSummaryTypeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            PortSummaryTypeEnum::EMPTY => "",
            PortSummaryTypeEnum::TCP => "tcp",
            PortSummaryTypeEnum::UDP => "udp",
            PortSummaryTypeEnum::SCTP => "sctp",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProcessConfig {
    #[serde(rename = "privileged")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileged: Option<bool>,

    #[serde(rename = "user")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    #[serde(rename = "tty")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    #[serde(rename = "entrypoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub entrypoint: Option<String>,

    #[serde(rename = "arguments")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arguments: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ProgressDetail {
    #[serde(rename = "current")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub current: Option<i64>,

    #[serde(rename = "total")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct PushImageInfo {
    #[serde(rename = "errorDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error_detail: Option<ErrorDetail>,

    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<String>,

    #[serde(rename = "progressDetail")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub progress_detail: Option<ProgressDetail>,

}

/// Reachability represents the reachability of a node.
/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum Reachability { 
    #[serde(rename = "unknown")]
    UNKNOWN,
    #[serde(rename = "unreachable")]
    UNREACHABLE,
    #[serde(rename = "reachable")]
    REACHABLE,
}

impl ::std::fmt::Display for Reachability {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            Reachability::UNKNOWN => write!(f, "{}", "unknown"),
            Reachability::UNREACHABLE => write!(f, "{}", "unreachable"),
            Reachability::REACHABLE => write!(f, "{}", "reachable"),
        }
    }
}

impl ::std::str::FromStr for Reachability {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "unknown" => Ok(Reachability::UNKNOWN),
            "unreachable" => Ok(Reachability::UNREACHABLE),
            "reachable" => Ok(Reachability::REACHABLE),
            _ => Err(()),
        }
    }
}

impl std::default::Default for Reachability {
    fn default() -> Self { 
        Reachability::UNKNOWN
    }
}

/// RegistryServiceConfig stores daemon registry services configuration. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RegistryServiceConfig {
    /// List of IP ranges of insecure registries, using the CIDR syntax ([RFC 4632](https://tools.ietf.org/html/4632)). Insecure registries accept un-encrypted (HTTP) and/or untrusted (HTTPS with certificates from unknown CAs) communication.  By default, local registries (`::1/128` and `127.0.0.0/8`) are configured as insecure. All other registries are secure. Communicating with an insecure registry is not possible if the daemon assumes that registry is secure.  This configuration override this behavior, insecure communication with registries whose resolved IP address is within the subnet described by the CIDR syntax.  Registries can also be marked insecure by hostname. Those registries are listed under `IndexConfigs` and have their `Secure` field set to `false`.  > **Warning**: Using this option can be useful when running a local > registry, but introduces security vulnerabilities. This option > should therefore ONLY be used for testing purposes. For increased > security, users should add their CA to their system's list of trusted > CAs instead of enabling this option. 
    #[serde(rename = "InsecureRegistryCIDRs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub insecure_registry_cidrs: Option<Vec<String>>,

    #[serde(rename = "IndexConfigs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_configs: Option<HashMap<String, IndexInfo>>,

    /// List of registry URLs that act as a mirror for the official (`docker.io`) registry. 
    #[serde(rename = "Mirrors")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mirrors: Option<Vec<String>>,

}

/// An object describing the resources which can be advertised by a node and requested by a task. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourceObject {
    #[serde(rename = "NanoCPUs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,

    #[serde(rename = "MemoryBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_bytes: Option<i64>,

    #[serde(rename = "GenericResources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_resources: Option<GenericResources>,

}

/// A container's resources (cgroups config, ulimits, etc)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Resources {
    /// An integer value representing this container's relative CPU weight versus other containers. 
    #[serde(rename = "CpuShares")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<i64>,

    /// Memory limit in bytes.
    #[serde(rename = "Memory")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory: Option<i64>,

    /// Path to `cgroups` under which the container's `cgroup` is created. If the path is not absolute, the path is considered to be relative to the `cgroups` path of the init process. Cgroups are created if they do not already exist. 
    #[serde(rename = "CgroupParent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_parent: Option<String>,

    /// Block IO weight (relative weight).
    #[serde(rename = "BlkioWeight")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight: Option<u16>,

    /// Block IO weight (relative device weight) in the form:  ``` [{\"Path\": \"device_path\", \"Weight\": weight}] ``` 
    #[serde(rename = "BlkioWeightDevice")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_weight_device: Option<Vec<ResourcesBlkioWeightDevice>>,

    /// Limit read rate (bytes per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_bps: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (bytes per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteBps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_bps: Option<Vec<ThrottleDevice>>,

    /// Limit read rate (IO per second) from a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceReadIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_read_iops: Option<Vec<ThrottleDevice>>,

    /// Limit write rate (IO per second) to a device, in the form:  ``` [{\"Path\": \"device_path\", \"Rate\": rate}] ``` 
    #[serde(rename = "BlkioDeviceWriteIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub blkio_device_write_iops: Option<Vec<ThrottleDevice>>,

    /// The length of a CPU period in microseconds.
    #[serde(rename = "CpuPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_period: Option<i64>,

    /// Microseconds of CPU time that the container can get in a CPU period. 
    #[serde(rename = "CpuQuota")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_quota: Option<i64>,

    /// The length of a CPU real-time period in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimePeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_period: Option<i64>,

    /// The length of a CPU real-time runtime in microseconds. Set to 0 to allocate no time allocated to real-time tasks. 
    #[serde(rename = "CpuRealtimeRuntime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_realtime_runtime: Option<i64>,

    /// CPUs in which to allow execution (e.g., `0-3`, `0,1`). 
    #[serde(rename = "CpusetCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_cpus: Option<String>,

    /// Memory nodes (MEMs) in which to allow execution (0-3, 0,1). Only effective on NUMA systems. 
    #[serde(rename = "CpusetMems")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpuset_mems: Option<String>,

    /// A list of devices to add to the container.
    #[serde(rename = "Devices")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub devices: Option<Vec<DeviceMapping>>,

    /// a list of cgroup rules to apply to the container
    #[serde(rename = "DeviceCgroupRules")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_cgroup_rules: Option<Vec<String>>,

    /// A list of requests for devices to be sent to device drivers. 
    #[serde(rename = "DeviceRequests")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub device_requests: Option<Vec<DeviceRequest>>,

    /// Memory soft limit in bytes.
    #[serde(rename = "MemoryReservation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_reservation: Option<i64>,

    /// Total memory limit (memory + swap). Set as `-1` to enable unlimited swap. 
    #[serde(rename = "MemorySwap")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swap: Option<i64>,

    /// Tune a container's memory swappiness behavior. Accepts an integer between 0 and 100. 
    #[serde(rename = "MemorySwappiness")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swappiness: Option<i64>,

    /// CPU quota in units of 10<sup>-9</sup> CPUs.
    #[serde(rename = "NanoCpus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nano_cpus: Option<i64>,

    /// Disable OOM Killer for the container.
    #[serde(rename = "OomKillDisable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill_disable: Option<bool>,

    /// Run an init inside the container that forwards signals and reaps processes. This field is omitted if empty, and the default (as configured on the daemon) is used. 
    #[serde(rename = "Init")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Tune a container's PIDs limit. Set `0` or `-1` for unlimited, or `null` to not change. 
    #[serde(rename = "PidsLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<i64>,

    /// A list of resource limits to set in the container. For example:  ``` {\"Name\": \"nofile\", \"Soft\": 1024, \"Hard\": 2048} ``` 
    #[serde(rename = "Ulimits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<Vec<ResourcesUlimits>>,

    /// The number of usable CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_count: Option<i64>,

    /// The usable percentage of the available CPUs (Windows only).  On Windows Server containers, the processor resource controls are mutually exclusive. The order of precedence is `CPUCount` first, then `CPUShares`, and `CPUPercent` last. 
    #[serde(rename = "CpuPercent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_percent: Option<i64>,

    /// Maximum IOps for the container system drive (Windows only)
    #[serde(rename = "IOMaximumIOps")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_iops: Option<i64>,

    /// Maximum IO in bytes per second for the container system drive (Windows only). 
    #[serde(rename = "IOMaximumBandwidth")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub io_maximum_bandwidth: Option<i64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourcesBlkioWeightDevice {
    #[serde(rename = "Path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    #[serde(rename = "Weight")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub weight: Option<usize>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ResourcesUlimits {
    /// Name of ulimit
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Soft limit
    #[serde(rename = "Soft")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub soft: Option<i64>,

    /// Hard limit
    #[serde(rename = "Hard")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hard: Option<i64>,

}

/// The behavior to apply when the container exits. The default is not to restart.  An ever increasing delay (double the previous delay, starting at 100ms) is added before each restart to prevent flooding the server. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RestartPolicy {
    /// - Empty string means not to restart - `no` Do not automatically restart - `always` Always restart - `unless-stopped` Restart always except when the user has manually stopped the container - `on-failure` Restart only when the container exit code is non-zero 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<RestartPolicyNameEnum>,

    /// If `on-failure` is used, the number of times to retry before giving up. 
    #[serde(rename = "MaximumRetryCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub maximum_retry_count: Option<i64>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum RestartPolicyNameEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "no")]
    NO,
    #[serde(rename = "always")]
    ALWAYS,
    #[serde(rename = "unless-stopped")]
    UNLESS_STOPPED,
    #[serde(rename = "on-failure")]
    ON_FAILURE,
}

impl ::std::fmt::Display for RestartPolicyNameEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            RestartPolicyNameEnum::EMPTY => write!(f, "{}", ""),
            RestartPolicyNameEnum::NO => write!(f, "{}", "no"),
            RestartPolicyNameEnum::ALWAYS => write!(f, "{}", "always"),
            RestartPolicyNameEnum::UNLESS_STOPPED => write!(f, "{}", "unless-stopped"),
            RestartPolicyNameEnum::ON_FAILURE => write!(f, "{}", "on-failure"),

        }
    }
}

impl ::std::str::FromStr for RestartPolicyNameEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(RestartPolicyNameEnum::EMPTY),
            "no" => Ok(RestartPolicyNameEnum::NO),
            "always" => Ok(RestartPolicyNameEnum::ALWAYS),
            "unless-stopped" => Ok(RestartPolicyNameEnum::UNLESS_STOPPED),
            "on-failure" => Ok(RestartPolicyNameEnum::ON_FAILURE),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for RestartPolicyNameEnum {
    fn as_ref(&self) -> &str {
        match self { 
            RestartPolicyNameEnum::EMPTY => "",
            RestartPolicyNameEnum::NO => "no",
            RestartPolicyNameEnum::ALWAYS => "always",
            RestartPolicyNameEnum::UNLESS_STOPPED => "unless-stopped",
            RestartPolicyNameEnum::ON_FAILURE => "on-failure",
        }
    }
}

/// Information about the storage used for the container's root filesystem. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RootFsStorage {
    /// Information about the snapshot used for the container's root filesystem. 
    #[serde(rename = "Snapshot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot: Option<RootFsStorageSnapshot>,

}

/// Information about a snapshot backend of the container's root filesystem. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct RootFsStorageSnapshot {
    /// Name of the snapshotter.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

}

/// Runtime describes an [OCI compliant](https://github.com/opencontainers/runtime-spec) runtime.  The runtime is invoked by the daemon via the `containerd` daemon. OCI runtimes act as an interface to the Linux kernel namespaces, cgroups, and SELinux. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Runtime {
    /// Name and, optional, path, of the OCI executable binary.  If the path is omitted, the daemon searches the host's `$PATH` for the binary and uses the first result. 
    #[serde(rename = "path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// List of command-line arguments to pass to the runtime when invoked. 
    #[serde(rename = "runtimeArgs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime_args: Option<Vec<String>>,

    /// Information specific to the runtime.  While this API specification does not define data provided by runtimes, the following well-known properties may be provided by runtimes:  `org.opencontainers.runtime-spec.features`: features structure as defined in the [OCI Runtime Specification](https://github.com/opencontainers/runtime-spec/blob/main/features.md), in a JSON string representation.  <p><br /></p>  > **Note**: The information returned in this field, including the > formatting of values and labels, should not be considered stable, > and may change without notice. 
    #[serde(rename = "status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Secret {
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SecretSpec>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SecretSpec {
    /// User-defined name of the secret.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// Data is the data to store as a secret, formatted as a Base64-url-safe-encoded ([RFC 4648](https://tools.ietf.org/html/rfc4648#section-5)) string. It must be empty if the Driver field is set, in which case the data is loaded from an external secret store. The maximum allowed size is 500KB, as defined in [MaxSecretSize](https://pkg.go.dev/github.com/moby/swarmkit/v2@v2.0.0/api/validation#MaxSecretSize).  This field is only used to _create_ a secret, and is not returned by other endpoints. 
    #[serde(rename = "Data")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<String>,

    /// Name of the secrets driver used to fetch the secret's value from an external secret store. 
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<Driver>,

    /// Templating driver, if applicable  Templating controls whether and how to evaluate the config payload as a template. If no driver is set, no templating is used. 
    #[serde(rename = "Templating")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub templating: Option<Driver>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Service {
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<ServiceSpec>,

    #[serde(rename = "Endpoint")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<ServiceEndpoint>,

    #[serde(rename = "UpdateStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_status: Option<ServiceUpdateStatus>,

    #[serde(rename = "ServiceStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_status: Option<ServiceServiceStatus>,

    #[serde(rename = "JobStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_status: Option<ServiceJobStatus>,

}

/// contains the information returned to a client on the creation of a new service. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceCreateResponse {
    /// The ID of the created service.
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Optional warning message.  FIXME(thaJeztah): this should have \"omitempty\" in the generated type. 
    #[serde(rename = "Warnings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceEndpoint {
    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<EndpointSpec>,

    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<EndpointPortConfig>>,

    #[serde(rename = "VirtualIPs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub virtual_ips: Option<Vec<ServiceEndpointVirtualIps>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceEndpointVirtualIps {
    #[serde(rename = "NetworkID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_id: Option<String>,

    #[serde(rename = "Addr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub addr: Option<String>,

}

/// represents service parameters with the list of service's tasks 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceInfo {
    #[serde(rename = "VIP")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vip: Option<String>,

    #[serde(rename = "Ports")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ports: Option<Vec<String>>,

    #[serde(rename = "LocalLBIndex")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_lb_index: Option<i64>,

    #[serde(rename = "Tasks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tasks: Option<Vec<NetworkTaskInfo>>,

}

/// The status of the service when it is in one of ReplicatedJob or GlobalJob modes. Absent on Replicated and Global mode services. The JobIteration is an ObjectVersion, but unlike the Service's version, does not need to be sent with an update request. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceJobStatus {
    /// JobIteration is a value increased each time a Job is executed, successfully or otherwise. \"Executed\", in this case, means the job as a whole has been started, not that an individual Task has been launched. A job is \"Executed\" when its ServiceSpec is updated. JobIteration can be used to disambiguate Tasks belonging to different executions of a job.  Though JobIteration will increase with each subsequent execution, it may not necessarily increase by 1, and so JobIteration should not be used to 
    #[serde(rename = "JobIteration")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_iteration: Option<ObjectVersion>,

    /// The last time, as observed by the server, that this job was started. 
    #[serde(rename = "LastExecution")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub last_execution: Option<BollardDate>,

}

/// The status of the service's tasks. Provided only when requested as part of a ServiceList operation. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceServiceStatus {
    /// The number of tasks for the service currently in the Running state. 
    #[serde(rename = "RunningTasks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub running_tasks: Option<u64>,

    /// The number of tasks for the service desired to be running. For replicated services, this is the replica count from the service spec. For global services, this is computed by taking count of all tasks for the service with a Desired State other than Shutdown. 
    #[serde(rename = "DesiredTasks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_tasks: Option<u64>,

    /// The number of tasks for a job that are in the Completed state. This field must be cross-referenced with the service type, as the value of 0 may mean the service is not in a job mode, or it may mean the job-mode service has no tasks yet Completed. 
    #[serde(rename = "CompletedTasks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub completed_tasks: Option<u64>,

}

/// User modifiable configuration for a service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpec {
    /// Name of the service.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "TaskTemplate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_template: Option<TaskSpec>,

    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<ServiceSpecMode>,

    #[serde(rename = "UpdateConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub update_config: Option<ServiceSpecUpdateConfig>,

    #[serde(rename = "RollbackConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rollback_config: Option<ServiceSpecRollbackConfig>,

    /// Specifies which networks the service should attach to.  Deprecated: This field is deprecated since v1.44. The Networks field in TaskSpec should be used instead. 
    #[serde(rename = "Networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<NetworkAttachmentConfig>>,

    #[serde(rename = "EndpointSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint_spec: Option<EndpointSpec>,

}

/// Scheduling mode for the service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecMode {
    #[serde(rename = "Replicated")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicated: Option<ServiceSpecModeReplicated>,

    #[serde(rename = "Global")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global: Option<HashMap<(), ()>>,

    #[serde(rename = "ReplicatedJob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicated_job: Option<ServiceSpecModeReplicatedJob>,

    /// The mode used for services which run a task to the completed state on each valid node. 
    #[serde(rename = "GlobalJob")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub global_job: Option<HashMap<(), ()>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecModeReplicated {
    #[serde(rename = "Replicas")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub replicas: Option<i64>,

}

/// The mode used for services with a finite number of tasks that run to a completed state. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecModeReplicatedJob {
    /// The maximum number of replicas to run simultaneously. 
    #[serde(rename = "MaxConcurrent")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_concurrent: Option<i64>,

    /// The total number of replicas desired to reach the Completed state. If unset, will default to the value of `MaxConcurrent` 
    #[serde(rename = "TotalCompletions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_completions: Option<i64>,

}

/// Specification for the rollback strategy of the service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecRollbackConfig {
    /// Maximum number of tasks to be rolled back in one iteration (0 means unlimited parallelism). 
    #[serde(rename = "Parallelism")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<i64>,

    /// Amount of time between rollback iterations, in nanoseconds. 
    #[serde(rename = "Delay")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,

    /// Action to take if an rolled back task fails to run, or stops running during the rollback. 
    #[serde(rename = "FailureAction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_action: Option<ServiceSpecRollbackConfigFailureActionEnum>,

    /// Amount of time to monitor each rolled back task for failures, in nanoseconds. 
    #[serde(rename = "Monitor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor: Option<i64>,

    /// The fraction of tasks that may fail during a rollback before the failure action is invoked, specified as a floating point number between 0 and 1. 
    #[serde(rename = "MaxFailureRatio")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_failure_ratio: Option<f64>,

    /// The order of operations when rolling back a task. Either the old task is shut down before the new task is started, or the new task is started before the old task is shut down. 
    #[serde(rename = "Order")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<ServiceSpecRollbackConfigOrderEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ServiceSpecRollbackConfigFailureActionEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "continue")]
    CONTINUE,
    #[serde(rename = "pause")]
    PAUSE,
}

impl ::std::fmt::Display for ServiceSpecRollbackConfigFailureActionEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ServiceSpecRollbackConfigFailureActionEnum::EMPTY => write!(f, ""),
            ServiceSpecRollbackConfigFailureActionEnum::CONTINUE => write!(f, "{}", "continue"),
            ServiceSpecRollbackConfigFailureActionEnum::PAUSE => write!(f, "{}", "pause"),

        }
    }
}

impl ::std::str::FromStr for ServiceSpecRollbackConfigFailureActionEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ServiceSpecRollbackConfigFailureActionEnum::EMPTY),
            "continue" => Ok(ServiceSpecRollbackConfigFailureActionEnum::CONTINUE),
            "pause" => Ok(ServiceSpecRollbackConfigFailureActionEnum::PAUSE),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ServiceSpecRollbackConfigFailureActionEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ServiceSpecRollbackConfigFailureActionEnum::EMPTY => "",
            ServiceSpecRollbackConfigFailureActionEnum::CONTINUE => "continue",
            ServiceSpecRollbackConfigFailureActionEnum::PAUSE => "pause",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ServiceSpecRollbackConfigOrderEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "stop-first")]
    STOP_FIRST,
    #[serde(rename = "start-first")]
    START_FIRST,
}

impl ::std::fmt::Display for ServiceSpecRollbackConfigOrderEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ServiceSpecRollbackConfigOrderEnum::EMPTY => write!(f, ""),
            ServiceSpecRollbackConfigOrderEnum::STOP_FIRST => write!(f, "{}", "stop-first"),
            ServiceSpecRollbackConfigOrderEnum::START_FIRST => write!(f, "{}", "start-first"),

        }
    }
}

impl ::std::str::FromStr for ServiceSpecRollbackConfigOrderEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ServiceSpecRollbackConfigOrderEnum::EMPTY),
            "stop-first" => Ok(ServiceSpecRollbackConfigOrderEnum::STOP_FIRST),
            "start-first" => Ok(ServiceSpecRollbackConfigOrderEnum::START_FIRST),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ServiceSpecRollbackConfigOrderEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ServiceSpecRollbackConfigOrderEnum::EMPTY => "",
            ServiceSpecRollbackConfigOrderEnum::STOP_FIRST => "stop-first",
            ServiceSpecRollbackConfigOrderEnum::START_FIRST => "start-first",
        }
    }
}

/// Specification for the update strategy of the service.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceSpecUpdateConfig {
    /// Maximum number of tasks to be updated in one iteration (0 means unlimited parallelism). 
    #[serde(rename = "Parallelism")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub parallelism: Option<i64>,

    /// Amount of time between updates, in nanoseconds.
    #[serde(rename = "Delay")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,

    /// Action to take if an updated task fails to run, or stops running during the update. 
    #[serde(rename = "FailureAction")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub failure_action: Option<ServiceSpecUpdateConfigFailureActionEnum>,

    /// Amount of time to monitor each updated task for failures, in nanoseconds. 
    #[serde(rename = "Monitor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub monitor: Option<i64>,

    /// The fraction of tasks that may fail during an update before the failure action is invoked, specified as a floating point number between 0 and 1. 
    #[serde(rename = "MaxFailureRatio")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_failure_ratio: Option<f64>,

    /// The order of operations when rolling out an updated task. Either the old task is shut down before the new task is started, or the new task is started before the old task is shut down. 
    #[serde(rename = "Order")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub order: Option<ServiceSpecUpdateConfigOrderEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ServiceSpecUpdateConfigFailureActionEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "continue")]
    CONTINUE,
    #[serde(rename = "pause")]
    PAUSE,
    #[serde(rename = "rollback")]
    ROLLBACK,
}

impl ::std::fmt::Display for ServiceSpecUpdateConfigFailureActionEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ServiceSpecUpdateConfigFailureActionEnum::EMPTY => write!(f, ""),
            ServiceSpecUpdateConfigFailureActionEnum::CONTINUE => write!(f, "{}", "continue"),
            ServiceSpecUpdateConfigFailureActionEnum::PAUSE => write!(f, "{}", "pause"),
            ServiceSpecUpdateConfigFailureActionEnum::ROLLBACK => write!(f, "{}", "rollback"),

        }
    }
}

impl ::std::str::FromStr for ServiceSpecUpdateConfigFailureActionEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ServiceSpecUpdateConfigFailureActionEnum::EMPTY),
            "continue" => Ok(ServiceSpecUpdateConfigFailureActionEnum::CONTINUE),
            "pause" => Ok(ServiceSpecUpdateConfigFailureActionEnum::PAUSE),
            "rollback" => Ok(ServiceSpecUpdateConfigFailureActionEnum::ROLLBACK),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ServiceSpecUpdateConfigFailureActionEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ServiceSpecUpdateConfigFailureActionEnum::EMPTY => "",
            ServiceSpecUpdateConfigFailureActionEnum::CONTINUE => "continue",
            ServiceSpecUpdateConfigFailureActionEnum::PAUSE => "pause",
            ServiceSpecUpdateConfigFailureActionEnum::ROLLBACK => "rollback",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ServiceSpecUpdateConfigOrderEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "stop-first")]
    STOP_FIRST,
    #[serde(rename = "start-first")]
    START_FIRST,
}

impl ::std::fmt::Display for ServiceSpecUpdateConfigOrderEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ServiceSpecUpdateConfigOrderEnum::EMPTY => write!(f, ""),
            ServiceSpecUpdateConfigOrderEnum::STOP_FIRST => write!(f, "{}", "stop-first"),
            ServiceSpecUpdateConfigOrderEnum::START_FIRST => write!(f, "{}", "start-first"),

        }
    }
}

impl ::std::str::FromStr for ServiceSpecUpdateConfigOrderEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ServiceSpecUpdateConfigOrderEnum::EMPTY),
            "stop-first" => Ok(ServiceSpecUpdateConfigOrderEnum::STOP_FIRST),
            "start-first" => Ok(ServiceSpecUpdateConfigOrderEnum::START_FIRST),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ServiceSpecUpdateConfigOrderEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ServiceSpecUpdateConfigOrderEnum::EMPTY => "",
            ServiceSpecUpdateConfigOrderEnum::STOP_FIRST => "stop-first",
            ServiceSpecUpdateConfigOrderEnum::START_FIRST => "start-first",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceUpdateResponse {
    /// Optional warning messages
    #[serde(rename = "Warnings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

}

/// The status of a service update.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ServiceUpdateStatus {
    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<ServiceUpdateStatusStateEnum>,

    #[serde(rename = "StartedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub started_at: Option<BollardDate>,

    #[serde(rename = "CompletedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub completed_at: Option<BollardDate>,

    #[serde(rename = "Message")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum ServiceUpdateStatusStateEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "updating")]
    UPDATING,
    #[serde(rename = "paused")]
    PAUSED,
    #[serde(rename = "completed")]
    COMPLETED,
    #[serde(rename = "rollback_started")]
    ROLLBACK_STARTED,
    #[serde(rename = "rollback_paused")]
    ROLLBACK_PAUSED,
    #[serde(rename = "rollback_completed")]
    ROLLBACK_COMPLETED,
}

impl ::std::fmt::Display for ServiceUpdateStatusStateEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            ServiceUpdateStatusStateEnum::EMPTY => write!(f, ""),
            ServiceUpdateStatusStateEnum::UPDATING => write!(f, "{}", "updating"),
            ServiceUpdateStatusStateEnum::PAUSED => write!(f, "{}", "paused"),
            ServiceUpdateStatusStateEnum::COMPLETED => write!(f, "{}", "completed"),
            ServiceUpdateStatusStateEnum::ROLLBACK_STARTED => write!(f, "{}", "rollback_started"),
            ServiceUpdateStatusStateEnum::ROLLBACK_PAUSED => write!(f, "{}", "rollback_paused"),
            ServiceUpdateStatusStateEnum::ROLLBACK_COMPLETED => write!(f, "{}", "rollback_completed"),

        }
    }
}

impl ::std::str::FromStr for ServiceUpdateStatusStateEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(ServiceUpdateStatusStateEnum::EMPTY),
            "updating" => Ok(ServiceUpdateStatusStateEnum::UPDATING),
            "paused" => Ok(ServiceUpdateStatusStateEnum::PAUSED),
            "completed" => Ok(ServiceUpdateStatusStateEnum::COMPLETED),
            "rollback_started" => Ok(ServiceUpdateStatusStateEnum::ROLLBACK_STARTED),
            "rollback_paused" => Ok(ServiceUpdateStatusStateEnum::ROLLBACK_PAUSED),
            "rollback_completed" => Ok(ServiceUpdateStatusStateEnum::ROLLBACK_COMPLETED),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for ServiceUpdateStatusStateEnum {
    fn as_ref(&self) -> &str {
        match self { 
            ServiceUpdateStatusStateEnum::EMPTY => "",
            ServiceUpdateStatusStateEnum::UPDATING => "updating",
            ServiceUpdateStatusStateEnum::PAUSED => "paused",
            ServiceUpdateStatusStateEnum::COMPLETED => "completed",
            ServiceUpdateStatusStateEnum::ROLLBACK_STARTED => "rollback_started",
            ServiceUpdateStatusStateEnum::ROLLBACK_PAUSED => "rollback_paused",
            ServiceUpdateStatusStateEnum::ROLLBACK_COMPLETED => "rollback_completed",
        }
    }
}

/// Information about the storage used by the container. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Storage {
    /// Information about the storage used for the container's root filesystem. 
    #[serde(rename = "RootFS")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_fs: Option<RootFsStorage>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SubnetStatus {
    /// Number of IP addresses in the subnet that are in use or reserved and are therefore unavailable for allocation, saturating at 2<sup>64</sup> - 1. 
    #[serde(rename = "IPsInUse")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ips_in_use: Option<u64>,

    /// Number of IP addresses within the network's IPRange for the subnet that are available for allocation, saturating at 2<sup>64</sup> - 1. 
    #[serde(rename = "DynamicIPsAvailable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dynamic_ips_available: Option<u64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Swarm {
    /// The ID of the swarm.
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    /// Date and time at which the swarm was initialised in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    /// Date and time at which the swarm was last updated in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSpec>,

    #[serde(rename = "TLSInfo")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tls_info: Option<TlsInfo>,

    /// Whether there is currently a root CA rotation in progress for the swarm 
    #[serde(rename = "RootRotationInProgress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub root_rotation_in_progress: Option<bool>,

    /// DataPathPort specifies the data path port number for data traffic. Acceptable port range is 1024 to 49151. If no port is set or is set to 0, the default port (4789) is used. 
    #[serde(rename = "DataPathPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path_port: Option<u32>,

    /// Default Address Pool specifies default subnet pools for global scope networks. 
    #[serde(rename = "DefaultAddrPool")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_addr_pool: Option<Vec<String>>,

    /// SubnetSize specifies the subnet size of the networks created from the default subnet pool. 
    #[serde(rename = "SubnetSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_size: Option<u32>,

    #[serde(rename = "JoinTokens")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_tokens: Option<JoinTokens>,

}

/// Represents generic information about swarm. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmInfo {
    /// Unique identifier of for this node in the swarm.
    #[serde(rename = "NodeID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    /// IP address at which this node can be reached by other nodes in the swarm. 
    #[serde(rename = "NodeAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_addr: Option<String>,

    #[serde(rename = "LocalNodeState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub local_node_state: Option<LocalNodeState>,

    #[serde(rename = "ControlAvailable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub control_available: Option<bool>,

    #[serde(rename = "Error")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,

    /// List of ID's and addresses of other managers in the swarm. 
    #[serde(rename = "RemoteManagers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_managers: Option<Vec<PeerNode>>,

    /// Total number of nodes in the swarm.
    #[serde(rename = "Nodes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nodes: Option<i64>,

    /// Total number of managers in the swarm.
    #[serde(rename = "Managers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub managers: Option<i64>,

    #[serde(rename = "Cluster")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster: Option<ClusterInfo>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmInitRequest {
    /// Listen address used for inter-manager communication, as well as determining the networking interface used for the VXLAN Tunnel Endpoint (VTEP). This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the default swarm listening port is used. 
    #[serde(rename = "ListenAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,

    /// Externally reachable address advertised to other nodes. This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the port number from the listen address is used. If `AdvertiseAddr` is not specified, it will be automatically detected when possible. 
    #[serde(rename = "AdvertiseAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_addr: Option<String>,

    /// Address or interface to use for data path traffic (format: `<ip|interface>`), for example,  `192.168.1.1`, or an interface, like `eth0`. If `DataPathAddr` is unspecified, the same address as `AdvertiseAddr` is used.  The `DataPathAddr` specifies the address that global scope network drivers will publish towards other  nodes in order to reach the containers running on this node. Using this parameter it is possible to separate the container data traffic from the management traffic of the cluster. 
    #[serde(rename = "DataPathAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path_addr: Option<String>,

    /// DataPathPort specifies the data path port number for data traffic. Acceptable port range is 1024 to 49151. if no port is set or is set to 0, default port 4789 will be used. 
    #[serde(rename = "DataPathPort")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path_port: Option<u32>,

    /// Default Address Pool specifies default subnet pools for global scope networks. 
    #[serde(rename = "DefaultAddrPool")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_addr_pool: Option<Vec<String>>,

    /// Force creation of a new swarm.
    #[serde(rename = "ForceNewCluster")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_new_cluster: Option<bool>,

    /// SubnetSize specifies the subnet size of the networks created from the default subnet pool. 
    #[serde(rename = "SubnetSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub subnet_size: Option<u32>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<SwarmSpec>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmJoinRequest {
    /// Listen address used for inter-manager communication if the node gets promoted to manager, as well as determining the networking interface used for the VXLAN Tunnel Endpoint (VTEP). 
    #[serde(rename = "ListenAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub listen_addr: Option<String>,

    /// Externally reachable address advertised to other nodes. This can either be an address/port combination in the form `192.168.1.1:4567`, or an interface followed by a port number, like `eth0:4567`. If the port number is omitted, the port number from the listen address is used. If `AdvertiseAddr` is not specified, it will be automatically detected when possible. 
    #[serde(rename = "AdvertiseAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub advertise_addr: Option<String>,

    /// Address or interface to use for data path traffic (format: `<ip|interface>`), for example,  `192.168.1.1`, or an interface, like `eth0`. If `DataPathAddr` is unspecified, the same address as `AdvertiseAddr` is used.  The `DataPathAddr` specifies the address that global scope network drivers will publish towards other nodes in order to reach the containers running on this node. Using this parameter it is possible to separate the container data traffic from the management traffic of the cluster. 
    #[serde(rename = "DataPathAddr")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data_path_addr: Option<String>,

    /// Addresses of manager nodes already participating in the swarm. 
    #[serde(rename = "RemoteAddrs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote_addrs: Option<Vec<String>>,

    /// Secret token for joining this swarm.
    #[serde(rename = "JoinToken")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub join_token: Option<String>,

}

/// User modifiable swarm configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpec {
    /// Name of the swarm.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "Orchestration")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub orchestration: Option<SwarmSpecOrchestration>,

    #[serde(rename = "Raft")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub raft: Option<SwarmSpecRaft>,

    #[serde(rename = "Dispatcher")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dispatcher: Option<SwarmSpecDispatcher>,

    #[serde(rename = "CAConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_config: Option<SwarmSpecCaConfig>,

    #[serde(rename = "EncryptionConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub encryption_config: Option<SwarmSpecEncryptionConfig>,

    #[serde(rename = "TaskDefaults")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_defaults: Option<SwarmSpecTaskDefaults>,

}

/// CA configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecCaConfig {
    /// The duration node certificates are issued for.
    #[serde(rename = "NodeCertExpiry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_cert_expiry: Option<i64>,

    /// Configuration for forwarding signing requests to an external certificate authority. 
    #[serde(rename = "ExternalCAs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub external_cas: Option<Vec<SwarmSpecCaConfigExternalCas>>,

    /// The desired signing CA certificate for all swarm node TLS leaf certificates, in PEM format. 
    #[serde(rename = "SigningCACert")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_ca_cert: Option<String>,

    /// The desired signing CA key for all swarm node TLS leaf certificates, in PEM format. 
    #[serde(rename = "SigningCAKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub signing_ca_key: Option<String>,

    /// An integer whose purpose is to force swarm to generate a new signing CA certificate and key, if none have been specified in `SigningCACert` and `SigningCAKey` 
    #[serde(rename = "ForceRotate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_rotate: Option<u64>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecCaConfigExternalCas {
    /// Protocol for communication with the external CA (currently only `cfssl` is supported). 
    #[serde(rename = "Protocol")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub protocol: Option<SwarmSpecCaConfigExternalCasProtocolEnum>,

    /// URL where certificate signing requests should be sent. 
    #[serde(rename = "URL")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,

    /// An object with key/value pairs that are interpreted as protocol-specific options for the external CA driver. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

    /// The root CA certificate (in PEM format) this external CA uses to issue TLS certificates (assumed to be to the current swarm root CA certificate if not provided). 
    #[serde(rename = "CACert")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ca_cert: Option<String>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum SwarmSpecCaConfigExternalCasProtocolEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "cfssl")]
    CFSSL,
}

impl ::std::fmt::Display for SwarmSpecCaConfigExternalCasProtocolEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            SwarmSpecCaConfigExternalCasProtocolEnum::EMPTY => write!(f, ""),
            SwarmSpecCaConfigExternalCasProtocolEnum::CFSSL => write!(f, "{}", "cfssl"),

        }
    }
}

impl ::std::str::FromStr for SwarmSpecCaConfigExternalCasProtocolEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(SwarmSpecCaConfigExternalCasProtocolEnum::EMPTY),
            "cfssl" => Ok(SwarmSpecCaConfigExternalCasProtocolEnum::CFSSL),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for SwarmSpecCaConfigExternalCasProtocolEnum {
    fn as_ref(&self) -> &str {
        match self { 
            SwarmSpecCaConfigExternalCasProtocolEnum::EMPTY => "",
            SwarmSpecCaConfigExternalCasProtocolEnum::CFSSL => "cfssl",
        }
    }
}

/// Dispatcher configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecDispatcher {
    /// The delay for an agent to send a heartbeat to the dispatcher. 
    #[serde(rename = "HeartbeatPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_period: Option<i64>,

}

/// Parameters related to encryption-at-rest.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecEncryptionConfig {
    /// If set, generate a key and use it to lock data stored on the managers. 
    #[serde(rename = "AutoLockManagers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub auto_lock_managers: Option<bool>,

}

/// Orchestration configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecOrchestration {
    /// The number of historic tasks to keep per instance or node. If negative, never remove completed or failed tasks. 
    #[serde(rename = "TaskHistoryRetentionLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub task_history_retention_limit: Option<i64>,

}

/// Raft configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecRaft {
    /// The number of log entries between snapshots.
    #[serde(rename = "SnapshotInterval")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub snapshot_interval: Option<u64>,

    /// The number of snapshots to keep beyond the current snapshot. 
    #[serde(rename = "KeepOldSnapshots")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub keep_old_snapshots: Option<u64>,

    /// The number of log entries to keep around to sync up slow followers after a snapshot is created. 
    #[serde(rename = "LogEntriesForSlowFollowers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_entries_for_slow_followers: Option<u64>,

    /// The number of ticks that a follower will wait for a message from the leader before becoming a candidate and starting an election. `ElectionTick` must be greater than `HeartbeatTick`.  A tick currently defaults to one second, so these translate directly to seconds currently, but this is NOT guaranteed. 
    #[serde(rename = "ElectionTick")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub election_tick: Option<i64>,

    /// The number of ticks between heartbeats. Every HeartbeatTick ticks, the leader will send a heartbeat to the followers.  A tick currently defaults to one second, so these translate directly to seconds currently, but this is NOT guaranteed. 
    #[serde(rename = "HeartbeatTick")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub heartbeat_tick: Option<i64>,

}

/// Defaults for creating tasks in this cluster.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecTaskDefaults {
    #[serde(rename = "LogDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_driver: Option<SwarmSpecTaskDefaultsLogDriver>,

}

/// The log driver to use for tasks created in the orchestrator if unspecified by a service.  Updating this value only affects new tasks. Existing tasks continue to use their previously configured log driver until recreated. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmSpecTaskDefaultsLogDriver {
    /// The log driver to use as a default for new tasks. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Driver-specific options for the selected log driver, specified as key/value pairs. 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SwarmUnlockRequest {
    /// The swarm's unlock key.
    #[serde(rename = "UnlockKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_key: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemDataUsageResponse {
    #[serde(rename = "ImagesDiskUsage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images_disk_usage: Option<ImagesDiskUsage>,

    #[serde(rename = "ContainersDiskUsage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_disk_usage: Option<ContainersDiskUsage>,

    #[serde(rename = "VolumesDiskUsage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes_disk_usage: Option<VolumesDiskUsage>,

    #[serde(rename = "BuildCacheDiskUsage")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_cache_disk_usage: Option<BuildCacheDiskUsage>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemInfo {
    /// Unique identifier of the daemon.  <p><br /></p>  > **Note**: The format of the ID itself is not part of the API, and > should not be considered stable. 
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    /// Total number of containers on the host.
    #[serde(rename = "Containers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers: Option<i64>,

    /// Number of containers with status `\"running\"`. 
    #[serde(rename = "ContainersRunning")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_running: Option<i64>,

    /// Number of containers with status `\"paused\"`. 
    #[serde(rename = "ContainersPaused")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_paused: Option<i64>,

    /// Number of containers with status `\"stopped\"`. 
    #[serde(rename = "ContainersStopped")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containers_stopped: Option<i64>,

    /// Total number of images on the host.  Both _tagged_ and _untagged_ (dangling) images are counted. 
    #[serde(rename = "Images")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub images: Option<i64>,

    /// Name of the storage driver in use.
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// Information specific to the storage driver, provided as \"label\" / \"value\" pairs.  This information is provided by the storage driver, and formatted in a way consistent with the output of `docker info` on the command line.  <p><br /></p>  > **Note**: The information returned in this field, including the > formatting of values and labels, should not be considered stable, > and may change without notice. 
    #[serde(rename = "DriverStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_status: Option<Vec<Vec<String>>>,

    /// Root directory of persistent Docker state.  Defaults to `/var/lib/docker` on Linux, and `C:\\ProgramData\\docker` on Windows. 
    #[serde(rename = "DockerRootDir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub docker_root_dir: Option<String>,

    #[serde(rename = "Plugins")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugins: Option<PluginsInfo>,

    /// Indicates if the host has memory limit support enabled.
    #[serde(rename = "MemoryLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_limit: Option<bool>,

    /// Indicates if the host has memory swap limit support enabled.
    #[serde(rename = "SwapLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_limit: Option<bool>,

    /// Indicates if CPU CFS(Completely Fair Scheduler) period is supported by the host. 
    #[serde(rename = "CpuCfsPeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cfs_period: Option<bool>,

    /// Indicates if CPU CFS(Completely Fair Scheduler) quota is supported by the host. 
    #[serde(rename = "CpuCfsQuota")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_cfs_quota: Option<bool>,

    /// Indicates if CPU Shares limiting is supported by the host. 
    #[serde(rename = "CPUShares")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_shares: Option<bool>,

    /// Indicates if CPUsets (cpuset.cpus, cpuset.mems) are supported by the host.  See [cpuset(7)](https://www.kernel.org/doc/Documentation/cgroup-v1/cpusets.txt) 
    #[serde(rename = "CPUSet")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cpu_set: Option<bool>,

    /// Indicates if the host kernel has PID limit support enabled.
    #[serde(rename = "PidsLimit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub pids_limit: Option<bool>,

    /// Indicates if OOM killer disable is supported on the host.
    #[serde(rename = "OomKillDisable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_kill_disable: Option<bool>,

    /// Indicates IPv4 forwarding is enabled.
    #[serde(rename = "IPv4Forwarding")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ipv4_forwarding: Option<bool>,

    /// Indicates if the daemon is running in debug-mode / with debug-level logging enabled. 
    #[serde(rename = "Debug")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub debug: Option<bool>,

    /// The total number of file Descriptors in use by the daemon process.  This information is only returned if debug-mode is enabled. 
    #[serde(rename = "NFd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nfd: Option<i64>,

    /// The  number of goroutines that currently exist.  This information is only returned if debug-mode is enabled. 
    #[serde(rename = "NGoroutines")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_goroutines: Option<i64>,

    /// Current system-time in [RFC 3339](https://www.ietf.org/rfc/rfc3339.txt) format with nano-seconds. 
    #[serde(rename = "SystemTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub system_time: Option<String>,

    /// The logging driver to use as a default for new containers. 
    #[serde(rename = "LoggingDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub logging_driver: Option<String>,

    /// The driver to use for managing cgroups. 
    #[serde(rename = "CgroupDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_driver: Option<SystemInfoCgroupDriverEnum>,

    /// The version of the cgroup. 
    #[serde(rename = "CgroupVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cgroup_version: Option<SystemInfoCgroupVersionEnum>,

    /// Number of event listeners subscribed.
    #[serde(rename = "NEventsListener")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub n_events_listener: Option<i64>,

    /// Kernel version of the host.  On Linux, this information obtained from `uname`. On Windows this information is queried from the <kbd>HKEY_LOCAL_MACHINE\\\\SOFTWARE\\\\Microsoft\\\\Windows NT\\\\CurrentVersion\\\\</kbd> registry value, for example _\"10.0 14393 (14393.1198.amd64fre.rs1_release_sec.170427-1353)\"_. 
    #[serde(rename = "KernelVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,

    /// Name of the host's operating system, for example: \"Ubuntu 24.04 LTS\" or \"Windows Server 2016 Datacenter\" 
    #[serde(rename = "OperatingSystem")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub operating_system: Option<String>,

    /// Version of the host's operating system  <p><br /></p>  > **Note**: The information returned in this field, including its > very existence, and the formatting of values, should not be considered > stable, and may change without notice. 
    #[serde(rename = "OSVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_version: Option<String>,

    /// Generic type of the operating system of the host, as returned by the Go runtime (`GOOS`).  Currently returned values are \"linux\" and \"windows\". A full list of possible values can be found in the [Go documentation](https://go.dev/doc/install/source#environment). 
    #[serde(rename = "OSType")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os_type: Option<String>,

    /// Hardware architecture of the host, as returned by the Go runtime (`GOARCH`).  A full list of possible values can be found in the [Go documentation](https://go.dev/doc/install/source#environment). 
    #[serde(rename = "Architecture")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub architecture: Option<String>,

    /// The number of logical CPUs usable by the daemon.  The number of available CPUs is checked by querying the operating system when the daemon starts. Changes to operating system CPU allocation after the daemon is started are not reflected. 
    #[serde(rename = "NCPU")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ncpu: Option<i64>,

    /// Total amount of physical memory available on the host, in bytes. 
    #[serde(rename = "MemTotal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mem_total: Option<i64>,

    /// Address / URL of the index server that is used for image search, and as a default for user authentication for Docker Hub and Docker Cloud. 
    #[serde(rename = "IndexServerAddress")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub index_server_address: Option<String>,

    #[serde(rename = "RegistryConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry_config: Option<RegistryServiceConfig>,

    #[serde(rename = "GenericResources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub generic_resources: Option<GenericResources>,

    /// HTTP-proxy configured for the daemon. This value is obtained from the [`HTTP_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html) environment variable. Credentials ([user info component](https://tools.ietf.org/html/rfc3986#section-3.2.1)) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration. 
    #[serde(rename = "HttpProxy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub http_proxy: Option<String>,

    /// HTTPS-proxy configured for the daemon. This value is obtained from the [`HTTPS_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html) environment variable. Credentials ([user info component](https://tools.ietf.org/html/rfc3986#section-3.2.1)) in the proxy URL are masked in the API response.  Containers do not automatically inherit this configuration. 
    #[serde(rename = "HttpsProxy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub https_proxy: Option<String>,

    /// Comma-separated list of domain extensions for which no proxy should be used. This value is obtained from the [`NO_PROXY`](https://www.gnu.org/software/wget/manual/html_node/Proxies.html) environment variable.  Containers do not automatically inherit this configuration. 
    #[serde(rename = "NoProxy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_proxy: Option<String>,

    /// Hostname of the host.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined labels (key/value metadata) as set on the daemon.  <p><br /></p>  > **Note**: When part of a Swarm, nodes can both have _daemon_ labels, > set through the daemon configuration, and _node_ labels, set from a > manager node in the Swarm. Node labels are not included in this > field. Node labels can be retrieved using the `/nodes/(id)` endpoint > on a manager node in the Swarm. 
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<Vec<String>>,

    /// Indicates if experimental features are enabled on the daemon. 
    #[serde(rename = "ExperimentalBuild")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental_build: Option<bool>,

    /// Version string of the daemon. 
    #[serde(rename = "ServerVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub server_version: Option<String>,

    /// List of [OCI compliant](https://github.com/opencontainers/runtime-spec) runtimes configured on the daemon. Keys hold the \"name\" used to reference the runtime.  The Docker daemon relies on an OCI compliant runtime (invoked via the `containerd` daemon) as its interface to the Linux kernel namespaces, cgroups, and SELinux.  The default runtime is `runc`, and automatically configured. Additional runtimes can be configured by the user and will be listed here. 
    #[serde(rename = "Runtimes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtimes: Option<HashMap<String, Runtime>>,

    /// Name of the default OCI runtime that is used when starting containers.  The default can be overridden per-container at create time. 
    #[serde(rename = "DefaultRuntime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_runtime: Option<String>,

    #[serde(rename = "Swarm")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swarm: Option<SwarmInfo>,

    /// Indicates if live restore is enabled.  If enabled, containers are kept running when the daemon is shutdown or upon daemon start if running containers are detected. 
    #[serde(rename = "LiveRestoreEnabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub live_restore_enabled: Option<bool>,

    /// Represents the isolation technology to use as a default for containers. The supported values are platform-specific.  If no isolation value is specified on daemon start, on Windows client, the default is `hyperv`, and on Windows server, the default is `process`.  This option is currently not used on other platforms. 
    #[serde(rename = "Isolation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<SystemInfoIsolationEnum>,

    /// Name and, optional, path of the `docker-init` binary.  If the path is omitted, the daemon searches the host's `$PATH` for the binary and uses the first result. 
    #[serde(rename = "InitBinary")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_binary: Option<String>,

    #[serde(rename = "ContainerdCommit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containerd_commit: Option<Commit>,

    #[serde(rename = "RuncCommit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runc_commit: Option<Commit>,

    #[serde(rename = "InitCommit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init_commit: Option<Commit>,

    /// List of security features that are enabled on the daemon, such as apparmor, seccomp, SELinux, user-namespaces (userns), rootless and no-new-privileges.  Additional configuration options for each security feature may be present, and are included as a comma-separated list of key/value pairs. 
    #[serde(rename = "SecurityOptions")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_options: Option<Vec<String>>,

    /// Reports a summary of the product license on the daemon.  If a commercial license has been applied to the daemon, information such as number of nodes, and expiration are included. 
    #[serde(rename = "ProductLicense")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub product_license: Option<String>,

    /// List of custom default address pools for local networks, which can be specified in the daemon.json file or dockerd option.  Example: a Base \"10.10.0.0/16\" with Size 24 will define the set of 256 10.10.[0-255].0/24 address pools. 
    #[serde(rename = "DefaultAddressPools")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub default_address_pools: Option<Vec<SystemInfoDefaultAddressPools>>,

    #[serde(rename = "FirewallBackend")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub firewall_backend: Option<FirewallInfo>,

    /// List of devices discovered by device drivers.  Each device includes information about its source driver, kind, name, and additional driver-specific attributes. 
    #[serde(rename = "DiscoveredDevices")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub discovered_devices: Option<Vec<DeviceInfo>>,

    /// List of warnings / informational messages about missing features, or issues related to the daemon configuration.  These messages can be printed by the client as information to the user. 
    #[serde(rename = "Warnings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

    /// List of directories where (Container Device Interface) CDI specifications are located.  These specifications define vendor-specific modifications to an OCI runtime specification for a container being created.  An empty list indicates that CDI device injection is disabled.  Note that since using CDI device injection requires the daemon to have experimental enabled. For non-experimental daemons an empty list will always be returned. 
    #[serde(rename = "CDISpecDirs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cdi_spec_dirs: Option<Vec<String>>,

    #[serde(rename = "Containerd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub containerd: Option<ContainerdInfo>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum SystemInfoCgroupDriverEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "cgroupfs")]
    CGROUPFS,
    #[serde(rename = "systemd")]
    SYSTEMD,
    #[serde(rename = "none")]
    NONE,
}

impl ::std::fmt::Display for SystemInfoCgroupDriverEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            SystemInfoCgroupDriverEnum::EMPTY => write!(f, ""),
            SystemInfoCgroupDriverEnum::CGROUPFS => write!(f, "{}", "cgroupfs"),
            SystemInfoCgroupDriverEnum::SYSTEMD => write!(f, "{}", "systemd"),
            SystemInfoCgroupDriverEnum::NONE => write!(f, "{}", "none"),

        }
    }
}

impl ::std::str::FromStr for SystemInfoCgroupDriverEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(SystemInfoCgroupDriverEnum::EMPTY),
            "cgroupfs" => Ok(SystemInfoCgroupDriverEnum::CGROUPFS),
            "systemd" => Ok(SystemInfoCgroupDriverEnum::SYSTEMD),
            "none" => Ok(SystemInfoCgroupDriverEnum::NONE),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for SystemInfoCgroupDriverEnum {
    fn as_ref(&self) -> &str {
        match self { 
            SystemInfoCgroupDriverEnum::EMPTY => "",
            SystemInfoCgroupDriverEnum::CGROUPFS => "cgroupfs",
            SystemInfoCgroupDriverEnum::SYSTEMD => "systemd",
            SystemInfoCgroupDriverEnum::NONE => "none",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum SystemInfoCgroupVersionEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "1")]
    _1,
    #[serde(rename = "2")]
    _2,
}

impl ::std::fmt::Display for SystemInfoCgroupVersionEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            SystemInfoCgroupVersionEnum::EMPTY => write!(f, ""),
            SystemInfoCgroupVersionEnum::_1 => write!(f, "{}", "1"),
            SystemInfoCgroupVersionEnum::_2 => write!(f, "{}", "2"),

        }
    }
}

impl ::std::str::FromStr for SystemInfoCgroupVersionEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(SystemInfoCgroupVersionEnum::EMPTY),
            "1" => Ok(SystemInfoCgroupVersionEnum::_1),
            "2" => Ok(SystemInfoCgroupVersionEnum::_2),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for SystemInfoCgroupVersionEnum {
    fn as_ref(&self) -> &str {
        match self { 
            SystemInfoCgroupVersionEnum::EMPTY => "",
            SystemInfoCgroupVersionEnum::_1 => "1",
            SystemInfoCgroupVersionEnum::_2 => "2",
        }
    }
}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum SystemInfoIsolationEnum { 
    #[serde(rename = "default")]
    DEFAULT,
    #[serde(rename = "hyperv")]
    HYPERV,
    #[serde(rename = "process")]
    PROCESS,
    #[serde(rename = "")]
    EMPTY,
}

impl ::std::fmt::Display for SystemInfoIsolationEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            SystemInfoIsolationEnum::DEFAULT => write!(f, "{}", "default"),
            SystemInfoIsolationEnum::HYPERV => write!(f, "{}", "hyperv"),
            SystemInfoIsolationEnum::PROCESS => write!(f, "{}", "process"),
            SystemInfoIsolationEnum::EMPTY => write!(f, "{}", ""),

        }
    }
}

impl ::std::str::FromStr for SystemInfoIsolationEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "default" => Ok(SystemInfoIsolationEnum::DEFAULT),
            "hyperv" => Ok(SystemInfoIsolationEnum::HYPERV),
            "process" => Ok(SystemInfoIsolationEnum::PROCESS),
            "" => Ok(SystemInfoIsolationEnum::EMPTY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for SystemInfoIsolationEnum {
    fn as_ref(&self) -> &str {
        match self { 
            SystemInfoIsolationEnum::DEFAULT => "default",
            SystemInfoIsolationEnum::HYPERV => "hyperv",
            SystemInfoIsolationEnum::PROCESS => "process",
            SystemInfoIsolationEnum::EMPTY => "",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemInfoDefaultAddressPools {
    /// The network address in CIDR format
    #[serde(rename = "Base")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub base: Option<String>,

    /// The network pool size
    #[serde(rename = "Size")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub size: Option<i64>,

}

/// Response of Engine API: GET \"/version\" 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemVersion {
    #[serde(rename = "Platform")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platform: Option<SystemVersionPlatform>,

    /// Information about system components 
    #[serde(rename = "Components")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub components: Option<Vec<SystemVersionComponents>>,

    /// The version of the daemon
    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<String>,

    /// The default (and highest) API version that is supported by the daemon 
    #[serde(rename = "ApiVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub api_version: Option<String>,

    /// The minimum API version that is supported by the daemon 
    #[serde(rename = "MinAPIVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub min_api_version: Option<String>,

    /// The Git commit of the source code that was used to build the daemon 
    #[serde(rename = "GitCommit")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub git_commit: Option<String>,

    /// The version Go used to compile the daemon, and the version of the Go runtime in use. 
    #[serde(rename = "GoVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub go_version: Option<String>,

    /// The operating system that the daemon is running on (\"linux\" or \"windows\") 
    #[serde(rename = "Os")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub os: Option<String>,

    /// The architecture that the daemon is running on 
    #[serde(rename = "Arch")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub arch: Option<String>,

    /// The kernel version (`uname -r`) that the daemon is running on.  This field is omitted when empty. 
    #[serde(rename = "KernelVersion")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub kernel_version: Option<String>,

    /// Indicates if the daemon is started with experimental features enabled.  This field is omitted when empty / false. 
    #[serde(rename = "Experimental")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub experimental: Option<bool>,

    /// The date and time that the daemon was compiled. 
    #[serde(rename = "BuildTime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub build_time: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemVersionComponents {
    /// Name of the component 
    #[serde(rename = "Name")]
    pub name: String,

    /// Version of the component 
    #[serde(rename = "Version")]
    pub version: String,

    /// Key/value pairs of strings with additional information about the component. These values are intended for informational purposes only, and their content is not defined, and not part of the API specification.  These messages can be printed by the client as information to the user. 
    #[serde(rename = "Details")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub details: Option<HashMap<String, String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct SystemVersionPlatform {
    #[serde(rename = "Name")]
    pub name: String,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Task {
    /// The ID of the task.
    #[serde(rename = "ID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,

    #[serde(rename = "Version")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub version: Option<ObjectVersion>,

    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    #[serde(rename = "UpdatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub updated_at: Option<BollardDate>,

    /// Name of the task.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "Spec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spec: Option<TaskSpec>,

    /// The ID of the service this task is part of.
    #[serde(rename = "ServiceID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub service_id: Option<String>,

    #[serde(rename = "Slot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub slot: Option<i64>,

    /// The ID of the node that this task is on.
    #[serde(rename = "NodeID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,

    #[serde(rename = "AssignedGenericResources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub assigned_generic_resources: Option<GenericResources>,

    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub status: Option<TaskStatus>,

    #[serde(rename = "DesiredState")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub desired_state: Option<TaskState>,

    /// If the Service this Task belongs to is a job-mode service, contains the JobIteration of the Service this Task was created for. Absent if the Task was created for a Replicated or Global Service. 
    #[serde(rename = "JobIteration")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub job_iteration: Option<ObjectVersion>,

}

/// User modifiable task configuration.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpec {
    #[serde(rename = "PluginSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_spec: Option<TaskSpecPluginSpec>,

    #[serde(rename = "ContainerSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_spec: Option<TaskSpecContainerSpec>,

    #[serde(rename = "NetworkAttachmentSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub network_attachment_spec: Option<TaskSpecNetworkAttachmentSpec>,

    #[serde(rename = "Resources")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub resources: Option<TaskSpecResources>,

    #[serde(rename = "RestartPolicy")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub restart_policy: Option<TaskSpecRestartPolicy>,

    #[serde(rename = "Placement")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub placement: Option<TaskSpecPlacement>,

    /// A counter that triggers an update even if no relevant parameters have been changed. 
    #[serde(rename = "ForceUpdate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub force_update: Option<u64>,

    /// Runtime is the type of runtime specified for the task executor. 
    #[serde(rename = "Runtime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<String>,

    /// Specifies which networks the service should attach to.
    #[serde(rename = "Networks")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub networks: Option<Vec<NetworkAttachmentConfig>>,

    #[serde(rename = "LogDriver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub log_driver: Option<TaskSpecLogDriver>,

}

/// Container spec for the service.  <p><br /></p>  > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are > mutually exclusive. PluginSpec is only used when the Runtime field > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime > field is set to `attachment`. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpec {
    /// The image name to use for the container
    #[serde(rename = "Image")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,

    /// User-defined key/value data.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    /// The command to be run in the image.
    #[serde(rename = "Command")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub command: Option<Vec<String>>,

    /// Arguments to the command.
    #[serde(rename = "Args")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub args: Option<Vec<String>>,

    /// The hostname to use for the container, as a valid [RFC 1123](https://tools.ietf.org/html/rfc1123) hostname. 
    #[serde(rename = "Hostname")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hostname: Option<String>,

    /// A list of environment variables in the form `VAR=value`. 
    #[serde(rename = "Env")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub env: Option<Vec<String>>,

    /// The working directory for commands to run in.
    #[serde(rename = "Dir")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dir: Option<String>,

    /// The user inside the container.
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// A list of additional groups that the container process will run as. 
    #[serde(rename = "Groups")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub groups: Option<Vec<String>>,

    #[serde(rename = "Privileges")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub privileges: Option<TaskSpecContainerSpecPrivileges>,

    /// Whether a pseudo-TTY should be allocated.
    #[serde(rename = "TTY")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tty: Option<bool>,

    /// Open `stdin`
    #[serde(rename = "OpenStdin")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub open_stdin: Option<bool>,

    /// Mount the container's root filesystem as read only.
    #[serde(rename = "ReadOnly")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub read_only: Option<bool>,

    /// Specification for mounts to be added to containers created as part of the service. 
    #[serde(rename = "Mounts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mounts: Option<Vec<Mount>>,

    /// Signal to stop the container.
    #[serde(rename = "StopSignal")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_signal: Option<String>,

    /// Amount of time to wait for the container to terminate before forcefully killing it. 
    #[serde(rename = "StopGracePeriod")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub stop_grace_period: Option<i64>,

    #[serde(rename = "HealthCheck")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub health_check: Option<HealthConfig>,

    /// A list of hostname/IP mappings to add to the container's `hosts` file. The format of extra hosts is specified in the [hosts(5)](http://man7.org/linux/man-pages/man5/hosts.5.html) man page:      IP_address canonical_hostname [aliases...] 
    #[serde(rename = "Hosts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub hosts: Option<Vec<String>>,

    #[serde(rename = "DNSConfig")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dns_config: Option<TaskSpecContainerSpecDnsConfig>,

    /// Secrets contains references to zero or more secrets that will be exposed to the service. 
    #[serde(rename = "Secrets")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secrets: Option<Vec<TaskSpecContainerSpecSecrets>>,

    /// An integer value containing the score given to the container in order to tune OOM killer preferences. 
    #[serde(rename = "OomScoreAdj")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub oom_score_adj: Option<i64>,

    /// Configs contains references to zero or more configs that will be exposed to the service. 
    #[serde(rename = "Configs")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub configs: Option<Vec<TaskSpecContainerSpecConfigs>>,

    /// Isolation technology of the containers running the service. (Windows only) 
    #[serde(rename = "Isolation")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub isolation: Option<TaskSpecContainerSpecIsolationEnum>,

    /// Run an init inside the container that forwards signals and reaps processes. This field is omitted if empty, and the default (as configured on the daemon) is used. 
    #[serde(rename = "Init")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub init: Option<bool>,

    /// Set kernel namedspaced parameters (sysctls) in the container. The Sysctls option on services accepts the same sysctls as the are supported on containers. Note that while the same sysctls are supported, no guarantees or checks are made about their suitability for a clustered environment, and it's up to the user to determine whether a given sysctl will work properly in a Service. 
    #[serde(rename = "Sysctls")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub sysctls: Option<HashMap<String, String>>,

    /// A list of kernel capabilities to add to the default set for the container. 
    #[serde(rename = "CapabilityAdd")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_add: Option<Vec<String>>,

    /// A list of kernel capabilities to drop from the default set for the container. 
    #[serde(rename = "CapabilityDrop")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub capability_drop: Option<Vec<String>>,

    /// A list of resource limits to set in the container. For example: `{\"Name\": \"nofile\", \"Soft\": 1024, \"Hard\": 2048}`\" 
    #[serde(rename = "Ulimits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub ulimits: Option<Vec<ResourcesUlimits>>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum TaskSpecContainerSpecIsolationEnum { 
    #[serde(rename = "default")]
    DEFAULT,
    #[serde(rename = "process")]
    PROCESS,
    #[serde(rename = "hyperv")]
    HYPERV,
    #[serde(rename = "")]
    EMPTY,
}

impl ::std::fmt::Display for TaskSpecContainerSpecIsolationEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            TaskSpecContainerSpecIsolationEnum::DEFAULT => write!(f, "{}", "default"),
            TaskSpecContainerSpecIsolationEnum::PROCESS => write!(f, "{}", "process"),
            TaskSpecContainerSpecIsolationEnum::HYPERV => write!(f, "{}", "hyperv"),
            TaskSpecContainerSpecIsolationEnum::EMPTY => write!(f, "{}", ""),

        }
    }
}

impl ::std::str::FromStr for TaskSpecContainerSpecIsolationEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "default" => Ok(TaskSpecContainerSpecIsolationEnum::DEFAULT),
            "process" => Ok(TaskSpecContainerSpecIsolationEnum::PROCESS),
            "hyperv" => Ok(TaskSpecContainerSpecIsolationEnum::HYPERV),
            "" => Ok(TaskSpecContainerSpecIsolationEnum::EMPTY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for TaskSpecContainerSpecIsolationEnum {
    fn as_ref(&self) -> &str {
        match self { 
            TaskSpecContainerSpecIsolationEnum::DEFAULT => "default",
            TaskSpecContainerSpecIsolationEnum::PROCESS => "process",
            TaskSpecContainerSpecIsolationEnum::HYPERV => "hyperv",
            TaskSpecContainerSpecIsolationEnum::EMPTY => "",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecConfigs {
    #[serde(rename = "File")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<TaskSpecContainerSpecFile1>,

    /// Runtime represents a target that is not mounted into the container but is used by the task  <p><br /><p>  > **Note**: `Configs.File` and `Configs.Runtime` are mutually > exclusive 
    #[serde(rename = "Runtime")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub runtime: Option<HashMap<(), ()>>,

    /// ConfigID represents the ID of the specific config that we're referencing. 
    #[serde(rename = "ConfigID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_id: Option<String>,

    /// ConfigName is the name of the config that this references, but this is just provided for lookup/display purposes. The config in the reference will be identified by its ID. 
    #[serde(rename = "ConfigName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config_name: Option<String>,

}

/// Specification for DNS related configurations in resolver configuration file (`resolv.conf`). 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecDnsConfig {
    /// The IP addresses of the name servers.
    #[serde(rename = "Nameservers")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub nameservers: Option<Vec<String>>,

    /// A search list for host-name lookup.
    #[serde(rename = "Search")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub search: Option<Vec<String>>,

    /// A list of internal resolver variables to be modified (e.g., `debug`, `ndots:3`, etc.). 
    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<Vec<String>>,

}

/// File represents a specific target that is backed by a file. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecFile {
    /// Name represents the final filename in the filesystem. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// UID represents the file UID.
    #[serde(rename = "UID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// GID represents the file GID.
    #[serde(rename = "GID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<String>,

    /// Mode represents the FileMode of the file.
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

}

/// File represents a specific target that is backed by a file.  <p><br /><p>  > **Note**: `Configs.File` and `Configs.Runtime` are mutually exclusive 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecFile1 {
    /// Name represents the final filename in the filesystem. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// UID represents the file UID.
    #[serde(rename = "UID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub uid: Option<String>,

    /// GID represents the file GID.
    #[serde(rename = "GID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub gid: Option<String>,

    /// Mode represents the FileMode of the file.
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<u32>,

}

/// Security options for the container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecPrivileges {
    #[serde(rename = "CredentialSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub credential_spec: Option<TaskSpecContainerSpecPrivilegesCredentialSpec>,

    #[serde(rename = "SELinuxContext")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub se_linux_context: Option<TaskSpecContainerSpecPrivilegesSeLinuxContext>,

    #[serde(rename = "Seccomp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub seccomp: Option<TaskSpecContainerSpecPrivilegesSeccomp>,

    #[serde(rename = "AppArmor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub app_armor: Option<TaskSpecContainerSpecPrivilegesAppArmor>,

    /// Configuration of the no_new_privs bit in the container
    #[serde(rename = "NoNewPrivileges")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub no_new_privileges: Option<bool>,

}

/// Options for configuring AppArmor on the container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecPrivilegesAppArmor {
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<TaskSpecContainerSpecPrivilegesAppArmorModeEnum>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum TaskSpecContainerSpecPrivilegesAppArmorModeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "default")]
    DEFAULT,
    #[serde(rename = "disabled")]
    DISABLED,
}

impl ::std::fmt::Display for TaskSpecContainerSpecPrivilegesAppArmorModeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::EMPTY => write!(f, ""),
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DEFAULT => write!(f, "{}", "default"),
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DISABLED => write!(f, "{}", "disabled"),

        }
    }
}

impl ::std::str::FromStr for TaskSpecContainerSpecPrivilegesAppArmorModeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(TaskSpecContainerSpecPrivilegesAppArmorModeEnum::EMPTY),
            "default" => Ok(TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DEFAULT),
            "disabled" => Ok(TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DISABLED),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for TaskSpecContainerSpecPrivilegesAppArmorModeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::EMPTY => "",
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DEFAULT => "default",
            TaskSpecContainerSpecPrivilegesAppArmorModeEnum::DISABLED => "disabled",
        }
    }
}

/// CredentialSpec for managed service account (Windows only)
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecPrivilegesCredentialSpec {
    /// Load credential spec from a Swarm Config with the given ID. The specified config must also be present in the Configs field with the Runtime property set.  <p><br /></p>   > **Note**: `CredentialSpec.File`, `CredentialSpec.Registry`, > and `CredentialSpec.Config` are mutually exclusive. 
    #[serde(rename = "Config")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,

    /// Load credential spec from this file. The file is read by the daemon, and must be present in the `CredentialSpecs` subdirectory in the docker data directory, which defaults to `C:\\ProgramData\\Docker\\` on Windows.  For example, specifying `spec.json` loads `C:\\ProgramData\\Docker\\CredentialSpecs\\spec.json`.  <p><br /></p>  > **Note**: `CredentialSpec.File`, `CredentialSpec.Registry`, > and `CredentialSpec.Config` are mutually exclusive. 
    #[serde(rename = "File")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<String>,

    /// Load credential spec from this value in the Windows registry. The specified registry value must be located in:  `HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Virtualization\\Containers\\CredentialSpecs`  <p><br /></p>   > **Note**: `CredentialSpec.File`, `CredentialSpec.Registry`, > and `CredentialSpec.Config` are mutually exclusive. 
    #[serde(rename = "Registry")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub registry: Option<String>,

}

/// SELinux labels of the container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecPrivilegesSeLinuxContext {
    /// Disable SELinux
    #[serde(rename = "Disable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disable: Option<bool>,

    /// SELinux user label
    #[serde(rename = "User")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub user: Option<String>,

    /// SELinux role label
    #[serde(rename = "Role")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub role: Option<String>,

    /// SELinux type label
    #[serde(rename = "Type")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub typ: Option<String>,

    /// SELinux level label
    #[serde(rename = "Level")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub level: Option<String>,

}

/// Options for configuring seccomp on the container
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecPrivilegesSeccomp {
    #[serde(rename = "Mode")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub mode: Option<TaskSpecContainerSpecPrivilegesSeccompModeEnum>,

    /// The custom seccomp profile as a json object
    #[serde(rename = "Profile")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum TaskSpecContainerSpecPrivilegesSeccompModeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "default")]
    DEFAULT,
    #[serde(rename = "unconfined")]
    UNCONFINED,
    #[serde(rename = "custom")]
    CUSTOM,
}

impl ::std::fmt::Display for TaskSpecContainerSpecPrivilegesSeccompModeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::EMPTY => write!(f, ""),
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::DEFAULT => write!(f, "{}", "default"),
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::UNCONFINED => write!(f, "{}", "unconfined"),
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::CUSTOM => write!(f, "{}", "custom"),

        }
    }
}

impl ::std::str::FromStr for TaskSpecContainerSpecPrivilegesSeccompModeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(TaskSpecContainerSpecPrivilegesSeccompModeEnum::EMPTY),
            "default" => Ok(TaskSpecContainerSpecPrivilegesSeccompModeEnum::DEFAULT),
            "unconfined" => Ok(TaskSpecContainerSpecPrivilegesSeccompModeEnum::UNCONFINED),
            "custom" => Ok(TaskSpecContainerSpecPrivilegesSeccompModeEnum::CUSTOM),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for TaskSpecContainerSpecPrivilegesSeccompModeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::EMPTY => "",
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::DEFAULT => "default",
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::UNCONFINED => "unconfined",
            TaskSpecContainerSpecPrivilegesSeccompModeEnum::CUSTOM => "custom",
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecContainerSpecSecrets {
    #[serde(rename = "File")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub file: Option<TaskSpecContainerSpecFile>,

    /// SecretID represents the ID of the specific secret that we're referencing. 
    #[serde(rename = "SecretID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_id: Option<String>,

    /// SecretName is the name of the secret that this references, but this is just provided for lookup/display purposes. The secret in the reference will be identified by its ID. 
    #[serde(rename = "SecretName")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub secret_name: Option<String>,

}

/// Specifies the log driver to use for tasks created from this spec. If not present, the default one for the swarm will be used, finally falling back to the engine default if not specified. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecLogDriver {
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    #[serde(rename = "Options")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub options: Option<HashMap<String, String>>,

}

/// Read-only spec type for non-swarm containers attached to swarm overlay networks.  <p><br /></p>  > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are > mutually exclusive. PluginSpec is only used when the Runtime field > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime > field is set to `attachment`. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecNetworkAttachmentSpec {
    /// ID of the container represented by this task
    #[serde(rename = "ContainerID")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_id: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecPlacement {
    /// An array of constraint expressions to limit the set of nodes where a task can be scheduled. Constraint expressions can either use a _match_ (`==`) or _exclude_ (`!=`) rule. Multiple constraints find nodes that satisfy every expression (AND match). Constraints can match node or Docker Engine labels as follows:  node attribute       | matches                        | example ---------------------|--------------------------------|----------------------------------------------- `node.id`            | Node ID                        | `node.id==2ivku8v2gvtg4` `node.hostname`      | Node hostname                  | `node.hostname!=node-2` `node.role`          | Node role (`manager`/`worker`) | `node.role==manager` `node.platform.os`   | Node operating system          | `node.platform.os==windows` `node.platform.arch` | Node architecture              | `node.platform.arch==x86_64` `node.labels`        | User-defined node labels       | `node.labels.security==high` `engine.labels`      | Docker Engine's labels         | `engine.labels.operatingsystem==ubuntu-24.04`  `engine.labels` apply to Docker Engine labels like operating system, drivers, etc. Swarm administrators add `node.labels` for operational purposes by using the [`node update endpoint`](#operation/NodeUpdate). 
    #[serde(rename = "Constraints")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub constraints: Option<Vec<String>>,

    /// Preferences provide a way to make the scheduler aware of factors such as topology. They are provided in order from highest to lowest precedence. 
    #[serde(rename = "Preferences")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub preferences: Option<Vec<TaskSpecPlacementPreferences>>,

    /// Maximum number of replicas for per node (default value is 0, which is unlimited) 
    #[serde(rename = "MaxReplicas")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_replicas: Option<i64>,

    /// Platforms stores all the platforms that the service's image can run on. This field is used in the platform filter for scheduling. If empty, then the platform filter is off, meaning there are no scheduling restrictions. 
    #[serde(rename = "Platforms")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub platforms: Option<Vec<Platform>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecPlacementPreferences {
    #[serde(rename = "Spread")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spread: Option<TaskSpecPlacementSpread>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecPlacementSpread {
    /// label descriptor, such as `engine.labels.az`. 
    #[serde(rename = "SpreadDescriptor")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub spread_descriptor: Option<String>,

}

/// Plugin spec for the service.  *(Experimental release only.)*  <p><br /></p>  > **Note**: ContainerSpec, NetworkAttachmentSpec, and PluginSpec are > mutually exclusive. PluginSpec is only used when the Runtime field > is set to `plugin`. NetworkAttachmentSpec is used when the Runtime > field is set to `attachment`. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecPluginSpec {
    /// The name or 'alias' to use for the plugin.
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// The plugin image reference to use.
    #[serde(rename = "Remote")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub remote: Option<String>,

    /// Disable the plugin once scheduled.
    #[serde(rename = "Disabled")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub disabled: Option<bool>,

    #[serde(rename = "PluginPrivilege")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub plugin_privilege: Option<Vec<PluginPrivilege>>,

}

/// Resource requirements which apply to each individual container created as part of the service. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecResources {
    /// Define resources limits.
    #[serde(rename = "Limits")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub limits: Option<Limit>,

    /// Define resources reservation.
    #[serde(rename = "Reservations")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reservations: Option<ResourceObject>,

    /// Amount of swap in bytes - can only be used together with a memory limit. If not specified, the default behaviour is to grant a swap space twice as big as the memory limit. Set to -1 to enable unlimited swap. 
    #[serde(rename = "SwapBytes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub swap_bytes: Option<i64>,

    /// Tune the service's containers' memory swappiness (0 to 100). If not specified, defaults to the containers' OS' default, generally 60, or whatever value was predefined in the image. Set to -1 to unset a previously set value. 
    #[serde(rename = "MemorySwappiness")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub memory_swappiness: Option<i64>,

}

/// Specification for the restart policy which applies to containers created as part of this service. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskSpecRestartPolicy {
    /// Condition for restart.
    #[serde(rename = "Condition")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub condition: Option<TaskSpecRestartPolicyConditionEnum>,

    /// Delay between restart attempts.
    #[serde(rename = "Delay")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub delay: Option<i64>,

    /// Maximum attempts to restart a given container before giving up (default value is 0, which is ignored). 
    #[serde(rename = "MaxAttempts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub max_attempts: Option<i64>,

    /// Windows is the time window used to evaluate the restart policy (default value is 0, which is unbounded). 
    #[serde(rename = "Window")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub window: Option<i64>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum TaskSpecRestartPolicyConditionEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "none")]
    NONE,
    #[serde(rename = "on-failure")]
    ON_FAILURE,
    #[serde(rename = "any")]
    ANY,
}

impl ::std::fmt::Display for TaskSpecRestartPolicyConditionEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            TaskSpecRestartPolicyConditionEnum::EMPTY => write!(f, ""),
            TaskSpecRestartPolicyConditionEnum::NONE => write!(f, "{}", "none"),
            TaskSpecRestartPolicyConditionEnum::ON_FAILURE => write!(f, "{}", "on-failure"),
            TaskSpecRestartPolicyConditionEnum::ANY => write!(f, "{}", "any"),

        }
    }
}

impl ::std::str::FromStr for TaskSpecRestartPolicyConditionEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(TaskSpecRestartPolicyConditionEnum::EMPTY),
            "none" => Ok(TaskSpecRestartPolicyConditionEnum::NONE),
            "on-failure" => Ok(TaskSpecRestartPolicyConditionEnum::ON_FAILURE),
            "any" => Ok(TaskSpecRestartPolicyConditionEnum::ANY),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for TaskSpecRestartPolicyConditionEnum {
    fn as_ref(&self) -> &str {
        match self { 
            TaskSpecRestartPolicyConditionEnum::EMPTY => "",
            TaskSpecRestartPolicyConditionEnum::NONE => "none",
            TaskSpecRestartPolicyConditionEnum::ON_FAILURE => "on-failure",
            TaskSpecRestartPolicyConditionEnum::ANY => "any",
        }
    }
}

/// Enumeration of values.
/// Since this enum's variants do not hold data, we can easily define them them as `#[repr(C)]`
/// which helps with FFI.
#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum TaskState { 
    #[serde(rename = "new")]
    NEW,
    #[serde(rename = "allocated")]
    ALLOCATED,
    #[serde(rename = "pending")]
    PENDING,
    #[serde(rename = "assigned")]
    ASSIGNED,
    #[serde(rename = "accepted")]
    ACCEPTED,
    #[serde(rename = "preparing")]
    PREPARING,
    #[serde(rename = "ready")]
    READY,
    #[serde(rename = "starting")]
    STARTING,
    #[serde(rename = "running")]
    RUNNING,
    #[serde(rename = "complete")]
    COMPLETE,
    #[serde(rename = "shutdown")]
    SHUTDOWN,
    #[serde(rename = "failed")]
    FAILED,
    #[serde(rename = "rejected")]
    REJECTED,
    #[serde(rename = "remove")]
    REMOVE,
    #[serde(rename = "orphaned")]
    ORPHANED,
}

impl ::std::fmt::Display for TaskState {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            TaskState::NEW => write!(f, "{}", "new"),
            TaskState::ALLOCATED => write!(f, "{}", "allocated"),
            TaskState::PENDING => write!(f, "{}", "pending"),
            TaskState::ASSIGNED => write!(f, "{}", "assigned"),
            TaskState::ACCEPTED => write!(f, "{}", "accepted"),
            TaskState::PREPARING => write!(f, "{}", "preparing"),
            TaskState::READY => write!(f, "{}", "ready"),
            TaskState::STARTING => write!(f, "{}", "starting"),
            TaskState::RUNNING => write!(f, "{}", "running"),
            TaskState::COMPLETE => write!(f, "{}", "complete"),
            TaskState::SHUTDOWN => write!(f, "{}", "shutdown"),
            TaskState::FAILED => write!(f, "{}", "failed"),
            TaskState::REJECTED => write!(f, "{}", "rejected"),
            TaskState::REMOVE => write!(f, "{}", "remove"),
            TaskState::ORPHANED => write!(f, "{}", "orphaned"),
        }
    }
}

impl ::std::str::FromStr for TaskState {
    type Err = ();
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s {
            "new" => Ok(TaskState::NEW),
            "allocated" => Ok(TaskState::ALLOCATED),
            "pending" => Ok(TaskState::PENDING),
            "assigned" => Ok(TaskState::ASSIGNED),
            "accepted" => Ok(TaskState::ACCEPTED),
            "preparing" => Ok(TaskState::PREPARING),
            "ready" => Ok(TaskState::READY),
            "starting" => Ok(TaskState::STARTING),
            "running" => Ok(TaskState::RUNNING),
            "complete" => Ok(TaskState::COMPLETE),
            "shutdown" => Ok(TaskState::SHUTDOWN),
            "failed" => Ok(TaskState::FAILED),
            "rejected" => Ok(TaskState::REJECTED),
            "remove" => Ok(TaskState::REMOVE),
            "orphaned" => Ok(TaskState::ORPHANED),
            _ => Err(()),
        }
    }
}

impl std::default::Default for TaskState {
    fn default() -> Self { 
        TaskState::NEW
    }
}

/// represents the status of a task.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TaskStatus {
    #[serde(rename = "Timestamp")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub timestamp: Option<BollardDate>,

    #[serde(rename = "State")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub state: Option<TaskState>,

    #[serde(rename = "Message")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,

    #[serde(rename = "Err")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub err: Option<String>,

    #[serde(rename = "ContainerStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub container_status: Option<ContainerStatus>,

    #[serde(rename = "PortStatus")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub port_status: Option<PortStatus>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct ThrottleDevice {
    /// Device path
    #[serde(rename = "Path")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub path: Option<String>,

    /// Rate
    #[serde(rename = "Rate")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate: Option<i64>,

}

/// Information about the issuer of leaf TLS certificates and the trusted root CA certificate. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct TlsInfo {
    /// The root CA certificate(s) that are used to validate leaf TLS certificates. 
    #[serde(rename = "TrustRoot")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub trust_root: Option<String>,

    /// The base64-url-safe-encoded raw subject bytes of the issuer.
    #[serde(rename = "CertIssuerSubject")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_issuer_subject: Option<String>,

    /// The base64-url-safe-encoded raw public key bytes of the issuer. 
    #[serde(rename = "CertIssuerPublicKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cert_issuer_public_key: Option<String>,

}

/// A map of topological domains to topological segments. For in depth details, see documentation for the Topology object in the CSI specification. 
// special-casing PortMap, cos swagger-codegen doesn't figure out this type
pub type Topology = HashMap<String, Option<Vec<PortBinding>>>;

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct UnlockKeyResponse {
    /// The swarm's unlock key.
    #[serde(rename = "UnlockKey")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub unlock_key: Option<String>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct Volume {
    /// Name of the volume.
    #[serde(rename = "Name")]
    pub name: String,

    /// Name of the volume driver used by the volume.
    #[serde(rename = "Driver")]
    pub driver: String,

    /// Mount path of the volume on the host.
    #[serde(rename = "Mountpoint")]
    pub mountpoint: String,

    /// Date/Time the volume was created.
    #[serde(rename = "CreatedAt")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(
        default,
        deserialize_with = "deserialize_timestamp",
        serialize_with = "serialize_timestamp"
    )]
    pub created_at: Option<BollardDate>,

    /// Low-level details about the volume, provided by the volume driver. Details are returned as a map with key/value pairs: `{\"key\":\"value\",\"key2\":\"value2\"}`.  The `Status` field is optional, and is omitted if the volume driver does not support this feature. 
    #[serde(rename = "Status")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(deserialize_with = "deserialize_hashmap_string_hashmap_empty", serialize_with = "serialize_hashmap_string_hashmap_empty", default)]
    pub status: Option<Vec<String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(deserialize_with = "deserialize_nonoptional_map")]
    pub labels: HashMap<String, String>,

    /// The level at which the volume exists. Either `global` for cluster-wide, or `local` for machine level. 
    #[serde(rename = "Scope")]
    #[serde(skip_serializing_if = "Option::is_none")]
    #[serde(with = "serde_ext::none_as_empty_string")]
    pub scope: Option<VolumeScopeEnum>,

    #[serde(rename = "ClusterVolume")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_volume: Option<ClusterVolume>,

    /// The driver specific options used when creating the volume. 
    #[serde(rename = "Options")]
    #[serde(deserialize_with = "deserialize_nonoptional_map")]
    pub options: HashMap<String, String>,

    #[serde(rename = "UsageData")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub usage_data: Option<VolumeUsageData>,

}

#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy, PartialEq, PartialOrd, Serialize, Deserialize, Eq, Ord)]
pub enum VolumeScopeEnum { 
    #[serde(rename = "")]
    EMPTY,
    #[serde(rename = "local")]
    LOCAL,
    #[serde(rename = "global")]
    GLOBAL,
}

impl ::std::fmt::Display for VolumeScopeEnum {
    fn fmt(&self, f: &mut ::std::fmt::Formatter) -> ::std::fmt::Result {
        match *self { 
            VolumeScopeEnum::EMPTY => write!(f, ""),
            VolumeScopeEnum::LOCAL => write!(f, "{}", "local"),
            VolumeScopeEnum::GLOBAL => write!(f, "{}", "global"),

        }
    }
}

impl ::std::str::FromStr for VolumeScopeEnum {
    type Err = String;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        match s { 
            "" => Ok(VolumeScopeEnum::EMPTY),
            "local" => Ok(VolumeScopeEnum::LOCAL),
            "global" => Ok(VolumeScopeEnum::GLOBAL),
            x => Err(format!("Invalid enum type: {}", x)),
        }
    }
}

impl ::std::convert::AsRef<str> for VolumeScopeEnum {
    fn as_ref(&self) -> &str {
        match self { 
            VolumeScopeEnum::EMPTY => "",
            VolumeScopeEnum::LOCAL => "local",
            VolumeScopeEnum::GLOBAL => "global",
        }
    }
}

/// Volume configuration
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumeCreateRequest {
    /// The new volume's name. If not specified, Docker generates a name. 
    #[serde(rename = "Name")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,

    /// Name of the volume driver to use.
    #[serde(rename = "Driver")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver: Option<String>,

    /// A mapping of driver options and values. These options are passed directly to the driver and are driver specific. 
    #[serde(rename = "DriverOpts")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub driver_opts: Option<HashMap<String, String>>,

    /// User-defined key/value metadata.
    #[serde(rename = "Labels")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub labels: Option<HashMap<String, String>>,

    #[serde(rename = "ClusterVolumeSpec")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cluster_volume_spec: Option<ClusterVolumeSpec>,

}

/// Volume list response
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumeListResponse {
    /// List of volumes
    #[serde(rename = "Volumes")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes: Option<Vec<Volume>>,

    /// Warnings that occurred when fetching the list of volumes. 
    #[serde(rename = "Warnings")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub warnings: Option<Vec<String>>,

}

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumePruneResponse {
    /// Volumes that were deleted
    #[serde(rename = "VolumesDeleted")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub volumes_deleted: Option<Vec<String>>,

    /// Disk space reclaimed in bytes
    #[serde(rename = "SpaceReclaimed")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub space_reclaimed: Option<i64>,

}

/// Usage details about the volume. This information is used by the `GET /system/df` endpoint, and omitted in other endpoints. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumeUsageData {
    /// Amount of disk space used by the volume (in bytes). This information is only available for volumes created with the `\"local\"` volume driver. For volumes created with other volume drivers, this field is set to `-1` (\"not available\") 
    #[serde(rename = "Size")]
    pub size: i64,

    /// The number of containers referencing this volume. This field is set to `-1` if the reference-count is not available. 
    #[serde(rename = "RefCount")]
    pub ref_count: i64,

}

/// represents system data usage for volume resources. 
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct VolumesDiskUsage {
    /// Count of active volumes. 
    #[serde(rename = "ActiveCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub active_count: Option<i64>,

    /// Count of all volumes. 
    #[serde(rename = "TotalCount")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_count: Option<i64>,

    /// Disk space that can be reclaimed by removing inactive volumes. 
    #[serde(rename = "Reclaimable")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reclaimable: Option<i64>,

    /// Disk space in use by volumes. 
    #[serde(rename = "TotalSize")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub total_size: Option<i64>,

    /// List of volumes. 
    #[serde(rename = "Items")]
    #[serde(skip_serializing_if = "Option::is_none")]
    pub items: Option<Vec<serde_json::Value>>,

}
