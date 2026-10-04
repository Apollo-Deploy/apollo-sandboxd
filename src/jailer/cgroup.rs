use crate::error::{Error, Result};
use sandboxd_protocol::Resources;
use serde::{Deserialize, Serialize};
use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::MetadataExt,
    path::{Path, PathBuf},
};

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CgroupLimits {
    pub memory_max: u64,
    pub cpu_max: String,
    pub cpuset: Option<String>,
}

impl CgroupLimits {
    pub fn from_resources(resources: &Resources) -> Result<Self> {
        let memory = resources.host_memory_max_bytes;
        let quota = resources.cpu_quota_us;
        let period = resources.cpu_period_us;
        if memory == 0 || quota == 0 || period == 0 {
            return Err(Error::Config("cgroup limits must be nonzero"));
        }
        Ok(Self {
            memory_max: memory,
            cpu_max: format!("{quota} {period}"),
            cpuset: resources.cpuset.clone(),
        })
    }
}

/// A daemon-owned cgroup-v2 leaf. Creation and limit writes happen before the
/// jailer external effect. The parent must already be an operator-configured
/// subtree; this type never writes outside its configured root.
pub struct CgroupV2 {
    path: PathBuf,
    limits: CgroupLimits,
    parent_arg: String,
    device: u64,
    inode: u64,
    parent_device: u64,
    parent_inode: u64,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CgroupIdentity {
    pub device: u64,
    pub inode: u64,
}

impl CgroupV2 {
    pub fn prepare(parent: &Path, name: &str, limits: CgroupLimits) -> Result<Self> {
        validate_component(name)?;
        ensure_cgroup2(parent)?;
        require_controller(parent, "memory")?;
        require_controller(parent, "cpu")?;
        if limits.cpuset.is_some() {
            require_controller(parent, "cpuset")?;
            validate_cpuset(parent, limits.cpuset.as_deref().ok_or(Error::State)?)?;
        }
        validate_directory_chain(parent)?;
        let path = parent.join(name);
        if fs::symlink_metadata(&path).is_ok() {
            return Err(Error::Path);
        }
        fs::create_dir(&path)?;
        let parent_arg = relative_cgroup_path(&path)?;
        let parent_identity = fs::symlink_metadata(parent)?;
        let identity = fs::symlink_metadata(&path)?;
        let cgroup = Self {
            path,
            limits,
            parent_arg,
            device: identity.dev(),
            inode: identity.ino(),
            parent_device: parent_identity.dev(),
            parent_inode: parent_identity.ino(),
        };
        let result = (|| {
            cgroup.write_limit("memory.max", &cgroup.limits.memory_max.to_string())?;
            cgroup.write_limit("cpu.max", &cgroup.limits.cpu_max)?;
            if let Some(cpuset) = &cgroup.limits.cpuset {
                cgroup.write_limit("cpuset.cpus", cpuset)?;
            }
            cgroup.require_file("cgroup.procs")?;
            Ok::<(), Error>(())
        })();
        if let Err(error) = result {
            let _ = fs::remove_dir(&cgroup.path);
            return Err(error);
        }
        Ok(cgroup)
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    pub fn parent_argument(&self) -> &str {
        &self.parent_arg
    }

    pub fn identity(&self) -> CgroupIdentity {
        CgroupIdentity {
            device: self.device,
            inode: self.inode,
        }
    }

    /// Returns the current members without trusting a PID supplied by a
    /// caller. The caller must still capture and verify each process identity.
    pub fn processes(&self) -> Result<Vec<u32>> {
        Self::processes_at(&self.path)
    }

    pub fn processes_at(path: &Path) -> Result<Vec<u32>> {
        let mut text = String::new();
        File::open(path.join("cgroup.procs"))?
            .take(1025)
            .read_to_string(&mut text)?;
        if text.len() > 1024 {
            return Err(Error::Config("cgroup process list exceeds bound"));
        }
        let mut pids = Vec::new();
        for line in text.lines() {
            let pid = line
                .parse::<u32>()
                .map_err(|_| Error::Config("invalid cgroup process list"))?;
            if pid != 0 {
                pids.push(pid);
            }
            if pids.len() > 64 {
                return Err(Error::Config("too many processes in VMM cgroup"));
            }
        }
        Ok(pids)
    }

    pub fn remove_owned(self) -> Result<()> {
        let meta = fs::symlink_metadata(&self.path)?;
        if !meta.is_dir()
            || meta.uid() != 0
            || meta.dev() != self.device
            || meta.ino() != self.inode
        {
            return Err(Error::Path);
        }
        let parent = self.path.parent().ok_or(Error::Path)?;
        let parent_meta = fs::symlink_metadata(parent)?;
        if !parent_meta.is_dir()
            || parent_meta.dev() != self.parent_device
            || parent_meta.ino() != self.parent_inode
        {
            return Err(Error::Path);
        }
        fs::remove_dir(&self.path)?;
        Ok(())
    }

    fn require_file(&self, name: &str) -> Result<()> {
        let path = self.path.join(name);
        let meta = fs::symlink_metadata(&path)
            .map_err(|_| Error::Config("required cgroup controller missing"))?;
        if !meta.is_file() {
            return Err(Error::Path);
        }
        Ok(())
    }

    fn write_limit(&self, name: &str, value: &str) -> Result<()> {
        if name.contains('/') || value.len() > 128 || value.bytes().any(|b| b == 0 || b == b'\n') {
            return Err(Error::Config("invalid cgroup limit"));
        }
        let path = self.path.join(name);
        let meta = fs::symlink_metadata(&path)?;
        if !meta.is_file() {
            return Err(Error::Path);
        }
        let mut file = OpenOptions::new().write(true).open(path)?;
        // cgroup control files interpret every write as a complete command.
        // A separate newline write can reset memory.max to zero. Submit the
        // complete value once; a short control write is an explicit failure.
        let command = format!("{value}\n");
        if file.write(command.as_bytes())? != command.len() {
            return Err(Error::Config("cgroup control write was incomplete"));
        }
        drop(file);
        if name != "cgroup.procs" {
            let mut actual = String::new();
            File::open(self.path.join(name))?
                .take(129)
                .read_to_string(&mut actual)?;
            let matches = if name == "cpuset.cpus" {
                parse_cpuset(actual.trim())? == parse_cpuset(value)?
            } else {
                actual.trim() == value
            };
            if !matches {
                return Err(Error::Config("cgroup limit write was not applied"));
            }
        }
        Ok(())
    }
}

fn validate_cpuset(parent: &Path, requested: &str) -> Result<()> {
    let requested = parse_cpuset(requested)?;
    let mut effective = String::new();
    File::open(parent.join("cpuset.cpus.effective"))?
        .take(257)
        .read_to_string(&mut effective)?;
    if effective.len() > 256 {
        return Err(Error::Config("effective CPU set exceeds bound"));
    }
    let effective = parse_cpuset(effective.trim())?;
    if requested.is_empty() || !requested.is_subset(&effective) {
        return Err(Error::Config("requested CPU set is unavailable"));
    }
    Ok(())
}

fn parse_cpuset(value: &str) -> Result<BTreeSet<u16>> {
    if value.is_empty() || value.len() > 256 {
        return Err(Error::Config("invalid CPU set"));
    }
    let mut cpus = BTreeSet::new();
    for part in value.split(',') {
        let (start, end) = match part.split_once('-') {
            Some((start, end)) => (start, end),
            None => (part, part),
        };
        let start = start
            .parse::<u16>()
            .map_err(|_| Error::Config("invalid CPU set"))?;
        let end = end
            .parse::<u16>()
            .map_err(|_| Error::Config("invalid CPU set"))?;
        if start > end || end > 8191 {
            return Err(Error::Config("invalid CPU set"));
        }
        for cpu in start..=end {
            if !cpus.insert(cpu) {
                return Err(Error::Config("overlapping CPU set"));
            }
        }
    }
    Ok(cpus)
}

#[cfg(target_os = "linux")]
fn ensure_cgroup2(path: &Path) -> Result<()> {
    let file = File::open(path)?;
    let stat = rustix::fs::fstatfs(&file)?;
    if stat.f_type as u64 != 0x6367_7270 {
        return Err(Error::Config("cgroup parent is not cgroup v2"));
    }
    Ok(())
}

#[cfg(not(target_os = "linux"))]
fn ensure_cgroup2(_path: &Path) -> Result<()> {
    Err(Error::Config("cgroup v2 requires Linux"))
}

fn require_controller(parent: &Path, controller: &str) -> Result<()> {
    let mut available = String::new();
    File::open(parent.join("cgroup.controllers"))?.read_to_string(&mut available)?;
    let mut enabled = String::new();
    File::open(parent.join("cgroup.subtree_control"))?.read_to_string(&mut enabled)?;
    if !available.split_whitespace().any(|v| v == controller)
        || !enabled.split_whitespace().any(|v| v == controller)
    {
        return Err(Error::Config(
            "required cgroup v2 controller is unavailable",
        ));
    }
    Ok(())
}

fn validate_directory_chain(path: &Path) -> Result<()> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, std::path::Component::ParentDir))
    {
        return Err(Error::Path);
    }
    let mut current = PathBuf::from("/");
    for component in path.components() {
        if let std::path::Component::Normal(name) = component {
            current.push(name);
            let meta = fs::symlink_metadata(&current)?;
            if !meta.is_dir()
                || meta.file_type().is_symlink()
                || meta.uid() != 0
                || meta.mode() & 0o022 != 0
            {
                return Err(Error::Path);
            }
        }
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn relative_cgroup_path(path: &Path) -> Result<String> {
    let text = std::fs::read_to_string("/proc/self/mountinfo")?;
    for line in text.lines() {
        let fields: Vec<&str> = line.split_whitespace().collect();
        let Some(separator) = fields.iter().position(|value| *value == "-") else {
            continue;
        };
        if fields.get(separator + 1) != Some(&"cgroup2") || fields.len() <= 5 {
            continue;
        }
        let mount = fields[4].replace("\\040", " ").replace("\\011", "\t");
        let mount = Path::new(&mount);
        if let Ok(relative) = path.strip_prefix(mount) {
            let value = relative.to_string_lossy();
            if !value.is_empty() && !value.contains("..") {
                return Ok(value.into_owned());
            }
        }
    }
    Err(Error::Config("cgroup mount path cannot be made relative"))
}

#[cfg(not(target_os = "linux"))]
fn relative_cgroup_path(_path: &Path) -> Result<String> {
    Err(Error::Config("cgroup v2 requires Linux"))
}

pub(crate) fn validate_component(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 120
        || name == "."
        || name == ".."
        || name.contains(['/', '\\', '\0'])
    {
        return Err(Error::Path);
    }
    Ok(())
}
