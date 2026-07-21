use std::{
    ffi::OsString,
    fs::{File, Metadata},
    io::Read,
    path::{Component, Path, PathBuf},
};

use cap_fs_ext::{DirExt, FollowSymlinks, OpenOptionsFollowExt, OpenOptionsSyncExt};
use cap_std::{ambient_authority, fs::Dir, fs::OpenOptions};
use same_file::Handle;
use zeroize::Zeroizing;

#[derive(Clone, Copy)]
pub(crate) enum SecureFilePolicy {
    Public,
    Secret,
}

pub(crate) struct SecureFile {
    contents: Zeroizing<Vec<u8>>,
    identity: Handle,
}

impl SecureFile {
    pub(crate) fn contents(&self) -> &[u8] {
        &self.contents
    }

    pub(crate) fn into_parts(self) -> (Zeroizing<Vec<u8>>, Handle) {
        (self.contents, self.identity)
    }
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct SecureFileError;

pub(crate) async fn read_secure_file(
    path: &Path,
    maximum: usize,
    policy: SecureFilePolicy,
) -> Result<SecureFile, SecureFileError> {
    let path = path.to_owned();
    tokio::task::spawn_blocking(move || read_secure_file_blocking(&path, maximum, policy))
        .await
        .map_err(|_| SecureFileError)?
}

fn read_secure_file_blocking(
    path: &Path,
    maximum: usize,
    policy: SecureFilePolicy,
) -> Result<SecureFile, SecureFileError> {
    validate_local_path(path)?;
    let file = open_without_following(path)?;
    let metadata = file.metadata().map_err(|_| SecureFileError)?;
    validate_metadata(&metadata, maximum, policy)?;
    #[cfg(windows)]
    crate::windows_acl::validate_handle(&file, policy.into()).map_err(|_| SecureFileError)?;

    let mut identity = Handle::from_file(file).map_err(|_| SecureFileError)?;
    let mut contents = Zeroizing::new(Vec::with_capacity(
        usize::try_from(metadata.len())
            .unwrap_or(maximum)
            .saturating_add(1),
    ));
    identity
        .as_file_mut()
        .take(maximum as u64 + 1)
        .read_to_end(&mut contents)
        .map_err(|_| SecureFileError)?;
    if contents.is_empty() || contents.len() > maximum {
        return Err(SecureFileError);
    }

    Ok(SecureFile { contents, identity })
}

fn validate_local_path(path: &Path) -> Result<(), SecureFileError> {
    validate_absolute_path(path)?;

    #[cfg(windows)]
    validate_windows_path(path, false)?;

    Ok(())
}

fn validate_canonical_root(path: &Path) -> Result<(), SecureFileError> {
    validate_absolute_path(path)?;

    #[cfg(windows)]
    validate_windows_path(path, true)?;

    Ok(())
}

fn validate_absolute_path(path: &Path) -> Result<(), SecureFileError> {
    if !path.is_absolute()
        || path
            .components()
            .any(|component| matches!(component, Component::CurDir | Component::ParentDir))
    {
        return Err(SecureFileError);
    }

    Ok(())
}

#[cfg(windows)]
fn validate_windows_path(path: &Path, allow_verbatim_disk: bool) -> Result<(), SecureFileError> {
    use std::path::Prefix;

    let mut components = path.components();
    let Some(Component::Prefix(prefix)) = components.next() else {
        return Err(SecureFileError);
    };
    if !(matches!(prefix.kind(), Prefix::Disk(_))
        || allow_verbatim_disk && matches!(prefix.kind(), Prefix::VerbatimDisk(_)))
    {
        return Err(SecureFileError);
    }
    for component in components {
        let Component::Normal(value) = component else {
            continue;
        };
        let value = value.to_string_lossy();
        if value.contains(':') || value.ends_with([' ', '.']) {
            return Err(SecureFileError);
        }
    }
    Ok(())
}

#[cfg(windows)]
fn is_reparse_point(metadata: &Metadata) -> bool {
    use std::os::windows::fs::MetadataExt;

    const FILE_ATTRIBUTE_REPARSE_POINT: u32 = 0x0000_0400;
    metadata.file_attributes() & FILE_ATTRIBUTE_REPARSE_POINT != 0
}

#[cfg(not(windows))]
fn is_reparse_point(_metadata: &Metadata) -> bool {
    false
}

fn open_without_following(path: &Path) -> Result<File, SecureFileError> {
    let (root, components) = split_absolute_path(path)?;
    let root = std::fs::canonicalize(root).map_err(|_| SecureFileError)?;
    validate_canonical_root(&root)?;
    let mut directory =
        Dir::open_ambient_dir(root, ambient_authority()).map_err(|_| SecureFileError)?;
    validate_directory_handle(&directory, true)?;
    let Some((file_name, parent_components)) = components.split_last() else {
        return Err(SecureFileError);
    };
    for component in parent_components {
        directory = directory
            .open_dir_nofollow(component)
            .map_err(|_| SecureFileError)?;
        validate_directory_handle(&directory, false)?;
    }

    let mut options = OpenOptions::new();
    options.read(true);
    options.follow(FollowSymlinks::No).nonblock(true);
    configure_windows_sharing(&mut options);
    directory
        .open_with(file_name, &options)
        .map(cap_std::fs::File::into_std)
        .map_err(|_| SecureFileError)
}

fn split_absolute_path(path: &Path) -> Result<(PathBuf, Vec<OsString>), SecureFileError> {
    let mut root = PathBuf::new();
    let mut components = Vec::new();
    for component in path.components() {
        match component {
            Component::Prefix(prefix) => root.push(prefix.as_os_str()),
            Component::RootDir => root.push(std::path::MAIN_SEPARATOR_STR),
            Component::Normal(value) => components.push(value.to_owned()),
            Component::CurDir | Component::ParentDir => return Err(SecureFileError),
        }
    }
    if root.as_os_str().is_empty() || components.is_empty() {
        return Err(SecureFileError);
    }
    Ok((root, components))
}

fn validate_directory_handle(
    directory: &Dir,
    is_filesystem_root: bool,
) -> Result<(), SecureFileError> {
    let file = directory
        .try_clone()
        .map_err(|_| SecureFileError)?
        .into_std_file();
    let metadata = file.metadata().map_err(|_| SecureFileError)?;
    if !metadata.is_dir() || is_reparse_point(&metadata) {
        return Err(SecureFileError);
    }
    #[cfg(windows)]
    crate::windows_acl::validate_handle(
        &file,
        if is_filesystem_root {
            crate::windows_acl::WindowsAclPolicy::FilesystemRoot
        } else {
            crate::windows_acl::WindowsAclPolicy::Directory
        },
    )
    .map_err(|_| SecureFileError)?;
    #[cfg(not(windows))]
    let _ = is_filesystem_root;
    Ok(())
}

#[cfg(windows)]
fn configure_windows_sharing(options: &mut OpenOptions) {
    use cap_std::fs::OpenOptionsExt;

    const FILE_SHARE_READ: u32 = 0x0000_0001;
    options.share_mode(FILE_SHARE_READ);
}

#[cfg(not(windows))]
fn configure_windows_sharing(_options: &mut OpenOptions) {}

fn validate_metadata(
    metadata: &Metadata,
    maximum: usize,
    policy: SecureFilePolicy,
) -> Result<(), SecureFileError> {
    if !metadata.is_file()
        || is_reparse_point(metadata)
        || metadata.len() == 0
        || metadata.len() > maximum as u64
    {
        return Err(SecureFileError);
    }

    #[cfg(unix)]
    validate_unix_permissions(metadata, policy)?;
    #[cfg(not(unix))]
    let _ = policy;

    Ok(())
}

#[cfg(unix)]
fn validate_unix_permissions(
    metadata: &Metadata,
    policy: SecureFilePolicy,
) -> Result<(), SecureFileError> {
    use std::os::unix::fs::MetadataExt;

    let mode = metadata.mode();
    let owner_is_trusted =
        metadata.uid() == 0 || metadata.uid() == rustix::process::geteuid().as_raw();
    if !owner_is_trusted || metadata.nlink() != 1 {
        return Err(SecureFileError);
    }
    match policy {
        SecureFilePolicy::Public if mode & 0o022 != 0 => Err(SecureFileError),
        SecureFilePolicy::Secret if mode & 0o177 != 0 => Err(SecureFileError),
        SecureFilePolicy::Public | SecureFilePolicy::Secret => Ok(()),
    }
}

#[cfg(all(test, windows))]
mod windows_path_tests {
    use std::path::Path;

    use super::{validate_canonical_root, validate_local_path};

    #[test]
    fn user_paths_reject_verbatim_disk_prefixes() {
        assert!(validate_local_path(Path::new(r"\\?\C:\secure\control.json")).is_err());
    }

    #[test]
    fn canonical_roots_accept_disk_and_verbatim_disk_prefixes() {
        assert!(validate_canonical_root(Path::new(r"C:\")).is_ok());
        assert!(validate_canonical_root(Path::new(r"\\?\C:\")).is_ok());
        assert!(validate_canonical_root(Path::new(r"\\server\share\")).is_err());
    }
}
