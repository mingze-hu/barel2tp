//! Safely handles runtime files that a privileged process writes into a normal user's directory.
//!
//! Every Unix operation first opens and anchors the parent directory, then reaches the last path
//! component through `openat`/`renameat`/`unlinkat`. Even if a normal user replaces a directory or
//! file with a symlink during administrator authorization, the privileged process never follows the
//! link to overwrite system files.

use std::{
    fs::{self, File},
    io::{self, Read, Write},
    path::{Component, Path},
};

#[cfg(not(unix))]
use std::fs::OpenOptions;
#[cfg(unix)]
use std::sync::atomic::{AtomicU64, Ordering};

#[cfg(unix)]
use std::{
    ffi::{CString, OsString},
    os::{
        fd::{AsRawFd, FromRawFd},
        unix::{ffi::OsStrExt, fs::MetadataExt, fs::PermissionsExt},
    },
};

#[cfg(unix)]
static TEMPORARY_SEQUENCE: AtomicU64 = AtomicU64::new(0);

#[cfg(unix)]
struct AnchoredPath {
    directory: File,
    name: CString,
}

#[cfg(unix)]
impl AnchoredPath {
    fn new(path: &Path) -> io::Result<Self> {
        let parent = path
            .parent()
            .filter(|parent| !parent.as_os_str().is_empty())
            .unwrap_or(Path::new("."));
        let name = path.file_name().ok_or_else(|| {
            io::Error::new(io::ErrorKind::InvalidInput, "file path has no file name")
        })?;
        let start = if parent.is_absolute() { c"/" } else { c"." };
        // SAFETY: start is a valid NUL-terminated path; the returned descriptor is taken over by
        // File.
        let descriptor = unsafe {
            libc::open(
                start.as_ptr(),
                libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor was just obtained by this function and is exclusively owned.
        let mut directory = unsafe { File::from_raw_fd(descriptor) };

        // Resolve the parent directory one level at a time with openat + O_NOFOLLOW. Using
        // O_NOFOLLOW only on the full parent path would still follow intermediate symlinks and
        // could not stop a user from replacing a higher directory with a link.
        for component in parent.components() {
            let Component::Normal(component) = component else {
                match component {
                    Component::RootDir | Component::CurDir => continue,
                    Component::ParentDir | Component::Prefix(_) => {
                        return Err(io::Error::new(
                            io::ErrorKind::InvalidInput,
                            "runtime file paths must not contain parent directories or platform prefixes",
                        ));
                    }
                    Component::Normal(_) => unreachable!(),
                }
            };
            let raw_component = CString::new(component.as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "directory name contains a NUL byte",
                )
            })?;
            // SAFETY: directory and raw_component are valid; the new descriptor is taken over by
            // File in the next iteration.
            let descriptor = unsafe {
                libc::openat(
                    directory.as_raw_fd(),
                    raw_component.as_ptr(),
                    libc::O_RDONLY | libc::O_DIRECTORY | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                )
            };
            if descriptor < 0 {
                return Err(io::Error::last_os_error());
            }
            // SAFETY: descriptor was just obtained in this iteration and is exclusively owned.
            directory = unsafe { File::from_raw_fd(descriptor) };
        }

        let name = CString::new(name.as_bytes()).map_err(|_| {
            io::Error::new(io::ErrorKind::InvalidInput, "file name contains a NUL byte")
        })?;
        Ok(Self { directory, name })
    }

    fn open(&self, flags: libc::c_int, mode: u32) -> io::Result<File> {
        // SAFETY: the directory descriptor and file name are valid for the call; the new descriptor
        // is taken over by File.
        let descriptor = unsafe {
            libc::openat(
                self.directory.as_raw_fd(),
                self.name.as_ptr(),
                flags | libc::O_CLOEXEC | libc::O_NOFOLLOW,
                mode as libc::c_uint,
            )
        };
        if descriptor < 0 {
            return Err(io::Error::last_os_error());
        }
        // SAFETY: descriptor was just obtained by this function and is exclusively owned.
        let file = unsafe { File::from_raw_fd(descriptor) };
        ensure_regular(&file)?;
        Ok(file)
    }

    fn remove(&self) -> io::Result<()> {
        // SAFETY: the directory descriptor and file name are valid for the call; unlinkat does not
        // follow a final symlink.
        if unsafe { libc::unlinkat(self.directory.as_raw_fd(), self.name.as_ptr(), 0) } != 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(())
    }
}

#[cfg(unix)]
fn ensure_regular(file: &File) -> io::Result<()> {
    if !file.metadata()?.file_type().is_file() {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "runtime path is not a regular file",
        ));
    }
    Ok(())
}

/// Safely opens a regular file for appending and explicitly fixes the permissions of an existing
/// file.
pub fn open_append(path: &Path, mode: u32) -> io::Result<File> {
    #[cfg(unix)]
    {
        let anchored = AnchoredPath::new(path)?;
        let file = anchored.open(libc::O_WRONLY | libc::O_CREAT | libc::O_APPEND, mode)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new().create(true).append(true).open(path)
    }
}

/// Safely opens or creates a readable and writable regular file and explicitly fixes its
/// permissions.
pub fn open_read_write(path: &Path, mode: u32) -> io::Result<File> {
    #[cfg(unix)]
    {
        let anchored = AnchoredPath::new(path)?;
        let file = anchored.open(libc::O_RDWR | libc::O_CREAT, mode)?;
        file.set_permissions(fs::Permissions::from_mode(mode))?;
        Ok(file)
    }
    #[cfg(not(unix))]
    {
        OpenOptions::new()
            .create(true)
            .read(true)
            .write(true)
            .open(path)
    }
}

/// Safely opens an existing regular file; returns `None` when it does not exist.
pub fn open_read_optional(path: &Path) -> io::Result<Option<File>> {
    #[cfg(unix)]
    {
        let anchored = match AnchoredPath::new(path) {
            Ok(anchored) => anchored,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return Ok(None),
            Err(error) => return Err(error),
        };
        match anchored.open(libc::O_RDONLY, 0) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
    #[cfg(not(unix))]
    {
        match File::open(path) {
            Ok(file) => Ok(Some(file)),
            Err(error) if error.kind() == io::ErrorKind::NotFound => Ok(None),
            Err(error) => Err(error),
        }
    }
}

/// Safely reads a UTF-8 text file; returns `None` when it does not exist.
pub fn read_to_string_optional(path: &Path) -> io::Result<Option<String>> {
    let Some(mut file) = open_read_optional(path)? else {
        return Ok(None);
    };
    let mut source = String::new();
    file.read_to_string(&mut source)?;
    Ok(Some(source))
}

/// Exclusively creates a temporary file in the same directory and, once it is on disk, atomically
/// replaces the target.
pub fn atomic_write(path: &Path, contents: &[u8], mode: u32) -> io::Result<()> {
    #[cfg(unix)]
    {
        let anchored = AnchoredPath::new(path)?;
        let target_name = anchored.name.as_bytes();
        let mut last_error = None;
        for _ in 0..32 {
            let sequence = TEMPORARY_SEQUENCE.fetch_add(1, Ordering::Relaxed);
            let mut temporary_name = OsString::from(".");
            temporary_name.push(std::ffi::OsStr::from_bytes(target_name));
            temporary_name.push(format!(".{}.{sequence}.tmp", std::process::id()));
            let temporary = CString::new(temporary_name.as_bytes()).map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "temporary file name contains a NUL byte",
                )
            })?;

            // SAFETY: the directory descriptor and temporary name are valid; O_EXCL guarantees no
            // existing link or file is opened.
            let descriptor = unsafe {
                libc::openat(
                    anchored.directory.as_raw_fd(),
                    temporary.as_ptr(),
                    libc::O_WRONLY
                        | libc::O_CREAT
                        | libc::O_EXCL
                        | libc::O_CLOEXEC
                        | libc::O_NOFOLLOW,
                    mode as libc::c_uint,
                )
            };
            if descriptor < 0 {
                let error = io::Error::last_os_error();
                if error.kind() == io::ErrorKind::AlreadyExists {
                    last_error = Some(error);
                    continue;
                }
                return Err(error);
            }
            // SAFETY: descriptor was just obtained by this function and is exclusively owned.
            let mut file = unsafe { File::from_raw_fd(descriptor) };
            let result = (|| {
                ensure_regular(&file)?;
                file.set_permissions(fs::Permissions::from_mode(mode))?;
                file.write_all(contents)?;
                file.sync_all()?;
                // SAFETY: both names are anchored in the same open directory; renameat replaces the
                // entry atomically.
                if unsafe {
                    libc::renameat(
                        anchored.directory.as_raw_fd(),
                        temporary.as_ptr(),
                        anchored.directory.as_raw_fd(),
                        anchored.name.as_ptr(),
                    )
                } != 0
                {
                    return Err(io::Error::last_os_error());
                }
                anchored.directory.sync_all()
            })();
            if result.is_err() {
                // SAFETY: only removes the temporary entry this function created with O_EXCL.
                unsafe {
                    libc::unlinkat(anchored.directory.as_raw_fd(), temporary.as_ptr(), 0);
                }
            }
            return result;
        }
        Err(last_error.unwrap_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "failed to create a unique temporary file",
            )
        }))
    }
    #[cfg(not(unix))]
    {
        let temporary = path.with_extension("tmp");
        fs::write(&temporary, contents)?;
        fs::rename(temporary, path)
    }
}

/// Removes the last directory entry within the anchored directory without following symlinks.
pub fn remove(path: &Path) -> io::Result<()> {
    #[cfg(unix)]
    {
        AnchoredPath::new(path)?.remove()
    }
    #[cfg(not(unix))]
    {
        fs::remove_file(path)
    }
}

/// Changes the permissions of the last directory entry within the anchored directory without
/// following symlinks. Useful for runtime objects such as Unix sockets that cannot be opened as
/// regular files.
#[cfg(unix)]
pub fn set_permissions_nofollow(path: &Path, mode: u32) -> io::Result<()> {
    let anchored = AnchoredPath::new(path)?;
    // SAFETY: the directory descriptor and name are valid; AT_SYMLINK_NOFOLLOW forbids following a
    // final symlink.
    if unsafe {
        libc::fchmodat(
            anchored.directory.as_raw_fd(),
            anchored.name.as_ptr(),
            mode as libc::mode_t,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Changes the owner of the last directory entry within the anchored directory without following
/// symlinks.
#[cfg(unix)]
pub fn chown_nofollow(path: &Path, uid: u32) -> io::Result<()> {
    let anchored = AnchoredPath::new(path)?;
    // SAFETY: the directory descriptor and name are valid; AT_SYMLINK_NOFOLLOW forbids following a
    // final symlink.
    if unsafe {
        libc::fchownat(
            anchored.directory.as_raw_fd(),
            anchored.name.as_ptr(),
            uid,
            u32::MAX,
            libc::AT_SYMLINK_NOFOLLOW,
        )
    } != 0
    {
        return Err(io::Error::last_os_error());
    }
    Ok(())
}

/// Returns the device and inode of a regular file, used on exit to make sure a PID file replaced
/// later is not deleted by mistake.
#[cfg(unix)]
pub fn identity(file: &File) -> io::Result<(u64, u64)> {
    let metadata = file.metadata()?;
    Ok((metadata.dev(), metadata.ino()))
}

/// Deletes the file only if the path still points at the original file.
#[cfg(unix)]
pub fn remove_if_identity_matches(path: &Path, expected: (u64, u64)) -> io::Result<bool> {
    let Some(file) = open_read_optional(path)? else {
        return Ok(false);
    };
    if identity(&file)? != expected {
        return Ok(false);
    }
    drop(file);
    remove(path).map(|()| true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::temp_path;

    #[test]
    fn atomic_write_replaces_content_safely() {
        let path = temp_path("secure-state");
        atomic_write(&path, b"first", 0o600).unwrap();
        atomic_write(&path, b"second", 0o600).unwrap();
        assert_eq!(
            read_to_string_optional(&path).unwrap().as_deref(),
            Some("second")
        );
        remove(&path).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_to_open_final_symlink_as_regular_file() {
        use std::os::unix::fs::{PermissionsExt, symlink};

        let target = temp_path("secure-target");
        let link = temp_path("secure-link");
        fs::write(&target, b"unchanged").unwrap();
        symlink(&target, &link).unwrap();

        assert!(open_append(&link, 0o600).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");

        set_permissions_nofollow(&target, 0o640).unwrap();
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );
        let _ = set_permissions_nofollow(&link, 0o600);
        assert_eq!(
            fs::metadata(&target).unwrap().permissions().mode() & 0o777,
            0o640
        );

        // Replace the target entry atomically without overwriting whatever a symlink points to.
        atomic_write(&link, b"replacement", 0o600).unwrap();
        assert_eq!(fs::read(&target).unwrap(), b"unchanged");
        assert_eq!(fs::read(&link).unwrap(), b"replacement");
        fs::remove_file(&link).unwrap();
        fs::remove_file(&target).unwrap();
    }

    #[cfg(unix)]
    #[test]
    fn refuses_symlink_in_parent_path() {
        use std::os::unix::fs::symlink;

        let base = temp_path("secure-directory");
        let actual = base.join("actual");
        let link = base.join("link");
        fs::create_dir_all(&actual).unwrap();
        symlink(&actual, &link).unwrap();

        assert!(open_append(&link.join("log"), 0o600).is_err());
        assert!(!actual.join("log").exists());

        fs::remove_file(&link).unwrap();
        fs::remove_dir(&actual).unwrap();
        fs::remove_dir(&base).unwrap();
    }
}
