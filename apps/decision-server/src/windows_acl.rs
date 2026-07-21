use std::{
    ffi::c_void,
    fs::File,
    mem::{offset_of, size_of},
    os::windows::io::AsRawHandle,
    ptr::{null_mut, read, read_unaligned},
};

use windows::Win32::{
    Foundation::{CloseHandle, ERROR_SUCCESS, HANDLE, HLOCAL, LocalFree},
    Security::{
        ACCESS_ALLOWED_ACE, ACE_HEADER, ACL, ACL_SIZE_INFORMATION, AclSizeInformation,
        CONTAINER_INHERIT_ACE, CopySid, CreateWellKnownSid, DACL_SECURITY_INFORMATION, EqualSid,
        GENERIC_MAPPING, GetAce, GetAclInformation, GetLengthSid, GetTokenInformation,
        INHERIT_ONLY_ACE, INHERITED_ACE, IsValidAcl, IsValidSecurityDescriptor, IsValidSid,
        MapGenericMask, NO_PROPAGATE_INHERIT_ACE, OBJECT_INHERIT_ACE, OWNER_SECURITY_INFORMATION,
        PSECURITY_DESCRIPTOR, PSID, SECURITY_MAX_SID_SIZE, TOKEN_QUERY, TOKEN_USER, TokenUser,
        WELL_KNOWN_SID_TYPE, WinBuiltinAdministratorsSid, WinLocalSystemSid,
    },
    Storage::FileSystem::{
        DELETE, FILE_ALL_ACCESS, FILE_APPEND_DATA, FILE_DELETE_CHILD, FILE_GENERIC_EXECUTE,
        FILE_GENERIC_READ, FILE_GENERIC_WRITE, FILE_WRITE_ATTRIBUTES, FILE_WRITE_DATA,
        FILE_WRITE_EA, WRITE_DAC, WRITE_OWNER,
    },
    System::{
        SystemServices::{ACCESS_ALLOWED_ACE_TYPE, ACCESS_DENIED_ACE_TYPE},
        Threading::{GetCurrentProcess, OpenProcessToken},
    },
};

use crate::secure_file::SecureFilePolicy;

const SID_REVISION: u8 = 1;
const SID_MAX_SUB_AUTHORITIES: u8 = 15;
const MAX_TOKEN_USER_BYTES: u32 = 64 * 1024;
const TRUSTED_INSTALLER_SID: windows::core::PCWSTR =
    windows::core::w!("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464");

#[derive(Clone, Copy)]
pub(crate) enum WindowsAclPolicy {
    FilesystemRoot,
    Directory,
    PublicFile,
    SecretFile,
}

impl From<SecureFilePolicy> for WindowsAclPolicy {
    fn from(value: SecureFilePolicy) -> Self {
        match value {
            SecureFilePolicy::Public => Self::PublicFile,
            SecureFilePolicy::Secret => Self::SecretFile,
        }
    }
}

pub(crate) fn validate_handle(file: &File, policy: WindowsAclPolicy) -> Result<(), ()> {
    let mut owner = PSID::default();
    let mut dacl = null_mut();
    let mut descriptor = PSECURITY_DESCRIPTOR::default();
    let status = unsafe {
        windows::Win32::Security::Authorization::GetSecurityInfo(
            HANDLE(file.as_raw_handle()),
            windows::Win32::Security::Authorization::SE_FILE_OBJECT,
            OWNER_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION,
            Some(&mut owner),
            None,
            Some(&mut dacl),
            None,
            Some(&mut descriptor),
        )
    };
    let _descriptor = LocalAllocation::new(descriptor.0);
    if status != ERROR_SUCCESS
        || descriptor.is_invalid()
        || !unsafe { IsValidSecurityDescriptor(descriptor) }.as_bool()
    {
        return Err(());
    }

    let trusted = TrustedSids::load()?;
    unsafe { validate_descriptor(owner, dacl, policy, &trusted) }
}

unsafe fn validate_descriptor(
    owner: PSID,
    dacl: *mut ACL,
    policy: WindowsAclPolicy,
    trusted: &TrustedSids,
) -> Result<(), ()> {
    if !sid_is_valid(owner) || !trusted.owner_is_trusted(owner, policy) || dacl.is_null() {
        return Err(());
    }
    if !unsafe { IsValidAcl(dacl) }.as_bool() {
        return Err(());
    }

    let mut information = ACL_SIZE_INFORMATION::default();
    unsafe {
        GetAclInformation(
            dacl,
            (&raw mut information).cast(),
            u32::try_from(size_of::<ACL_SIZE_INFORMATION>()).map_err(|_| ())?,
            AclSizeInformation,
        )
    }
    .map_err(|_| ())?;
    let header = unsafe { read_unaligned(dacl) };
    validate_acl_bounds(header, information)?;

    for index in 0..information.AceCount {
        let mut ace = null_mut();
        unsafe { GetAce(dacl, index, &mut ace) }.map_err(|_| ())?;
        unsafe { validate_ace(dacl, information, ace, policy, trusted)? };
    }
    Ok(())
}

fn validate_acl_bounds(header: ACL, information: ACL_SIZE_INFORMATION) -> Result<(), ()> {
    let header_bytes = u32::try_from(size_of::<ACL>()).map_err(|_| ())?;
    let acl_size = u32::from(header.AclSize);
    let reported_size = information
        .AclBytesInUse
        .checked_add(information.AclBytesFree)
        .ok_or(())?;
    let available_for_aces = information
        .AclBytesInUse
        .checked_sub(header_bytes)
        .ok_or(())?;
    let maximum_ace_count = available_for_aces / 16;
    if acl_size < header_bytes
        || acl_size != reported_size
        || information.AclBytesInUse > acl_size
        || u32::from(header.AceCount) != information.AceCount
        || information.AceCount > maximum_ace_count
    {
        return Err(());
    }
    Ok(())
}

unsafe fn validate_ace(
    dacl: *mut ACL,
    information: ACL_SIZE_INFORMATION,
    ace: *mut c_void,
    policy: WindowsAclPolicy,
    trusted: &TrustedSids,
) -> Result<(), ()> {
    let base = dacl.addr();
    let ace_region = base.checked_add(size_of::<ACL>()).ok_or(())?;
    let end = base
        .checked_add(usize::try_from(information.AclBytesInUse).map_err(|_| ())?)
        .ok_or(())?;
    let ace_address = ace.addr();
    let header_end = ace_address.checked_add(size_of::<ACE_HEADER>()).ok_or(())?;
    if ace.is_null() || ace_address < ace_region || header_end > end {
        return Err(());
    }

    let header = unsafe { read_unaligned(ace.cast::<ACE_HEADER>()) };
    let ace_size = usize::from(header.AceSize);
    let ace_end = ace_address.checked_add(ace_size).ok_or(())?;
    if ace_size < 16 || ace_size % 4 != 0 || ace_end > end {
        return Err(());
    }
    if !matches!(
        u32::from(header.AceType),
        ACCESS_ALLOWED_ACE_TYPE | ACCESS_DENIED_ACE_TYPE
    ) {
        return Err(());
    }
    let allowed_flags = OBJECT_INHERIT_ACE.0
        | CONTAINER_INHERIT_ACE.0
        | NO_PROPAGATE_INHERIT_ACE.0
        | INHERIT_ONLY_ACE.0
        | INHERITED_ACE.0;
    if u32::from(header.AceFlags) & !allowed_flags != 0 {
        return Err(());
    }

    let sid_offset = offset_of!(ACCESS_ALLOWED_ACE, SidStart);
    let sid_available = ace_size.checked_sub(sid_offset).ok_or(())?;
    if sid_available < 8 {
        return Err(());
    }
    let ace_bytes = ace.cast::<u8>();
    let sid_pointer = unsafe { ace_bytes.add(sid_offset) };
    let revision = unsafe { read(sid_pointer) };
    let sub_authority_count = unsafe { read(sid_pointer.add(1)) };
    if revision != SID_REVISION || sub_authority_count > SID_MAX_SUB_AUTHORITIES {
        return Err(());
    }
    let sid_length = 8usize
        .checked_add(usize::from(sub_authority_count).checked_mul(4).ok_or(())?)
        .ok_or(())?;
    if sid_length != sid_available {
        return Err(());
    }
    let sid = PSID(sid_pointer.cast());
    if !sid_is_valid(sid)
        || usize::try_from(unsafe { GetLengthSid(sid) }).map_err(|_| ())? != sid_length
    {
        return Err(());
    }

    let mask_pointer = unsafe { ace_bytes.add(size_of::<ACE_HEADER>()) }.cast::<u32>();
    let mut mask = unsafe { read_unaligned(mask_pointer) };
    let mapping = GENERIC_MAPPING {
        GenericRead: FILE_GENERIC_READ.0,
        GenericWrite: FILE_GENERIC_WRITE.0,
        GenericExecute: FILE_GENERIC_EXECUTE.0,
        GenericAll: FILE_ALL_ACCESS.0,
    };
    unsafe { MapGenericMask(&mut mask, &mapping) };
    if mask & !FILE_ALL_ACCESS.0 != 0 {
        return Err(());
    }
    if u32::from(header.AceFlags) & INHERIT_ONLY_ACE.0 != 0
        || u32::from(header.AceType) == ACCESS_DENIED_ACE_TYPE
        || trusted.contains(sid, policy)
    {
        return Ok(());
    }
    if mask & policy.forbidden_rights() != 0 {
        return Err(());
    }
    Ok(())
}

impl WindowsAclPolicy {
    fn forbidden_rights(self) -> u32 {
        let specific_mutating = FILE_WRITE_DATA.0
            | FILE_APPEND_DATA.0
            | FILE_WRITE_EA.0
            | FILE_DELETE_CHILD.0
            | FILE_WRITE_ATTRIBUTES.0;
        let standard_mutating = DELETE.0 | WRITE_DAC.0 | WRITE_OWNER.0;
        let mutating = specific_mutating | standard_mutating;
        match self {
            Self::FilesystemRoot => mutating & !FILE_APPEND_DATA.0,
            Self::Directory | Self::PublicFile => mutating,
            Self::SecretFile => 0x1ff | standard_mutating,
        }
    }

    fn allows_trusted_installer_owner(self) -> bool {
        matches!(self, Self::FilesystemRoot)
    }
}

struct TrustedSids {
    process: OwnedSid,
    system: OwnedSid,
    administrators: OwnedSid,
    trusted_installer: OwnedSid,
}

impl TrustedSids {
    fn load() -> Result<Self, ()> {
        Ok(Self {
            process: OwnedSid::current_process()?,
            system: OwnedSid::well_known(WinLocalSystemSid)?,
            administrators: OwnedSid::well_known(WinBuiltinAdministratorsSid)?,
            trusted_installer: OwnedSid::from_string(TRUSTED_INSTALLER_SID)?,
        })
    }

    fn contains(&self, sid: PSID, policy: WindowsAclPolicy) -> bool {
        sids_equal(sid, self.process.as_psid())
            || sids_equal(sid, self.system.as_psid())
            || sids_equal(sid, self.administrators.as_psid())
            || (policy.allows_trusted_installer_owner()
                && sids_equal(sid, self.trusted_installer.as_psid()))
    }

    fn owner_is_trusted(&self, owner: PSID, policy: WindowsAclPolicy) -> bool {
        sids_equal(owner, self.process.as_psid())
            || sids_equal(owner, self.system.as_psid())
            || sids_equal(owner, self.administrators.as_psid())
            || (policy.allows_trusted_installer_owner()
                && sids_equal(owner, self.trusted_installer.as_psid()))
    }
}

struct OwnedSid {
    storage: Vec<usize>,
}

impl OwnedSid {
    fn current_process() -> Result<Self, ()> {
        let mut token = HANDLE::default();
        unsafe { OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &mut token) }
            .map_err(|_| ())?;
        let token = OwnedHandle(token);
        let mut required = 0;
        let probe = unsafe { GetTokenInformation(token.0, TokenUser, None, 0, &mut required) };
        if probe.is_ok()
            || required < u32::try_from(size_of::<TOKEN_USER>()).map_err(|_| ())?
            || required > MAX_TOKEN_USER_BYTES
        {
            return Err(());
        }
        let mut buffer = aligned_storage(required)?;
        unsafe {
            GetTokenInformation(
                token.0,
                TokenUser,
                Some(buffer.as_mut_ptr().cast()),
                required,
                &mut required,
            )
        }
        .map_err(|_| ())?;
        let user = unsafe { read_unaligned(buffer.as_ptr().cast::<TOKEN_USER>()) };
        unsafe { Self::copy_from(user.User.Sid) }
    }

    fn well_known(kind: WELL_KNOWN_SID_TYPE) -> Result<Self, ()> {
        let mut size = SECURITY_MAX_SID_SIZE;
        let mut storage = aligned_storage(size)?;
        let sid = PSID(storage.as_mut_ptr().cast());
        unsafe { CreateWellKnownSid(kind, None, Some(sid), &mut size) }.map_err(|_| ())?;
        if size > SECURITY_MAX_SID_SIZE || !sid_is_valid(sid) {
            return Err(());
        }
        Ok(Self { storage })
    }

    fn from_string(value: windows::core::PCWSTR) -> Result<Self, ()> {
        let mut source = PSID::default();
        unsafe {
            windows::Win32::Security::Authorization::ConvertStringSidToSidW(value, &mut source)
        }
        .map_err(|_| ())?;
        let _source = LocalAllocation::new(source.0);
        unsafe { Self::copy_from(source) }
    }

    unsafe fn copy_from(source: PSID) -> Result<Self, ()> {
        if !sid_is_valid(source) {
            return Err(());
        }
        let length = unsafe { GetLengthSid(source) };
        if !(8..=SECURITY_MAX_SID_SIZE).contains(&length) {
            return Err(());
        }
        let mut storage = aligned_storage(length)?;
        let destination = PSID(storage.as_mut_ptr().cast());
        unsafe { CopySid(length, destination, source) }.map_err(|_| ())?;
        if !sid_is_valid(destination) {
            return Err(());
        }
        Ok(Self { storage })
    }

    fn as_psid(&self) -> PSID {
        PSID(self.storage.as_ptr().cast_mut().cast())
    }
}

fn aligned_storage(bytes: u32) -> Result<Vec<usize>, ()> {
    let bytes = usize::try_from(bytes).map_err(|_| ())?;
    let words = bytes.checked_add(size_of::<usize>() - 1).ok_or(())? / size_of::<usize>();
    if words == 0 {
        return Err(());
    }
    Ok(vec![0; words])
}

fn sid_is_valid(sid: PSID) -> bool {
    !sid.is_invalid() && unsafe { IsValidSid(sid) }.as_bool()
}

fn sids_equal(left: PSID, right: PSID) -> bool {
    sid_is_valid(left) && sid_is_valid(right) && unsafe { EqualSid(left, right) }.is_ok()
}

struct OwnedHandle(HANDLE);

impl Drop for OwnedHandle {
    fn drop(&mut self) {
        if !self.0.is_invalid() {
            let _ = unsafe { CloseHandle(self.0) };
        }
    }
}

struct LocalAllocation(*mut c_void);

impl LocalAllocation {
    fn new(pointer: *mut c_void) -> Self {
        Self(pointer)
    }
}

impl Drop for LocalAllocation {
    fn drop(&mut self) {
        let allocation = HLOCAL(self.0);
        if !allocation.is_invalid() {
            unsafe {
                LocalFree(Some(allocation));
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use std::{ffi::OsString, path::PathBuf, ptr::null_mut};

    use cap_std::{ambient_authority, fs::Dir};

    use windows::Win32::Security::{
        ACE_HEADER, ACL, GetAce, GetSecurityDescriptorDacl, PSECURITY_DESCRIPTOR, PSID, WinWorldSid,
    };

    use super::{
        LocalAllocation, OwnedSid, TrustedSids, WindowsAclPolicy, validate_acl_bounds,
        validate_descriptor, validate_handle,
    };

    struct TestDescriptor {
        _allocation: LocalAllocation,
        dacl: *mut ACL,
    }

    impl TestDescriptor {
        fn from_sddl(sddl: &str) -> Self {
            let wide: Vec<u16> = sddl.encode_utf16().chain([0]).collect();
            let mut descriptor = PSECURITY_DESCRIPTOR::default();
            unsafe {
                windows::Win32::Security::Authorization::ConvertStringSecurityDescriptorToSecurityDescriptorW(
                    windows::core::PCWSTR(wide.as_ptr()),
                    1,
                    &mut descriptor,
                    None,
                )
            }
            .expect("valid test SDDL");
            let allocation = LocalAllocation::new(descriptor.0);
            let mut present = windows::core::BOOL::default();
            let mut defaulted = windows::core::BOOL::default();
            let mut dacl = null_mut();
            unsafe {
                GetSecurityDescriptorDacl(descriptor, &mut present, &mut dacl, &mut defaulted)
            }
            .expect("test DACL");
            assert!(present.as_bool());
            Self {
                _allocation: allocation,
                dacl,
            }
        }

        fn first_ace(&self) -> *mut std::ffi::c_void {
            let mut ace = null_mut();
            unsafe { GetAce(self.dacl, 0, &mut ace) }.expect("first test ACE");
            ace
        }
    }

    fn validates(sddl: &str, policy: WindowsAclPolicy, owner: PSID) -> bool {
        let descriptor = TestDescriptor::from_sddl(sddl);
        let trusted = TrustedSids::load().expect("trusted SIDs");
        unsafe { validate_descriptor(owner, descriptor.dacl, policy, &trusted) }.is_ok()
    }

    #[test]
    fn rejects_a_null_dacl() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    null_mut(),
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn rejects_everyone_full_control() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let owner = trusted.process.as_psid();
        assert!(!validates(
            "D:(A;;FA;;;WD)",
            WindowsAclPolicy::PublicFile,
            owner,
        ));
    }

    #[test]
    fn allows_users_read_on_a_public_file() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(validates(
            "D:(A;;FR;;;BU)",
            WindowsAclPolicy::PublicFile,
            trusted.process.as_psid(),
        ));
    }

    #[test]
    fn rejects_users_read_on_a_secret_file() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(!validates(
            "D:(A;;FR;;;BU)",
            WindowsAclPolicy::SecretFile,
            trusted.process.as_psid(),
        ));
    }

    #[test]
    fn rejects_all_specific_rights_on_a_secret_file() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(!validates(
            "D:(A;;FX;;;BU)",
            WindowsAclPolicy::SecretFile,
            trusted.process.as_psid(),
        ));
    }

    #[test]
    fn rejects_users_write_on_a_public_file() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(!validates(
            "D:(A;;FW;;;BU)",
            WindowsAclPolicy::PublicFile,
            trusted.process.as_psid(),
        ));
    }

    #[test]
    fn maps_generic_rights_before_enforcement() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let owner = trusted.process.as_psid();
        assert!(!validates(
            "D:(A;;GW;;;BU)",
            WindowsAclPolicy::PublicFile,
            owner,
        ));
        assert!(!validates(
            "D:(A;;GR;;;BU)",
            WindowsAclPolicy::SecretFile,
            owner,
        ));
    }

    #[test]
    fn ignores_inherit_only_simple_aces() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        assert!(validates(
            "D:(A;IO;FA;;;BU)",
            WindowsAclPolicy::SecretFile,
            trusted.process.as_psid(),
        ));
    }

    #[test]
    fn rejects_non_simple_aces_without_panicking() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let descriptor = TestDescriptor::from_sddl("D:(A;;FR;;;BU)");
        let ace = descriptor.first_ace();
        unsafe {
            (*ace.cast::<ACE_HEADER>()).AceType = u8::MAX;
        }
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    descriptor.dacl,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn rejects_an_invalid_ace_sid_without_panicking() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let descriptor = TestDescriptor::from_sddl("D:(A;;FR;;;BU)");
        let ace = descriptor.first_ace();
        let sid_offset =
            std::mem::offset_of!(windows::Win32::Security::ACCESS_ALLOWED_ACE, SidStart);
        unsafe {
            *ace.cast::<u8>().add(sid_offset) = 0;
        }
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    descriptor.dacl,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn validates_inherit_only_and_deny_ace_payloads() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let inherit_only = TestDescriptor::from_sddl("D:(A;IO;FR;;;BU)");
        let inherit_only_ace = inherit_only.first_ace();
        let sid_offset =
            std::mem::offset_of!(windows::Win32::Security::ACCESS_ALLOWED_ACE, SidStart);
        unsafe {
            *inherit_only_ace.cast::<u8>().add(sid_offset) = 0;
        }
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    inherit_only.dacl,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );

        let denied = TestDescriptor::from_sddl("D:(D;;FR;;;BU)");
        let denied_ace = denied.first_ace();
        unsafe {
            *denied_ace
                .cast::<u8>()
                .add(std::mem::size_of::<ACE_HEADER>()) = 0;
            *denied_ace
                .cast::<u8>()
                .add(std::mem::size_of::<ACE_HEADER>() + 3) = 2;
        }
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    denied.dacl,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn rejects_unsupported_ace_flags_even_when_inherit_only() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let descriptor = TestDescriptor::from_sddl("D:(A;IO;FR;;;BU)");
        let ace = descriptor.first_ace();
        unsafe {
            (*ace.cast::<ACE_HEADER>()).AceFlags |= 0x40;
        }
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    descriptor.dacl,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn rejects_misaligned_or_non_exact_simple_ace_sizes() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        for size_change in [1i16, -4i16] {
            let descriptor = TestDescriptor::from_sddl("D:(A;;FR;;;BU)");
            let ace = descriptor.first_ace();
            unsafe {
                let header = &mut *ace.cast::<ACE_HEADER>();
                header.AceSize = u16::try_from(i32::from(header.AceSize) + i32::from(size_change))
                    .expect("bounded test ACE size");
            }
            assert!(
                unsafe {
                    validate_descriptor(
                        trusted.process.as_psid(),
                        descriptor.dacl,
                        WindowsAclPolicy::PublicFile,
                        &trusted,
                    )
                }
                .is_err()
            );
        }
    }

    #[test]
    fn rejects_inconsistent_acl_header_information() {
        let header = ACL {
            AclSize: 8,
            AceCount: 1,
            ..ACL::default()
        };
        let information = windows::Win32::Security::ACL_SIZE_INFORMATION {
            AceCount: 1,
            AclBytesInUse: 8,
            AclBytesFree: 0,
        };
        assert!(validate_acl_bounds(header, information).is_err());

        let header = ACL {
            AclSize: 32,
            AceCount: 1,
            ..ACL::default()
        };
        let information = windows::Win32::Security::ACL_SIZE_INFORMATION {
            AceCount: 2,
            AclBytesInUse: 24,
            AclBytesFree: 8,
        };
        assert!(validate_acl_bounds(header, information).is_err());
    }

    #[test]
    fn accepts_only_approved_owners() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        for owner in [
            trusted.process.as_psid(),
            trusted.system.as_psid(),
            trusted.administrators.as_psid(),
        ] {
            assert!(validates(
                "D:(A;;FR;;;BU)",
                WindowsAclPolicy::PublicFile,
                owner,
            ));
        }
        let world = OwnedSid::well_known(WinWorldSid).expect("Everyone SID");
        assert!(!validates(
            "D:(A;;FR;;;BU)",
            WindowsAclPolicy::PublicFile,
            world.as_psid(),
        ));
        assert!(!validates(
            "D:(A;;FR;;;BU)",
            WindowsAclPolicy::PublicFile,
            trusted.trusted_installer.as_psid(),
        ));
        assert!(validates(
            "D:(A;;FR;;;BU)",
            WindowsAclPolicy::FilesystemRoot,
            trusted.trusted_installer.as_psid(),
        ));
    }

    #[test]
    fn directory_mutation_is_rejected_except_root_add_subdirectory() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let owner = trusted.process.as_psid();
        assert!(!validates(
            "D:(A;;0x4;;;AU)",
            WindowsAclPolicy::Directory,
            owner,
        ));
        assert!(validates(
            "D:(A;;0x4;;;AU)",
            WindowsAclPolicy::FilesystemRoot,
            owner,
        ));
        assert!(!validates(
            "D:(A;;DC;;;AU)",
            WindowsAclPolicy::FilesystemRoot,
            owner,
        ));
    }

    #[test]
    fn rejects_invalid_acl_without_panicking() {
        let trusted = TrustedSids::load().expect("trusted SIDs");
        let mut invalid = ACL::default();
        assert!(
            unsafe {
                validate_descriptor(
                    trusted.process.as_psid(),
                    &mut invalid,
                    WindowsAclPolicy::PublicFile,
                    &trusted,
                )
            }
            .is_err()
        );
    }

    #[test]
    fn validates_the_open_standard_windows_root_handle() {
        let drive = std::env::var_os("SystemDrive").unwrap_or_else(|| OsString::from("C:"));
        let root = PathBuf::from(format!("{}\\", drive.to_string_lossy()));
        let file = Dir::open_ambient_dir(&root, ambient_authority())
            .expect("Windows system drive root")
            .into_std_file();
        validate_handle(&file, WindowsAclPolicy::FilesystemRoot)
            .expect("standard Windows root ACL");
    }
}
