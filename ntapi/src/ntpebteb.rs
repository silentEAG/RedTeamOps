use crate::ntapi_base::CLIENT_ID;
use crate::ntpsapi::{GDI_HANDLE_BUFFER, PPEB_LDR_DATA};
use crate::ntrtl::PRTL_USER_PROCESS_PARAMETERS;
use core::mem::size_of;
use winapi::shared::basetsd::{SIZE_T, ULONG_PTR};
use winapi::shared::guiddef::GUID;
use winapi::shared::ntdef::{
    BOOLEAN, CHAR, HANDLE, LCID, LIST_ENTRY, LONG, NTSTATUS, PROCESSOR_NUMBER, PSTR, PVOID, UCHAR,
    ULARGE_INTEGER, ULONG, ULONGLONG, UNICODE_STRING, USHORT, WCHAR,
};
use winapi::um::winnt::{
    ACTIVATION_CONTEXT, FLS_MAXIMUM_AVAILABLE, NT_TIB, PRTL_CRITICAL_SECTION, PSLIST_HEADER,
};
STRUCT! {struct RTL_ACTIVATION_CONTEXT_STACK_FRAME {
    Previous: PRTL_ACTIVATION_CONTEXT_STACK_FRAME,
    ActivationContext: *mut ACTIVATION_CONTEXT,
    Flags: ULONG,
}}
pub type PRTL_ACTIVATION_CONTEXT_STACK_FRAME = *mut RTL_ACTIVATION_CONTEXT_STACK_FRAME;
STRUCT! {struct ACTIVATION_CONTEXT_STACK {
    ActiveFrame: *mut RTL_ACTIVATION_CONTEXT_STACK_FRAME,
    FrameListCache: LIST_ENTRY,
    Flags: ULONG,
    NextCookieSequenceNumber: ULONG,
    StackId: ULONG,
}}
pub type PACTIVATION_CONTEXT_STACK = *mut ACTIVATION_CONTEXT_STACK;
STRUCT! {struct API_SET_NAMESPACE {
    Version: ULONG,
    Size: ULONG,
    Flags: ULONG,
    Count: ULONG,
    EntryOffset: ULONG,
    HashOffset: ULONG,
    HashFactor: ULONG,
}}
pub type PAPI_SET_NAMESPACE = *mut API_SET_NAMESPACE;
STRUCT! {struct API_SET_HASH_ENTRY {
    Hash: ULONG,
    Index: ULONG,
}}
pub type PAPI_SET_HASH_ENTRY = *mut API_SET_HASH_ENTRY;
STRUCT! {struct API_SET_NAMESPACE_ENTRY {
    Flags: ULONG,
    NameOffset: ULONG,
    NameLength: ULONG,
    HashedLength: ULONG,
    ValueOffset: ULONG,
    ValueCount: ULONG,
}}
pub type PAPI_SET_NAMESPACE_ENTRY = *mut API_SET_NAMESPACE_ENTRY;
STRUCT! {struct API_SET_VALUE_ENTRY {
    Flags: ULONG,
    NameOffset: ULONG,
    NameLength: ULONG,
    ValueOffset: ULONG,
    ValueLength: ULONG,
}}
pub type PAPI_SET_VALUE_ENTRY = *mut API_SET_VALUE_ENTRY;
UNION! {union PEB_u {
    KernelCallbackTable: PVOID,
    UserSharedInfoPtr: PVOID,
}}
#[repr(C)]
pub struct LEAP_SECOND_DATA([u8; 0]); //fixme
STRUCT! {struct PEB {
    InheritedAddressSpace: BOOLEAN,
    ReadImageFileExecOptions: BOOLEAN,
    BeingDebugged: BOOLEAN,
    BitField: BOOLEAN,
    Mutant: HANDLE,
    ImageBaseAddress: PVOID,
    Ldr: PPEB_LDR_DATA,
    ProcessParameters: PRTL_USER_PROCESS_PARAMETERS,
    SubSystemData: PVOID,
    ProcessHeap: PVOID,
    FastPebLock: PRTL_CRITICAL_SECTION,
    IFEOKey: PVOID,
    AtlThunkSListPtr: PSLIST_HEADER,
    CrossProcessFlags: ULONG,
    u: PEB_u,
    SystemReserved: [ULONG; 1],
    AtlThunkSListPtr32: ULONG,
    ApiSetMap: PAPI_SET_NAMESPACE,
    TlsExpansionCounter: ULONG,
    TlsBitmap: PVOID,
    TlsBitmapBits: [ULONG; 2],
    ReadOnlySharedMemoryBase: PVOID,
    SharedData: PVOID,
    ReadOnlyStaticServerData: *mut PVOID,
    AnsiCodePageData: PVOID,
    OemCodePageData: PVOID,
    UnicodeCaseTableData: PVOID,
    NumberOfProcessors: ULONG,
    NtGlobalFlag: ULONG,
    CriticalSectionTimeout: ULARGE_INTEGER,
    HeapSegmentReserve: SIZE_T,
    HeapSegmentCommit: SIZE_T,
    HeapDeCommitTotalFreeThreshold: SIZE_T,
    HeapDeCommitFreeBlockThreshold: SIZE_T,
    NumberOfHeaps: ULONG,
    MaximumNumberOfHeaps: ULONG,
    ProcessHeaps: *mut PVOID,
    GdiSharedHandleTable: PVOID,
    ProcessStarterHelper: PVOID,
    GdiDCAttributeList: ULONG,
    LoaderLock: PRTL_CRITICAL_SECTION,
    OSMajorVersion: ULONG,
    OSMinorVersion: ULONG,
    OSBuildNumber: USHORT,
    OSCSDVersion: USHORT,
    OSPlatformId: ULONG,
    ImageSubsystem: ULONG,
    ImageSubsystemMajorVersion: ULONG,
    ImageSubsystemMinorVersion: ULONG,
    ActiveProcessAffinityMask: ULONG_PTR,
    GdiHandleBuffer: GDI_HANDLE_BUFFER,
    PostProcessInitRoutine: PVOID,
    TlsExpansionBitmap: PVOID,
    TlsExpansionBitmapBits: [ULONG; 32],
    SessionId: ULONG,
    AppCompatFlags: ULARGE_INTEGER,
    AppCompatFlagsUser: ULARGE_INTEGER,
    pShimData: PVOID,
    AppCompatInfo: PVOID,
    CSDVersion: UNICODE_STRING,
    ActivationContextData: PVOID,
    ProcessAssemblyStorageMap: PVOID,
    SystemDefaultActivationContextData: PVOID,
    SystemAssemblyStorageMap: PVOID,
    MinimumStackCommit: SIZE_T,
    FlsCallback: *mut PVOID,
    FlsListHead: LIST_ENTRY,
    FlsBitmap: PVOID,
    FlsBitmapBits: [ULONG; FLS_MAXIMUM_AVAILABLE as usize / (size_of::<ULONG>() * 8)],
    FlsHighIndex: ULONG,
    WerRegistrationData: PVOID,
    WerShipAssertPtr: PVOID,
    pUnused: PVOID,
    pImageHeaderHash: PVOID,
    TracingFlags: ULONG,
    CsrServerReadOnlySharedMemoryBase: ULONGLONG,
    TppWorkerpListLock: PRTL_CRITICAL_SECTION,
    TppWorkerpList: LIST_ENTRY,
    WaitOnAddressHashTable: [PVOID; 128],
    TelemetryCoverageHeader: PVOID,
    CloudFileFlags: ULONG,
    CloudFileDiagFlags: ULONG,
    PlaceholderCompatibilityMode: CHAR,
    PlaceholderCompatibilityModeReserved: [CHAR; 7],
    LeapSecondData: *mut LEAP_SECOND_DATA,
    LeapSecondFlags: ULONG,
    NtGlobalFlag2: ULONG,
}}
BITFIELD! {PEB BitField: BOOLEAN [
    ImageUsesLargePages set_ImageUsesLargePages[0..1],
    IsProtectedProcess set_IsProtectedProcess[1..2],
    IsImageDynamicallyRelocated set_IsImageDynamicallyRelocated[2..3],
    SkipPatchingUser32Forwarders set_SkipPatchingUser32Forwarders[3..4],
    IsPackagedProcess set_IsPackagedProcess[4..5],
    IsAppContainer set_IsAppContainer[5..6],
    IsProtectedProcessLight set_IsProtectedProcessLight[6..7],
    IsLongPathAwareProcess set_IsLongPathAwareProcess[7..8],
]}
BITFIELD! {PEB CrossProcessFlags: ULONG [
    ProcessInJob set_ProcessInJob[0..1],
    ProcessInitializing set_ProcessInitializing[1..2],
    ProcessUsingVEH set_ProcessUsingVEH[2..3],
    ProcessUsingVCH set_ProcessUsingVCH[3..4],
    ProcessUsingFTH set_ProcessUsingFTH[4..5],
    ProcessPreviouslyThrottled set_ProcessPreviouslyThrottled[5..6],
    ProcessCurrentlyThrottled set_ProcessCurrentlyThrottled[6..7],
    ProcessImagesHotPatched set_ProcessImagesHotPatched[7..8],
    ReservedBits0 set_ReservedBits0[8..32],
]}
BITFIELD! {PEB TracingFlags: ULONG [
    HeapTracingEnabled set_HeapTracingEnabled[0..1],
    CritSecTracingEnabled set_CritSecTracingEnabled[1..2],
    LibLoaderTracingEnabled set_LibLoaderTracingEnabled[2..3],
    SpareTracingBits set_SpareTracingBits[3..32],
]}
BITFIELD! {PEB LeapSecondFlags: ULONG [
    SixtySecondEnabled set_SixtySecondEnabled[0..1],
    Reserved set_Reserved[1..32],
]}
pub type PPEB = *mut PEB;
pub const GDI_BATCH_BUFFER_SIZE: usize = 310;
STRUCT! {struct GDI_TEB_BATCH {
    Offset: ULONG,
    HDC: ULONG_PTR,
    Buffer: [ULONG; GDI_BATCH_BUFFER_SIZE],
}}
pub type PGDI_TEB_BATCH = *mut GDI_TEB_BATCH;
STRUCT! {struct TEB_ACTIVE_FRAME_CONTEXT {
    Flags: ULONG,
    FrameName: PSTR,
}}
pub type PTEB_ACTIVE_FRAME_CONTEXT = *mut TEB_ACTIVE_FRAME_CONTEXT;
STRUCT! {struct TEB_ACTIVE_FRAME {
    Flags: ULONG,
    Previous: *mut TEB_ACTIVE_FRAME,
    Context: PTEB_ACTIVE_FRAME_CONTEXT,
}}
pub type PTEB_ACTIVE_FRAME = *mut TEB_ACTIVE_FRAME;
STRUCT! {struct TEB_u_s {
    ReservedPad0: UCHAR,
    ReservedPad1: UCHAR,
    ReservedPad2: UCHAR,
    IdealProcessor: UCHAR,
}}
UNION! {union TEB_u {
    CurrentIdealProcessor: PROCESSOR_NUMBER,
    IdealProcessorValue: ULONG,
    s: TEB_u_s,
}}
#[cfg(any(target_arch = "x86_64", target_arch = "aarch64"))]
STRUCT! {struct TEB {
    NtTib: NT_TIB,
    EnvironmentPointer: PVOID,
    ClientId: CLIENT_ID,
    ActiveRpcHandle: PVOID,
    ThreadLocalStoragePointer: PVOID,
    ProcessEnvironmentBlock: PPEB,
    LastErrorValue: ULONG,
    CountOfOwnedCriticalSections: ULONG,
    CsrClientThread: PVOID,
    Win32ThreadInfo: PVOID,
    User32Reserved: [ULONG; 26],
    UserReserved: [ULONG; 5],
    WOW32Reserved: PVOID,
    CurrentLocale: LCID,
    FpSoftwareStatusRegister: ULONG,
    ReservedForDebuggerInstrumentation: [PVOID; 16],
    SystemReserved1: [PVOID; 30],
    PlaceholderCompatibilityMode: CHAR,
    PlaceholderReserved: [CHAR; 11],
    ProxiedProcessId: ULONG,
    ActivationStack: ACTIVATION_CONTEXT_STACK,
    WorkingOnBehalfTicket: [UCHAR; 8],
    ExceptionCode: NTSTATUS,
    ActivationContextStackPointer: PACTIVATION_CONTEXT_STACK,
    InstrumentationCallbackSp: ULONG_PTR,
    InstrumentationCallbackPreviousPc: ULONG_PTR,
    InstrumentationCallbackPreviousSp: ULONG_PTR,
    TxFsContext: ULONG,
    InstrumentationCallbackDisabled: BOOLEAN,
    GdiTebBatch: GDI_TEB_BATCH,
    RealClientId: CLIENT_ID,
    GdiCachedProcessHandle: HANDLE,
    GdiClientPID: ULONG,
    GdiClientTID: ULONG,
    GdiThreadLocalInfo: PVOID,
    Win32ClientInfo: [ULONG_PTR; 62],
    glDispatchTable: [PVOID; 233],
    glReserved1: [ULONG_PTR; 29],
    glReserved2: PVOID,
    glSectionInfo: PVOID,
    glSection: PVOID,
    glTable: PVOID,
    glCurrentRC: PVOID,
    glContext: PVOID,
    LastStatusValue: NTSTATUS,
    StaticUnicodeString: UNICODE_STRING,
    StaticUnicodeBuffer: [WCHAR; 261],
    DeallocationStack: PVOID,
    TlsSlots: [PVOID; 64],
    TlsLinks: LIST_ENTRY,
    Vdm: PVOID,
    ReservedForNtRpc: PVOID,
    DbgSsReserved: [PVOID; 2],
    HardErrorMode: ULONG,
    Instrumentation: [PVOID; 11],
    ActivityId: GUID,
    SubProcessTag: PVOID,
    PerflibData: PVOID,
    EtwTraceData: PVOID,
    WinSockData: PVOID,
    GdiBatchCount: ULONG,
    u: TEB_u,
    GuaranteedStackBytes: ULONG,
    ReservedForPerf: PVOID,
    ReservedForOle: PVOID,
    WaitingOnLoaderLock: ULONG,
    SavedPriorityState: PVOID,
    ReservedForCodeCoverage: ULONG_PTR,
    ThreadPoolData: PVOID,
    TlsExpansionSlots: *mut PVOID,
    DeallocationBStore: PVOID,
    BStoreLimit: PVOID,
    MuiGeneration: ULONG,
    IsImpersonating: ULONG,
    NlsCache: PVOID,
    pShimData: PVOID,
    HeapVirtualAffinity: USHORT,
    LowFragHeapDataSlot: USHORT,
    CurrentTransactionHandle: HANDLE,
    ActiveFrame: PTEB_ACTIVE_FRAME,
    FlsData: PVOID,
    PreferredLanguages: PVOID,
    UserPrefLanguages: PVOID,
    MergedPrefLanguages: PVOID,
    MuiImpersonation: ULONG,
    CrossTebFlags: USHORT,
    SameTebFlags: USHORT,
    TxnScopeEnterCallback: PVOID,
    TxnScopeExitCallback: PVOID,
    TxnScopeContext: PVOID,
    LockCount: ULONG,
    WowTebOffset: LONG,
    ResourceRetValue: PVOID,
    ReservedForWdf: PVOID,
    ReservedForCrt: ULONGLONG,
    EffectiveContainerId: GUID,
}}
#[cfg(target_arch = "x86")]
STRUCT! {struct TEB {
    NtTib: NT_TIB,
    EnvironmentPointer: PVOID,
    ClientId: CLIENT_ID,
    ActiveRpcHandle: PVOID,
    ThreadLocalStoragePointer: PVOID,
    ProcessEnvironmentBlock: PPEB,
    LastErrorValue: ULONG,
    CountOfOwnedCriticalSections: ULONG,
    CsrClientThread: PVOID,
    Win32ThreadInfo: PVOID,
    User32Reserved: [ULONG; 26],
    UserReserved: [ULONG; 5],
    WOW32Reserved: PVOID,
    CurrentLocale: LCID,
    FpSoftwareStatusRegister: ULONG,
    ReservedForDebuggerInstrumentation: [PVOID; 16],
    SystemReserved1: [PVOID; 26],
    PlaceholderCompatibilityMode: CHAR,
    PlaceholderReserved: [CHAR; 11],
    ProxiedProcessId: ULONG,
    ActivationStack: ACTIVATION_CONTEXT_STACK,
    WorkingOnBehalfTicket: [UCHAR; 8],
    ExceptionCode: NTSTATUS,
    ActivationContextStackPointer: PACTIVATION_CONTEXT_STACK,
    InstrumentationCallbackSp: ULONG_PTR,
    InstrumentationCallbackPreviousPc: ULONG_PTR,
    InstrumentationCallbackPreviousSp: ULONG_PTR,
    InstrumentationCallbackDisabled: BOOLEAN,
    SpareBytes: [UCHAR; 23],
    TxFsContext: ULONG,
    GdiTebBatch: GDI_TEB_BATCH,
    RealClientId: CLIENT_ID,
    GdiCachedProcessHandle: HANDLE,
    GdiClientPID: ULONG,
    GdiClientTID: ULONG,
    GdiThreadLocalInfo: PVOID,
    Win32ClientInfo: [ULONG_PTR; 62],
    glDispatchTable: [PVOID; 233],
    glReserved1: [ULONG_PTR; 29],
    glReserved2: PVOID,
    glSectionInfo: PVOID,
    glSection: PVOID,
    glTable: PVOID,
    glCurrentRC: PVOID,
    glContext: PVOID,
    LastStatusValue: NTSTATUS,
    StaticUnicodeString: UNICODE_STRING,
    StaticUnicodeBuffer: [WCHAR; 261],
    DeallocationStack: PVOID,
    TlsSlots: [PVOID; 64],
    TlsLinks: LIST_ENTRY,
    Vdm: PVOID,
    ReservedForNtRpc: PVOID,
    DbgSsReserved: [PVOID; 2],
    HardErrorMode: ULONG,
    Instrumentation: [PVOID; 9],
    ActivityId: GUID,
    SubProcessTag: PVOID,
    PerflibData: PVOID,
    EtwTraceData: PVOID,
    WinSockData: PVOID,
    GdiBatchCount: ULONG,
    u: TEB_u,
    GuaranteedStackBytes: ULONG,
    ReservedForPerf: PVOID,
    ReservedForOle: PVOID,
    WaitingOnLoaderLock: ULONG,
    SavedPriorityState: PVOID,
    ReservedForCodeCoverage: ULONG_PTR,
    ThreadPoolData: PVOID,
    TlsExpansionSlots: *mut PVOID,
    MuiGeneration: ULONG,
    IsImpersonating: ULONG,
    NlsCache: PVOID,
    pShimData: PVOID,
    HeapVirtualAffinity: USHORT,
    LowFragHeapDataSlot: USHORT,
    CurrentTransactionHandle: HANDLE,
    ActiveFrame: PTEB_ACTIVE_FRAME,
    FlsData: PVOID,
    PreferredLanguages: PVOID,
    UserPrefLanguages: PVOID,
    MergedPrefLanguages: PVOID,
    MuiImpersonation: ULONG,
    CrossTebFlags: USHORT,
    SameTebFlags: USHORT,
    TxnScopeEnterCallback: PVOID,
    TxnScopeExitCallback: PVOID,
    TxnScopeContext: PVOID,
    LockCount: ULONG,
    WowTebOffset: LONG,
    ResourceRetValue: PVOID,
    ReservedForWdf: PVOID,
    ReservedForCrt: ULONGLONG,
    EffectiveContainerId: GUID,
}}
BITFIELD! {TEB SameTebFlags: USHORT [
    SafeThunkCall set_SafeThunkCall[0..1],
    InDebugPrint set_InDebugPrint[1..2],
    HasFiberData set_HasFiberData[2..3],
    SkipThreadAttach set_SkipThreadAttach[3..4],
    WerInShipAssertCode set_WerInShipAssertCode[4..5],
    RanProcessInit set_RanProcessInit[5..6],
    ClonedThread set_ClonedThread[6..7],
    SuppressDebugMsg set_SuppressDebugMsg[7..8],
    DisableUserStackWalk set_DisableUserStackWalk[8..9],
    RtlExceptionAttached set_RtlExceptionAttached[9..10],
    InitialThread set_InitialThread[10..11],
    SessionAware set_SessionAware[11..12],
    LoadOwner set_LoadOwner[12..13],
    LoaderWorker set_LoaderWorker[13..14],
    SkipLoaderInit set_SkipLoaderInit[14..15],
    SpareSameTebBits set_SpareSameTebBits[15..16],
]}
pub type PTEB = *mut TEB;