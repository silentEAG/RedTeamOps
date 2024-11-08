use winapi::shared::minwindef::DWORD;
use winapi::shared::ntdef::{LPCWSTR, LPWSTR, PVOID};
ENUM! {enum TAG_INFO_LEVEL {
    eTagInfoLevelNameFromTag = 1,
    eTagInfoLevelNamesReferencingModule = 2,
    eTagInfoLevelNameTagMapping = 3,
    eTagInfoLevelMax = 4,
}}
ENUM! {enum TAG_TYPE {
    eTagTypeService = 1,
    eTagTypeMax = 2,
}}
STRUCT! {struct TAG_INFO_NAME_FROM_TAG_IN_PARAMS {
    dwPid: DWORD,
    dwTag: DWORD,
}}
pub type PTAG_INFO_NAME_FROM_TAG_IN_PARAMS = *mut TAG_INFO_NAME_FROM_TAG_IN_PARAMS;
STRUCT! {struct TAG_INFO_NAME_FROM_TAG_OUT_PARAMS {
    eTagType: DWORD,
    pszName: LPWSTR,
}}
pub type PTAG_INFO_NAME_FROM_TAG_OUT_PARAMS = *mut TAG_INFO_NAME_FROM_TAG_OUT_PARAMS;
STRUCT! {struct TAG_INFO_NAME_FROM_TAG {
    InParams: TAG_INFO_NAME_FROM_TAG_IN_PARAMS,
    OutParams: TAG_INFO_NAME_FROM_TAG_OUT_PARAMS,
}}
pub type PTAG_INFO_NAME_FROM_TAG = *mut TAG_INFO_NAME_FROM_TAG;
STRUCT! {struct TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS {
    dwPid: DWORD,
    pszModule: LPWSTR,
}}
pub type PTAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS =
    *mut TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS;
STRUCT! {struct TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS {
    eTagType: DWORD,
    pmszNames: LPWSTR,
}}
pub type PTAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS =
    *mut TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS;
STRUCT! {struct TAG_INFO_NAMES_REFERENCING_MODULE {
    InParams: TAG_INFO_NAMES_REFERENCING_MODULE_IN_PARAMS,
    OutParams: TAG_INFO_NAMES_REFERENCING_MODULE_OUT_PARAMS,
}}
pub type PTAG_INFO_NAMES_REFERENCING_MODULE = *mut TAG_INFO_NAMES_REFERENCING_MODULE;
STRUCT! {struct TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS {
    dwPid: DWORD,
}}
pub type PTAG_INFO_NAME_TAG_MAPPING_IN_PARAMS = *mut TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS;
STRUCT! {struct TAG_INFO_NAME_TAG_MAPPING_ELEMENT {
    eTagType: DWORD,
    dwTag: DWORD,
    pszName: LPWSTR,
    pszGroupName: LPWSTR,
}}
pub type PTAG_INFO_NAME_TAG_MAPPING_ELEMENT = *mut TAG_INFO_NAME_TAG_MAPPING_ELEMENT;
STRUCT! {struct TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS {
    cElements: DWORD,
    pNameTagMappingElements: PTAG_INFO_NAME_TAG_MAPPING_ELEMENT,
}}
pub type PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS = *mut TAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS;
STRUCT! {struct TAG_INFO_NAME_TAG_MAPPING {
    InParams: TAG_INFO_NAME_TAG_MAPPING_IN_PARAMS,
    pOutParams: PTAG_INFO_NAME_TAG_MAPPING_OUT_PARAMS,
}}
pub type PTAG_INFO_NAME_TAG_MAPPING = *mut TAG_INFO_NAME_TAG_MAPPING;
EXTERN! {extern "system" {
    fn I_QueryTagInformation(
        pszMachineName: LPCWSTR,
        eInfoLevel: TAG_INFO_LEVEL,
        pTagInfo: PVOID,
    ) -> DWORD;
}}
FN! {stdcall PQUERY_TAG_INFORMATION(
    pszMachineName: LPCWSTR,
    eInfoLevel: TAG_INFO_LEVEL,
    pTagInfo: PVOID,
) -> DWORD}
