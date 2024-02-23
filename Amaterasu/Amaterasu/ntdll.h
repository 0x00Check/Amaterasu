#pragma once

extern "C" {
#include <Windows.h>
#include <ntstatus.h>
#include <intrin.h>
#include <Psapi.h>

    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR Buffer;
    } UNICODE_STRING, * PUNICODE_STRING;
    typedef const UNICODE_STRING* PCUNICODE_STRING;

    typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
        USHORT UniqueProcessId;
        USHORT CreatorBackTraceIndex;
        UCHAR ObjectTypeIndex;
        UCHAR HandleAttributes;
        USHORT HandleValue;
        PVOID Object;
        ULONG GrantedAccess;
    } SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

    typedef struct _SYSTEM_HANDLE_INFORMATION {
        ULONG NumberOfHandles;
        SYSTEM_HANDLE_TABLE_ENTRY_INFO Handles[1];
    } SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

    typedef enum _SYSTEM_INFORMATION_CLASS {
        SystemBasicInformation,
        SystemProcessorInformation,
        SystemPerformanceInformation,
        SystemTimeOfDayInformation,
        SystemPathInformation,
        SystemProcessInformation,
        SystemCallCountInformation,
        SystemDeviceInformation,
        SystemProcessorPerformanceInformation,
        SystemFlagsInformation,
        SystemCallTimeInformation,
        SystemModuleInformation,
        SystemLocksInformation,
        SystemStackTraceInformation,
        SystemPagedPoolInformation,
        SystemNonPagedPoolInformation,
        SystemHandleInformation,
        SystemObjectInformation,
        SystemPageFileInformation,
        SystemVdmInstemulInformation,
        SystemVdmBopInformation,
        SystemFileCacheInformation,
        SystemPoolTagInformation,
        SystemInterruptInformation,
        SystemDpcBehaviorInformation,
        SystemFullMemoryInformation,
        SystemLoadGdiDriverInformation,
        SystemUnloadGdiDriverInformation,
        SystemTimeAdjustmentInformation,
        SystemSummaryMemoryInformation,
        SystemMirrorMemoryInformation,
        SystemPerformanceTraceInformation,
        SystemObsolete0,
        SystemExceptionInformation,
        SystemCrashDumpStateInformation,
        SystemKernelDebuggerInformation,
        SystemContextSwitchInformation,
        SystemRegistryQuotaInformation,
        SystemExtendServiceTableInformation,
        SystemPrioritySeperation,
        SystemVerifierAddDriverInformation,
        SystemVerifierRemoveDriverInformation,
        SystemProcessorIdleInformation,
        SystemLegacyDriverInformation,
        SystemCurrentTimeZoneInformation,
        SystemLookasideInformation,
        SystemTimeSlipNotification,
        SystemSessionCreate,
        SystemSessionDetach,
        SystemSessionInformation,
        SystemRangeStartInformation,
        SystemVerifierInformation,
        SystemVerifierThunkExtend,
        SystemSessionProcessInformation,
        SystemLoadGdiDriverInSystemSpace,
        SystemNumaProcessorMap,
        SystemPrefetcherInformation,
        SystemExtendedProcessInformation,
        SystemRecommendedSharedDataAlignment,
        SystemComPlusPackage,
        SystemNumaAvailableMemory,
        SystemProcessorPowerInformation,
        SystemEmulationBasicInformation,
        SystemEmulationProcessorInformation,
        SystemExtendedHandleInformation,
        SystemLostDelayedWriteInformation,
        SystemBigPoolInformation,
        SystemSessionPoolTagInformation,
        SystemSessionMappedViewInformation,
        SystemHotpatchInformation,
        SystemObjectSecurityMode,
        SystemWatchdogTimerHandler,
        SystemWatchdogTimerInformation,
        SystemLogicalProcessorInformation,
        SystemWow64SharedInformationObsolete,
        SystemRegisterFirmwareTableInformationHandler,
        SystemFirmwareTableInformation,
        SystemModuleInformationEx,
        SystemVerifierTriageInformation,
        SystemSuperfetchInformation,
        SystemMemoryListInformation,
        SystemFileCacheInformationEx,
        SystemThreadPriorityClientIdInformation,
        SystemProcessorIdleCycleTimeInformation,
        SystemVerifierCancellationInformation,
        SystemProcessorPowerInformationEx,
        SystemRefTraceInformation,
        SystemSpecialPoolInformation,
        SystemProcessIdInformation,
        SystemErrorPortInformation,
        SystemBootEnvironmentInformation,
        SystemHypervisorInformation,
        SystemVerifierInformationEx,
        SystemTimeZoneInformation,
        SystemImageFileExecutionOptionsInformation,
        SystemCoverageInformation,
        SystemPrefetchPatchInformation,
        SystemVerifierFaultsInformation,
        SystemSystemPartitionInformation,
        SystemSystemDiskInformation,
        SystemProcessorPerformanceDistribution,
        SystemNumaProximityNodeInformation,
        SystemDynamicTimeZoneInformation,
        SystemCodeIntegrityInformation,
        SystemProcessorMicrocodeUpdateInformation,
        SystemProcessorBrandString,
        SystemVirtualAddressInformation,
        SystemLogicalProcessorAndGroupInformation,
        SystemProcessorCycleTimeInformation,
        SystemStoreInformation,
        SystemRegistryAppendString,
        SystemAitSamplingValue,
        SystemVhdBootInformation,
        SystemCpuQuotaInformation,
        SystemNativeBasicInformation,
        SystemSpare1,
        SystemLowPriorityIoInformation,
        SystemTpmBootEntropyInformation,
        SystemVerifierCountersInformation,
        SystemPagedPoolInformationEx,
        SystemSystemPtesInformationEx,
        SystemNodeDistanceInformation,
        SystemAcpiAuditInformation,
        SystemBasicPerformanceInformation,
        SystemQueryPerformanceCounterInformation,
        SystemSessionBigPoolInformation,
        SystemBootGraphicsInformation,
        SystemScrubPhysicalMemoryInformation,
        SystemBadPageInformation,
        SystemProcessorProfileControlArea,
        SystemCombinePhysicalMemoryInformation,
        SystemEntropyInterruptTimingCallback,
        SystemConsoleInformation,
        SystemPlatformBinaryInformation,
        SystemThrottleNotificationInformation,
        SystemHypervisorProcessorCountInformation,
        SystemDeviceDataInformation,
        SystemDeviceDataEnumerationInformation,
        SystemMemoryTopologyInformation,
        SystemMemoryChannelInformation,
        SystemBootLogoInformation,
        SystemProcessorPerformanceInformationEx,
        SystemSpare0,
        SystemSecureBootPolicyInformation,
        SystemPageFileInformationEx,
        SystemSecureBootInformation,
        SystemEntropyInterruptTimingRawInformation,
        SystemPortableWorkspaceEfiLauncherInformation,
        SystemFullProcessInformation,
        SystemKernelDebuggerInformationEx,
        SystemBootMetadataInformation,
        SystemSoftRebootInformation,
        SystemElamCertificateInformation,
        SystemOfflineDumpConfigInformation,
        SystemProcessorFeaturesInformation,
        SystemRegistryReconciliationInformation,
        SystemEdidInformation,
        SystemManufacturingInformation,
        SystemEnergyEstimationConfigInformation,
        SystemHypervisorDetailInformation,
        SystemProcessorCycleStatsInformation,
        SystemVmGenerationCountInformation,
        SystemTrustedPlatformModuleInformation,
        SystemKernelDebuggerFlags,
        SystemCodeIntegrityPolicyInformation,
        SystemIsolatedUserModeInformation,
        SystemHardwareSecurityTestInterfaceResultsInformation,
        SystemSingleModuleInformation,
        SystemAllowedCpuSetsInformation,
        SystemDmaProtectionInformation,
        SystemInterruptCpuSetsInformation,
        SystemSecureBootPolicyFullInformation,
        SystemCodeIntegrityPolicyFullInformation,
        SystemAffinitizedInterruptProcessorInformation,
        SystemRootSiloInformation,
        SystemCpuSetInformation,
        SystemCpuSetTagInformation,
        SystemWin32WerStartCallout,
        SystemSecureKernelProfileInformation,
        SystemCodeIntegrityPlatformManifestInformation,
        SystemInterruptSteeringInformation,
        SystemSupportedProcessorArchitectures,
        SystemMemoryUsageInformation,
        SystemCodeIntegrityCertificateInformation,
        SystemPhysicalMemoryInformation,
        SystemControlFlowTransition,
        SystemKernelDebuggingAllowed,
        SystemActivityModerationExeState,
        SystemActivityModerationUserSettings,
        SystemCodeIntegrityPoliciesFullInformation,
        SystemCodeIntegrityUnlockInformation,
        SystemIntegrityQuotaInformation,
        SystemFlushInformation,
        MaxSystemInfoClass
    } SYSTEM_INFORMATION_CLASS;

    NTSYSAPI VOID NTAPI RtlInitUnicodeString(
        _Out_ PUNICODE_STRING DestinationString,
        _In_opt_ PCWSTR SourceString
    );

    NTSYSCALLAPI NTSTATUS NTAPI NtLoadDriver(
        _In_ PUNICODE_STRING DriverServiceName
    );

    NTSYSCALLAPI NTSTATUS NTAPI NtUnloadDriver(
        _In_ PUNICODE_STRING DriverServiceName
    );

    NTSYSCALLAPI NTSTATUS NTAPI NtQuerySystemInformation(
        _In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
        _Out_opt_ PVOID SystemInformation,
        _In_ ULONG SystemInformationLength,
        _Out_opt_ PULONG ReturnLength
    );
};