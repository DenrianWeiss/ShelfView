using System.Runtime.InteropServices;

namespace BControl.Core.Native;

// 与 include/bcontrol/redfish.h / redfish_auth.h 保持一致。
public static class RedfishAbi
{
    public const uint CollectionSystems = 0;
    public const uint CollectionSensors = 2;
    public const uint CollectionManagers = 5;

    public const uint Probe = 13;
    public const uint VirtualMedia = 14;
    public const uint VirtualMediaInsert = 15;
    public const uint VirtualMediaEject = 16;
    public const uint VirtualMediaDiscovery = 17;
    public const uint GraphicalConsole = 18;

    public const uint VmInserted = 1;
    public const uint VmInsertedPresent = 16;
    public const uint VmWriteProtected = 2;
    public const uint VmWriteProtectedSet = 1;
    public const uint VmInsertAction = 4;
    public const uint VmEjectAction = 8;

    public const uint ConsoleServiceEnabled = 1;
    public const uint ConsolePortPresent = 2;
    public const uint ConsoleSessionsPresent = 4;
    public const uint ConsoleTypesPresent = 8;

    public const uint ResetOn = 0;
    public const uint ResetForceOff = 1;
    public const uint ResetGracefulShutdown = 2;
    public const uint ResetGracefulRestart = 3;
    public const uint ResetForceRestart = 4;
    public const uint ResetNmi = 5;
    public const uint ResetForceOn = 6;
    public const uint ResetPushPowerButton = 7;
    public const uint ResetPowerCycle = 8;

    public const uint CommandAccepted = 1;
    public const uint TaskPending = 2;
    public const uint CommandSubmitted = 4;
    public const uint CommandUnconfirmed = 8;
    public const uint TaskTerminal = 4;
    public const uint TaskFailed = 8;
    public const uint TaskCancelled = 16;
    public const uint BootVerified = 4;

    public const uint AuthFellBack = 1;
    public const uint AuthSessionCreated = 2;
    public const uint AuthSessionMayExist = 4;
    public const uint AuthPasswordChangeRequired = 8;
    public const uint AuthLoggedOut = 16;

    public const uint ConnectionOpen = 0;
    public const uint ConnectionClosing = 1;
    public const uint ConnectionClosed = 2;

    public const uint LoginAuto = 0;
    public const uint LoginBasic = 1;
    public const uint LoginSession = 2;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint RequestTimeoutMs;
    public uint MaxSystems;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishCollectionOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint RequestTimeoutMs;
    public uint MaxMembers;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishLoginOptions
{
    public uint StructSize;
    public uint AbiVersion;
    public uint Mode;
    public uint RequestTimeoutMs;
    public BcString Username;
    public BcString Password;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BcRedfishResult
{
    public uint StructSize;
    public uint Status;
    public uint Kind;
    public uint HttpStatus;
    public ulong EndpointRevision;
    public BcString ResourceUri;
    public BcString RedfishVersion;
    public BcString Id;
    public BcString Name;
    public BcString RawPowerState;
    public IntPtr Systems;
    public uint SystemCount;
    public uint PowerState;
    public uint Flags;
    public uint Reserved;
    public BcBytes ErrorBody;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishSystemIdentity
{
    public uint StructSize;
    public uint Reserved;
    public BcString Manufacturer;
    public BcString Model;
    public BcString SerialNumber;
    public BcString Uuid;
    public BcString HostName;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishContextInfo
{
    public uint StructSize;
    public uint Status;
    public BcString PhysicalContext;
    public BcString ReadingBasis;
    public BcString SensorCollectionUri;
    public BcString ThermalUri;
    public IntPtr RelatedItems;
    public uint RelatedCount;
    public uint Flags;
    public IntPtr Chassis;
    public uint ChassisCount;
    public uint Enabled;
    public IntPtr Systems;
    public uint SystemCount;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BcRedfishSensorInfo
{
    public uint StructSize;
    public uint Flags;
    public double Reading;
    public double RangeMin;
    public double RangeMax;
    public BcString ReadingType;
    public BcString Units;
    public BcString Health;
    public BcString State;
    public BcString ReadingTime;
    public fixed double Thresholds[6];
    public uint ThresholdMask;
    public uint Reserved;
    public BcBytes ThresholdsJson;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishCollectionInfo
{
    public uint StructSize;
    public uint CollectionKind;
    public IntPtr Members;
    public uint MemberCount;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishResourceInfo
{
    public uint StructSize;
    public uint Reserved;
    public BcString OdataType;
    public BcBytes Json;
    public BcBytes OemJson;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishVirtualMediaInfo
{
    public uint StructSize;
    public uint Flags;
    public BcString Id;
    public BcString Name;
    public BcString Image;
    public BcString ImageName;
    public BcString ConnectedVia;
    public IntPtr MediaTypes;
    public uint MediaTypeCount;
    public uint Inserted;
    public uint WriteProtected;
    public BcString InsertTarget;
    public BcString EjectTarget;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishGraphicalConsoleInfo
{
    public uint StructSize;
    public uint Flags;
    public uint ServiceEnabled;
    public uint Port;
    public uint MaxSessions;
    public IntPtr ConnectTypes;
    public uint ConnectTypeCount;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishResetInfo
{
    public uint StructSize;
    public uint SupportedResetTypes;
    public BcString Target;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcBootInfo
{
    public uint StructSize;
    public uint Status;
    public uint Target;
    public uint Mode;
    public uint Flags;
    public uint SupportedTargets;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishBootInfo
{
    public uint StructSize;
    public uint SupportedModes;
    public BcBootInfo Boot;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishVirtualMediaInsertOptions
{
    public uint StructSize;
    public uint Flags;
    public BcString Image;
    public BcString TransferMethod;
    public BcString TransferProtocolType;
    public uint WriteProtected;
    public uint Reserved;
}

[StructLayout(LayoutKind.Sequential)]
internal unsafe struct BcRedfishAuthResult
{
    public uint StructSize;
    public uint Status;
    public uint HttpStatus;
    public uint Flags;
    public uint AuthMode;
    public uint Reserved;
    public IntPtr Connection;
    public BcString SessionUri;
    public BcBytes ErrorBody;
    public BcBytes MessagesJson;
}

[StructLayout(LayoutKind.Sequential)]
internal struct BcRedfishConnectionInfo
{
    public uint StructSize;
    public uint Mode;
    public uint State;
    public uint Reserved;
    public BcString SessionUri;
    public ulong EndpointRevision;
}
