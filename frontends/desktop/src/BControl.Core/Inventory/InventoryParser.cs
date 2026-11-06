using System.Runtime.InteropServices;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Inventory;

public sealed record InventoryEntry(
    uint Record, uint Protocol, uint DuplicateOf, string Name, string Address, string Username, string SystemUri);

public sealed record InventoryParseResult(IReadOnlyList<InventoryEntry> Entries);

public sealed class InventoryParseException : Exception
{
    public uint Code { get; }
    public uint Record { get; }
    public uint Line { get; }
    public uint Field { get; }
    public InventoryParseException(uint code, uint record, uint line, uint field)
        : base(Loc.F("import.parseFailed", ("code", code), ("record", record), ("line", line), ("field", field)))
    { Code = code; Record = record; Line = line; Field = field; }
}

/// <summary>批量导入解析：纯 C 核心解析，无网络副作用；错误不回显输入值。</summary>
public static class InventoryParser
{
    public const uint FormatJson = 1;
    public const uint FormatCsv = 2;

    public static InventoryParseResult Parse(byte[] data, uint format)
    {
        var handle = GCHandle.Alloc(data, GCHandleType.Pinned);
        try
        {
            var bytes = new BcBytes { Data = handle.AddrOfPinnedObject(), Length = (ulong)data.Length };
            var error = new NativeMethods.BcInventoryError { StructSize = (uint)Marshal.SizeOf<NativeMethods.BcInventoryError>() };
            var status = NativeMethods.bc_inventory_parse(bytes, format, out var import, out error);
            if (status != Bc.Ok)
                throw new InventoryParseException(error.Code, error.Record, error.Line, error.Field);
            try
            {
                var count = NativeMethods.bc_inventory_count(import);
                var entries = new List<InventoryEntry>((int)count);
                var stride = Marshal.SizeOf<EntryStruct>();
                for (var i = 0u; i < count; i++)
                {
                    var ptr = NativeMethods.bc_inventory_entry_get(import, i);
                    var entry = Marshal.PtrToStructure<EntryStruct>(ptr);
                    entries.Add(new InventoryEntry(i, entry.Protocol, entry.DuplicateOf,
                        Redfish.RedfishSession.Text(entry.Name), Redfish.RedfishSession.Text(entry.Address),
                        Redfish.RedfishSession.Text(entry.Username), Redfish.RedfishSession.Text(entry.SystemUri)));
                }
                return new InventoryParseResult(entries);
            }
            finally
            {
                NativeMethods.bc_inventory_import_destroy(import);
            }
        }
        finally
        {
            handle.Free();
        }
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct EntryStruct
    {
        public uint StructSize;
        public uint Protocol;
        public uint DuplicateOf;
        public uint Reserved;
        public BcString Name;
        public BcString Address;
        public BcString Username;
        public BcString SystemUri;
    }
}
