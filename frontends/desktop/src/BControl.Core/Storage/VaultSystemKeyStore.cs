using System.Runtime.InteropServices;
using System.Security.Cryptography;
using BControl.Core.Native;

namespace BControl.Core.Storage;

public sealed record VaultStoredKey(byte[] Key, bool RoamingEligible);
public interface IVaultKeyStore
{
    VaultStoredKey? Read(VaultMetadata metadata);
    bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool allowRoaming);
}
public sealed class SystemVaultKeyStore : IVaultKeyStore
{
    public VaultStoredKey? Read(VaultMetadata metadata) => VaultSystemKeyStore.Read(metadata);
    public bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool allowRoaming) => VaultSystemKeyStore.Store(metadata, key, allowRoaming);
}
public static class VaultSystemKeyStore
{
    public static VaultStoredKey? Read(VaultMetadata metadata)
    {
        using var reference = BcStringPinned.Pin(metadata.VaultId + metadata.KeyId);
        var key = new byte[32];
        try {
            Bc.Check(ReadKey(reference.Value, key, 32, out var found, out var flags), "vault.operation");
            if (found != 0) return new(key, (flags & 2) != 0);
            CryptographicOperations.ZeroMemory(key); return null;
        }
        catch { CryptographicOperations.ZeroMemory(key); throw; }
    }
    public static unsafe bool Store(VaultMetadata metadata, ReadOnlySpan<byte> key, bool allowRoaming = true)
    {
        using var reference = BcStringPinned.Pin(metadata.VaultId + metadata.KeyId);
        fixed (byte* bytes = key) {
            Bc.Check(StoreKey(reference.Value, new() { Data = (IntPtr)bytes, Length = (ulong)key.Length },
                allowRoaming ? 1 : 0, out var flags), "vault.operation");
            return (flags & 2) != 0;
        }
    }
    public static void Delete(VaultMetadata metadata)
    {
        using var reference = BcStringPinned.Pin(metadata.VaultId + metadata.KeyId);
        Bc.Check(DeleteKey(reference.Value), "vault.operation");
    }
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_system_key_read", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint ReadKey(BcString reference, [Out] byte[] key, uint capacity, out int found, out uint flags);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_system_key_store", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint StoreKey(BcString reference, BcBytes key, int allowRoaming, out uint flags);
    [DllImport("bcontrol_vault", EntryPoint = "bc_vault_system_key_delete", CallingConvention = CallingConvention.Cdecl)]
    private static extern uint DeleteKey(BcString reference);
}
