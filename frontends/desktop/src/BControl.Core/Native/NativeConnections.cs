namespace BControl.Core.Native;

internal static class NativeConnections
{
    internal static uint Connect(ref BcKvmTransportOptions options, Socks5Connection? proxy, out IntPtr transport)
    {
        using var pin = proxy?.Pin();
        return pin == null
            ? NativeMethods.bc_kvm_transport_connect(ref options, out transport)
            : NativeMethods.bc_kvm_transport_connect_proxy(ref options, ref pin.Value, out transport);
    }

    internal static uint CreateEndpoint(IntPtr context, ref BcEndpointOptions options, Socks5Connection? proxy, out IntPtr endpoint)
    {
        using var pin = proxy?.Pin();
        return pin == null
            ? NativeMethods.bc_endpoint_create(context, ref options, out endpoint)
            : NativeMethods.bc_endpoint_create_proxy(context, ref options, ref pin.Value, out endpoint);
    }
}
