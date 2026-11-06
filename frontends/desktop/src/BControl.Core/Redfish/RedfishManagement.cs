using System.Text.Json;
using BControl.Core.Ipmi;
using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Redfish;
public static class RedfishManagement
{
    public static Task<ManagementSnapshot> ReadAsync(string address, DeviceCredential credential, string systemUri, string section, string caFile, uint certPolicy, CancellationToken cancellation, uint tlsMin = 12, Socks5Connection? proxy = null, HostTimeout? timeout = null) => DiscoveryService.RunSessionAsync(address, credential, caFile, certPolicy, cancellation, 15000, null, async (session, remaining, ct) =>
    {
        uint Timeout()
        {
            ct.ThrowIfCancellationRequested();
            var time = remaining(null);
            if (time == 0)
                throw new BcException(Bc.Timeout, Loc.T("error.deviceTimeout"));
            return Math.Min(time, timeout?.Milliseconds ?? 5000);
        }

        Task<JsonElement> Read(string uri) => session.GetResourceAsync(uri, Timeout(), ct);
        systemUri = await DiscoveryService.ResolveSystemAsync(session, systemUri, remaining, ct);
        var system = await Read(systemUri);
        var items = new List<ManagementItem>();
        var switches = new List<ManagementSwitch>();
        uint status = Bc.Ok;
        async Task Optional(string uri, Func<JsonElement, Task> consume)
        {
            try
            {
                await consume(await Read(uri));
            }
            catch (BcException ex)
            {
                status = ex.Status;
                items.Add(new(uri, new[] { new ManagementField(Loc.T("sensor.state"), ex.Message) }));
            }
        }

        if (section == "inventory")
        {
            items.Add(Asset(system));
            foreach (var chassis in Links(system, "Links", "Chassis"))
                await Optional(chassis, json =>
                {
                    items.Add(Asset(json));
                    return Task.CompletedTask;
                });
        }
        else if (section == "sensors")
        {
            foreach (var chassisUri in Links(system, "Links", "Chassis"))
            {
                await Optional(chassisUri, async chassis =>
                {
                    var collection = Link(chassis, "Sensors");
                    var known = new HashSet<int>();
                    var fans = new List<string>();
                    var hasPower = false;
                    if (collection != null)
                    {
                        var sensors = await session.GetCollectionAsync(collection, 2, Timeout(), ct);
                        foreach (var uri in sensors)
                            await Optional(uri, json =>
                            {
                                items.Add(Sensor(json));
                                return Task.CompletedTask;
                            });
                    }
                    else
                    {
                        foreach (var(relation, groups)in new[]
                        {
                            ("Thermal", new[] { "Temperatures", "Fans" }),
                            ("Power", new[] { "Voltages", "PowerSupplies", "PowerControl" })
                        }

                        )
                        {
                            if (LegacySensors.Link(chassis, relation)is not { } uri)
                                continue;
                            await Optional(uri, json =>
                            {
                                foreach (var group in groups)
                                    if (json.TryGetProperty(group, out var array) && array.ValueKind == JsonValueKind.Array)
                                        foreach (var sensor in array.EnumerateArray())
                                        {
                                            items.Add(Sensor(sensor));
                                            if (group == "Fans" && sensor.TryGetProperty("Name", out var fan))
                                                fans.Add(fan.GetString() ?? "");
                                            if (sensor.TryGetProperty("SensorNumber", out var number) && number.TryGetInt32(out var id))
                                                known.Add(id);
                                            if (sensor.TryGetProperty("PowerConsumedWatts", out _) || sensor.TryGetProperty("PowerOutputWatts", out _))
                                                hasPower = true;
                                        }

                                return Task.CompletedTask;
                            });
                        }

                        foreach (var uri in SensorCompatibility.Links(chassis))
                            await Optional(uri, json =>
                            {
                                foreach (var sensor in SensorCompatibility.Map(json, known, hasPower, fans))
                                    items.Add(Sensor(sensor));
                                return Task.CompletedTask;
                            });
                    }
                });
            }
        }
        else if (section == "network")
        {
            var managerPaths = Links(system, "Links", "ManagedBy").ToList();
            if (managerPaths.Count == 0)
                managerPaths.AddRange(await session.DiscoverManagersAsync(Timeout(), ct));
            foreach (var managerUri in managerPaths)
            {
                await Optional(managerUri, async manager =>
                {
                    var hasDell = Vendors.Dell.DellNetwork.Advertised(manager);
                    var oemUnavailable = false;
                    if (hasDell)
                    {
                        var attributesUri = Vendors.Dell.DellNetwork.AttributesUri(managerUri);
                        try
                        {
                            switches.AddRange(Vendors.Dell.DellNetwork.Switches(await Read(attributesUri), attributesUri));
                        }
                        catch (BcException ex)when (ex.Status == Bc.Unsupported || ex is { Status: Bc.HttpError, HttpStatus: 404 or 405 or 501 })
                        {
                            oemUnavailable = true;
                        }
                    }

                    if (Link(manager, "NetworkProtocol")is { } network)
                        await Optional(network, json =>
                        {
                            if ((!hasDell || oemUnavailable) && ManagementSwitches.Read(json, null)is { } ipmiEnabled)
                                switches.Add(new(Loc.T("manage.redfish.ipmi"), network, null, ipmiEnabled));
                            var fields = new List<ManagementField>();
                            Add(fields, json, "HostName", "manage.redfish.hostname");
                            Add(fields, json, "FQDN", "manage.redfish.fqdn");
                            foreach (var protocol in new[]
                            {
                                "HTTP",
                                "HTTPS",
                                "SSH",
                                "IPMI",
                                "KVMIP",
                                "VirtualMedia",
                                "NTP",
                                "SNMP",
                                "SSDP"
                            }

                            )
                                if (json.TryGetProperty(protocol, out var entry) && entry.ValueKind == JsonValueKind.Object)
                                {
                                    if (entry.TryGetProperty("ProtocolEnabled", out var enabled))
                                        fields.Add(new(protocol, Value(enabled)));
                                    if (entry.TryGetProperty("Port", out var port))
                                        fields.Add(new(protocol + " " + Loc.T("manage.redfish.port"), Value(port)));
                                }

                            items.Add(new(Name(manager), fields));
                            return Task.CompletedTask;
                        });
                    if (Link(manager, "EthernetInterfaces")is { } ethernet)
                    {
                        var interfaces = await session.GetCollectionAsync(ethernet, 6, Timeout(), ct);
                        foreach (var uri in interfaces)
                            await Optional(uri, json =>
                            {
                                var fields = new List<ManagementField>();
                                foreach (var(property, key)in new[]
                                {
                                    ("MACAddress", "manage.redfish.mac"),
                                    ("HostName", "manage.redfish.hostname"),
                                    ("FQDN", "manage.redfish.fqdn"),
                                    ("LinkStatus", "manage.redfish.link")
                                }

                                )
                                    Add(fields, json, property, key);
                                foreach (var(property, key)in new[]
                                {
                                    ("IPv4Addresses", "manage.redfish.ipv4"),
                                    ("IPv6Addresses", "manage.redfish.ipv6")
                                }

                                )
                                    if (json.TryGetProperty(property, out var array) && array.ValueKind == JsonValueKind.Array)
                                        foreach (var ip in array.EnumerateArray())
                                            fields.Add(new(Loc.T(key), string.Join(" ", ip.EnumerateObject().Select(p => p.Name + ": " + Value(p.Value)))));
                                items.Add(new(Name(json), fields));
                                return Task.CompletedTask;
                            });
                    }
                });
            }
        }

        return new ManagementSnapshot(items, status)
        {
            Switches = switches
        };
    }, tlsMin, proxy, timeout);
    private static string Name(JsonElement json) => json.TryGetProperty("Name", out var name) ? Value(name) : json.TryGetProperty("Id", out var id) ? Value(id) : "";
    private static string Value(JsonElement value) => value.ValueKind switch
    {
        JsonValueKind.Null => Loc.T("common.unknown"),
        JsonValueKind.True => Loc.T("manage.redfish.enabled"),
        JsonValueKind.False => Loc.T("manage.redfish.disabled"),
        JsonValueKind.String => value.GetString() ?? "",
        _ => value.ToString(),
    };
    private static void Add(List<ManagementField> fields, JsonElement json, string property, string key)
    {
        if (json.TryGetProperty(property, out var value))
            fields.Add(new(Loc.T(key), Value(value)));
    }

    private static string? Link(JsonElement json, string relation) => json.TryGetProperty(relation, out var link) && link.ValueKind == JsonValueKind.Object && link.TryGetProperty("@odata.id", out var id) ? id.GetString() : null;
    private static IEnumerable<string> Links(JsonElement json, string container, string relation)
    {
        if (!json.TryGetProperty(container, out var links) || links.ValueKind != JsonValueKind.Object || !links.TryGetProperty(relation, out var array) || array.ValueKind != JsonValueKind.Array)
            yield break;
        foreach (var link in array.EnumerateArray())
            if (link.ValueKind == JsonValueKind.Object && link.TryGetProperty("@odata.id", out var id) && id.GetString()is { } uri)
                yield return uri;
    }

    private static ManagementItem Asset(JsonElement json)
    {
        var fields = new List<ManagementField>();
        foreach (var(property, key)in new[]
        {
            ("Manufacturer", "manage.redfish.manufacturer"),
            ("Model", "manage.redfish.model"),
            ("SerialNumber", "manage.redfish.serial"),
            ("PartNumber", "manage.redfish.partNumber"),
            ("AssetTag", "manage.redfish.assetTag"),
            ("SKU", "manage.redfish.sku"),
            ("ChassisType", "manage.redfish.chassisType"),
            ("HostName", "manage.redfish.hostname")
        }

        )
            Add(fields, json, property, key);
        return new(Name(json), fields);
    }

    private static ManagementItem Sensor(JsonElement json)
    {
        var fields = new List<ManagementField>();
        foreach (var property in new[]
        {
            "Reading",
            "ReadingCelsius",
            "ReadingVolts",
            "PowerConsumedWatts",
            "LastPowerOutputWatts",
            "PowerOutputWatts",
            "PowerInputWatts"
        }

        )
        {
            if (!json.TryGetProperty(property, out var reading) || reading.ValueKind == JsonValueKind.Null) continue;
            Add(fields, json, property, "sensor.reading");
            break;
        }
        if (json.TryGetProperty("ReadingUnits", out _)) Add(fields, json, "ReadingUnits", "sensor.units");
        else
        {
            var units = json.TryGetProperty("ReadingCelsius", out _) ? "Cel" : json.TryGetProperty("ReadingVolts", out _) ? "V" :
                new[] { "PowerConsumedWatts", "LastPowerOutputWatts", "PowerOutputWatts", "PowerInputWatts" }.Any(key => json.TryGetProperty(key, out _)) ? "W" : null;
            if (units != null) fields.Add(new(Loc.T("sensor.units"), units));
        }
        if (json.TryGetProperty("Status", out var status) && status.ValueKind == JsonValueKind.Object)
        {
            Add(fields, status, "Health", "sensor.health");
            Add(fields, status, "State", "sensor.state");
        }

        var thresholdNames = new[]
        {
            "LowerCaution",
            "LowerCritical",
            "LowerFatal",
            "UpperCaution",
            "UpperCritical",
            "UpperFatal"
        };
        var legacyNames = new[]
        {
            "LowerThresholdNonCritical",
            "LowerThresholdCritical",
            "LowerThresholdFatal",
            "UpperThresholdNonCritical",
            "UpperThresholdCritical",
            "UpperThresholdFatal"
        };
        for (var index = 0; index < 6; index++)
        {
            var key = "manage.redfish.threshold." + char.ToLowerInvariant(thresholdNames[index][0]) + thresholdNames[index][1..];
            if (json.TryGetProperty("Thresholds", out var thresholds) && thresholds.ValueKind == JsonValueKind.Object && thresholds.TryGetProperty(thresholdNames[index], out var threshold) && threshold.ValueKind == JsonValueKind.Object)
                Add(fields, threshold, "Reading", key);
            else
                Add(fields, json, legacyNames[index], key);
        }

        return new(Name(json), fields);
    }
}
