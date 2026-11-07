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
                    var readings = new List<JsonElement>();
                    var known = new HashSet<int>();
                    var fans = new List<string>();
                    var hasPower = false;
                    int? Number(JsonElement sensor) =>
                        sensor.TryGetProperty("SensorNumber", out var value) && value.ValueKind == JsonValueKind.Number &&
                            value.TryGetInt32(out var number) ? number : null;
                    string? Key(JsonElement sensor) => LegacySensors.ReadingKey(Name(sensor), LegacySensors.ReadingUnits(sensor) ?? "");
                    if (collection != null)
                    {
                        try
                        {
                            var sensors = await session.GetCollectionAsync(collection, RedfishAbi.CollectionSensors, Timeout(), ct);
                            foreach (var uri in sensors)
                                await Optional(uri, json =>
                                {
                                    readings.Add(json);
                                    if (Number(json) is { } number) known.Add(number);
                                    return Task.CompletedTask;
                                });
                        }
                        catch (BcException ex) when (ex.Status != Bc.Cancelled)
                        {
                            status = ex.Status;
                            items.Add(new(collection, new[] { new ManagementField(Loc.T("sensor.state"), ex.Message) }));
                        }
                    }
                    var standardCount = readings.Count;
                    void AddLegacy(JsonElement sensor)
                    {
                        if (sensor.ValueKind != JsonValueKind.Object) return;
                        var number = Number(sensor);
                        var key = Key(sensor);
                        var matches = Enumerable.Range(0, standardCount)
                            .Where(index => (number != null && Number(readings[index]) == number) ||
                                (key != null && Key(readings[index]) == key)).Take(2).ToArray();
                        if (matches.Length == 1)
                        {
                            var index = matches[0];
                            if (!LegacySensors.HasReading(readings[index]) && LegacySensors.HasReading(sensor))
                                readings[index] = sensor;
                        }
                        else readings.Add(sensor);
                        if (number is { } id) known.Add(id);
                    }
                    foreach (var (relation, groups) in new[]
                    {
                        ("Thermal", new[] { "Temperatures", "Fans" }),
                        ("Power", new[] { "Voltages", "PowerSupplies", "PowerControl" })
                    })
                    {
                        if (LegacySensors.Link(chassis, relation) is not { } uri)
                            continue;
                        await Optional(uri, json =>
                        {
                            foreach (var group in groups)
                                if (json.TryGetProperty(group, out var array) && array.ValueKind == JsonValueKind.Array)
                                    foreach (var sensor in array.EnumerateArray())
                                    {
                                        if (sensor.ValueKind != JsonValueKind.Object) continue;
                                        AddLegacy(sensor);
                                        if (group == "Fans") fans.Add(Name(sensor));
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
                                AddLegacy(sensor);
                            return Task.CompletedTask;
                        });
                    items.AddRange(readings.Select(Sensor));
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
                        await Optional(network, async json =>
                        {
                            if ((!hasDell || oemUnavailable) && ManagementSwitches.Read(json, null)is { } ipmiEnabled)
                                switches.Add(new(Loc.T("manage.redfish.ipmi"), network, null, ipmiEnabled));
                            items.Add(NetworkItem(Name(manager), await session.GetNetworkRowsAsync(managerUri, false, Timeout(), ct)));
                        });
                    if (Link(manager, "EthernetInterfaces")is { } ethernet)
                    {
                        var interfaces = await session.GetCollectionAsync(ethernet, 6, Timeout(), ct);
                        foreach (var uri in interfaces)
                            try
                            {
                                items.Add(NetworkItem(uri, await session.GetNetworkRowsAsync(uri, true, Timeout(), ct)));
                            }
                            catch (BcException ex)
                            {
                                status = ex.Status;
                                items.Add(new(uri, new[] { new ManagementField(Loc.T("sensor.state"), ex.Message) }));
                            }
                    }
                });
            }
        }

        return new ManagementSnapshot(items, status)
        {
            Switches = switches
        };
    }, tlsMin, proxy, timeout);
    private static ManagementItem NetworkItem(string title, IReadOnlyList<RedfishSession.NetworkRow> rows)
    {
        var fields = new List<ManagementField>();
        foreach (var row in rows)
        {
            var value = (row.ValueIsKey ? Loc.T(row.Value) : row.Value) + row.Suffix;
            if (row.IsHeading) title = value;
            else fields.Add(new(row.LabelIsKey ? Loc.T(row.Label) : row.Label, value));
        }
        return new(title, fields);
    }
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
        foreach (var property in LegacySensors.ReadingFields)
        {
            if (!json.TryGetProperty(property, out var reading) || reading.ValueKind == JsonValueKind.Null) continue;
            Add(fields, json, property, "sensor.reading");
            break;
        }
        if (LegacySensors.ReadingUnits(json) is { } units)
            fields.Add(new(Loc.T("sensor.units"), units));
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
