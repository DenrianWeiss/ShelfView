using BControl.Core.Localization;
using BControl.Core.Native;

namespace BControl.Core.Tests;

public sealed class LocalizationTests
{
    [Fact]
    public void CatalogIsEmbeddedAndSupportsBothLanguages()
    {
        var loc = Loc.Instance;
        Assert.Contains(loc.Languages, language => language.Tag == "zh-CN");
        Assert.Contains(loc.Languages, language => language.Tag == "en");
        Assert.Equal("zh-CN", loc.DefaultLanguage);
    }

    [Fact]
    public void LanguageSwitchAndPlaceholders()
    {
        var loc = Loc.Instance;
        var original = loc.Language;
        try
        {
            loc.Language = "en";
            Assert.Equal("Cancel", Loc.T("common.cancel"));
            Assert.Equal("Reading system /redfish/v1/Systems/1", Loc.F("add.readingSystem", ("uri", "/redfish/v1/Systems/1")));
            Assert.Equal("Timed out", loc.Status(Bc.Timeout));

            loc.Language = "zh-CN";
            Assert.Equal("取消", Loc.T("common.cancel"));
            Assert.Equal("读取系统 /redfish/v1/Systems/1", Loc.F("add.readingSystem", ("uri", "/redfish/v1/Systems/1")));
        }
        finally
        {
            loc.Language = original;
        }
    }

    [Fact]
    public void MissingKeysFallBackToTheKey()
    {
        Assert.Equal("missing.key", Loc.T("missing.key"));
    }
}
