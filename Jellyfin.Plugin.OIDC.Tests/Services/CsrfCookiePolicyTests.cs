using System;
using Jellyfin.Plugin.OIDC.Services;
using Microsoft.AspNetCore.Http;
using Xunit;

namespace Jellyfin.Plugin.OIDC.Tests.Services;

public class CsrfCookiePolicyTests
{
    // ── UseStrict ──────────────────────────────────────────────────────────────

    [Theory]
    [InlineData("https://jellyfin.example", false, true)]
    [InlineData("https://jellyfin.example", true, true)]
    [InlineData("HTTPS://jellyfin.example/jf", false, true)]
    [InlineData("http://jellyfin.lan:8096", true, false)]
    [InlineData("http://jellyfin.lan:8096", false, false)]
    [InlineData("", true, true)]
    [InlineData("", false, false)]
    [InlineData("   ", false, false)]
    [InlineData(null, true, true)]
    [InlineData("jellyfin.example", true, true)]
    [InlineData("jellyfin.example", false, false)]
    public void UseStrict_FollowsServerBaseUrlSchemeThenRequest(string? serverBaseUrl, bool requestIsHttps, bool expected)
    {
        Assert.Equal(expected, CsrfCookiePolicy.UseStrict(serverBaseUrl, requestIsHttps));
    }

    // ── CookieName ─────────────────────────────────────────────────────────────

    [Fact]
    public void CookieName_Strict_UsesHostPrefix() =>
        Assert.Equal("__Host-oidc_csrf.abc123", CsrfCookiePolicy.CookieName("abc123", strict: true));

    [Fact]
    public void CookieName_Compatible_UsesOriginalName() =>
        Assert.Equal("oidc_csrf.abc123", CsrfCookiePolicy.CookieName("abc123", strict: false));

    // ── IssueOptions ───────────────────────────────────────────────────────────

    [Fact]
    public void IssueOptions_Strict_MeetsHostPrefixRulesEvenOverHttp()
    {
        var options = CsrfCookiePolicy.IssueOptions(strict: true, requestIsHttps: false, TimeSpan.FromMinutes(10));

        Assert.True(options.Secure);
        Assert.Equal("/", options.Path);
        Assert.Null(options.Domain);
        Assert.True(options.HttpOnly);
        Assert.Equal(SameSiteMode.Lax, options.SameSite);
        Assert.Equal(TimeSpan.FromMinutes(10), options.MaxAge);
    }

    [Theory]
    [InlineData(false, false)]
    [InlineData(true, true)]
    public void IssueOptions_Compatible_KeepsOriginalPathAndSecureFollowsRequest(bool requestIsHttps, bool expectedSecure)
    {
        var options = CsrfCookiePolicy.IssueOptions(strict: false, requestIsHttps, TimeSpan.FromMinutes(10));

        Assert.Equal(expectedSecure, options.Secure);
        Assert.Equal("/sso/OIDC", options.Path);
        Assert.True(options.HttpOnly);
    }

    // ── DeleteOptions ──────────────────────────────────────────────────────────

    [Fact]
    public void DeleteOptions_Strict_IsSecureAtRoot()
    {
        var options = CsrfCookiePolicy.DeleteOptions(strict: true);

        Assert.True(options.Secure);
        Assert.Equal("/", options.Path);
    }

    [Fact]
    public void DeleteOptions_Compatible_MatchesIssuePath() =>
        Assert.Equal("/sso/OIDC", CsrfCookiePolicy.DeleteOptions(strict: false).Path);
}
