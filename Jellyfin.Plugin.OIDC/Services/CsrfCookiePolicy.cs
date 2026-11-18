using System;
using Microsoft.AspNetCore.Http;

namespace Jellyfin.Plugin.OIDC.Services;

/// <summary>
/// Decides how the per-flow login-CSRF cookie is issued, and builds its name and options.
/// <para>
/// <b>Strict</b> (<c>__Host-oidc_csrf.&lt;state&gt;</c>, <c>Secure</c>, <c>Path=/</c>): browsers only
/// accept a <c>__Host-</c> cookie from the exact host over HTTPS, with no <c>Domain</c>, so a page
/// on a sibling subdomain cannot plant or toss it (same-site login CSRF).
/// </para>
/// <para>
/// <b>Compatible</b> (<c>oidc_csrf.&lt;state&gt;</c>, <c>Path=/sso/OIDC</c>): the original cookie,
/// kept for plain-HTTP deployments, where browsers refuse <c>Secure</c> and <c>__Host-</c> cookies.
/// </para>
/// The mode is decided once at <c>/Start</c> and stored in <see cref="OidcState"/>; the callback
/// reads only the name recorded there. Never fall back to the other name: accepting the
/// compatible name for a strict flow would let a sibling plant it and reopen the hole.
/// </summary>
public static class CsrfCookiePolicy
{
    private const string StrictPrefix = "__Host-oidc_csrf.";
    private const string CompatiblePrefix = "oidc_csrf.";
    private const string CompatiblePath = "/sso/OIDC";

    /// <summary>
    /// Strict when <paramref name="serverBaseUrl"/> is an absolute <c>https</c> URL, whatever the
    /// request scheme (behind a TLS-terminating proxy without KnownProxies the request looks like
    /// HTTP). Compatible when it is an absolute <c>http</c> URL. When it is empty or not absolute,
    /// follows <paramref name="requestIsHttps"/>.
    /// </summary>
    public static bool UseStrict(string? serverBaseUrl, bool requestIsHttps)
    {
        if (!string.IsNullOrWhiteSpace(serverBaseUrl)
            && Uri.TryCreate(serverBaseUrl, UriKind.Absolute, out var baseUri))
        {
            return string.Equals(baseUri.Scheme, Uri.UriSchemeHttps, StringComparison.OrdinalIgnoreCase);
        }

        return requestIsHttps;
    }

    public static string CookieName(string stateKey, bool strict) =>
        (strict ? StrictPrefix : CompatiblePrefix) + stateKey;

    public static CookieOptions IssueOptions(bool strict, bool requestIsHttps, TimeSpan maxAge) => new()
    {
        HttpOnly = true,
        Secure = strict || requestIsHttps,
        SameSite = SameSiteMode.Lax,
        Path = strict ? "/" : CompatiblePath,
        MaxAge = maxAge
    };

    /// <summary>A <c>__Host-</c> clear must also be <c>Secure</c> and <c>Path=/</c>, or browsers ignore it.</summary>
    public static CookieOptions DeleteOptions(bool strict) => strict
        ? new CookieOptions { Path = "/", Secure = true }
        : new CookieOptions { Path = CompatiblePath };
}
