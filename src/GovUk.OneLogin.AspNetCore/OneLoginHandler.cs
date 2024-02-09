using System.Text.Encodings.Web;
#if !NET8_0_OR_GREATER
using Microsoft.AspNetCore.Authentication;
#endif
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace GovUk.OneLogin.AspNetCore;

/// <summary>
/// An authentication handler for authenticating using GOV.UK One Login.
/// </summary>
public class OneLoginHandler : OpenIdConnectHandler
{
#if NET8_0_OR_GREATER
    /// <summary>
    /// Initializes a new instance of <see cref="OneLoginHandler"/>.
    /// </summary>
    /// <param name="options">A monitor to observe changes to <see cref="OpenIdConnectOptions"/>.</param>
    /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
    /// <param name="htmlEncoder">The <see cref="System.Text.Encodings.Web.HtmlEncoder"/>.</param>
    /// <param name="urlEncoder">The <see cref="UrlEncoder"/>.</param>
    public OneLoginHandler(IOptionsMonitor<OneLoginOptions> options, ILoggerFactory loggerFactory, HtmlEncoder htmlEncoder, UrlEncoder urlEncoder)
        : base(new MapOneLoginToOpenIdConnectOptionsMonitor(options), loggerFactory, htmlEncoder, urlEncoder)
    {
    }
#else
    /// <summary>
    /// Initializes a new instance of <see cref="OneLoginHandler"/>.
    /// </summary>
    /// <param name="options">A monitor to observe changes to <see cref="OpenIdConnectOptions"/>.</param>
    /// <param name="loggerFactory">The <see cref="ILoggerFactory"/>.</param>
    /// <param name="htmlEncoder">The <see cref="System.Text.Encodings.Web.HtmlEncoder"/>.</param>
    /// <param name="urlEncoder">The <see cref="UrlEncoder"/>.</param>
    /// <param name="clock">The <see cref="ISystemClock"/>.</param>
    public OneLoginHandler(IOptionsMonitor<OneLoginOptions> options, ILoggerFactory loggerFactory, HtmlEncoder htmlEncoder, UrlEncoder urlEncoder, ISystemClock clock)
        : base(new MapOneLoginToOpenIdConnectOptionsMonitor(options), loggerFactory, htmlEncoder, urlEncoder, clock)
    {
    }
#endif

    private sealed class MapOneLoginToOpenIdConnectOptionsMonitor : IOptionsMonitor<OpenIdConnectOptions>
    {
        private readonly IOptionsMonitor<OneLoginOptions> _oneLoginOptionsMonitor;

        public MapOneLoginToOpenIdConnectOptionsMonitor(IOptionsMonitor<OneLoginOptions> oneLoginOptionsMonitor)
        {
            _oneLoginOptionsMonitor = oneLoginOptionsMonitor;
        }

        public OpenIdConnectOptions CurrentValue =>
            _oneLoginOptionsMonitor.CurrentValue.OpenIdConnectOptions;

        public OpenIdConnectOptions Get(string? name) =>
            _oneLoginOptionsMonitor.Get(name).OpenIdConnectOptions;

        public IDisposable? OnChange(Action<OpenIdConnectOptions, string?> listener) =>
            _oneLoginOptionsMonitor.OnChange((options, name) => listener(options.OpenIdConnectOptions, name));
    }
}
