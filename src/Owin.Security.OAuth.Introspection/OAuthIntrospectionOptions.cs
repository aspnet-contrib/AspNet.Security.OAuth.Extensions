/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Collections.Generic;
using System.Net.Http;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Security;

namespace Owin.Security.OAuth.Introspection
{
    public class OAuthIntrospectionOptions : AuthenticationOptions
    {
        public OAuthIntrospectionOptions()
            : base(OAuthIntrospectionDefaults.AuthenticationScheme)
        {
            AuthenticationMode = AuthenticationMode.Active;
        }

        /// <summary>
        /// Gets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public ISet<string> Audiences { get; } = new HashSet<string>();

        /// <summary>
        /// Gets or sets the base address of the OAuth2/OpenID Connect server.
        /// </summary>
        public string Authority { get; set; }

        /// <summary>
        /// Gets or sets the address of the introspection endpoint.
        /// </summary>
        public string IntrospectionEndpoint { get; set; }

        /// <summary>
        /// Gets or sets the client identifier representing the resource server.
        /// </summary>
        public string ClientId { get; set; }

        /// <summary>
        /// Gets or sets the client secret used to
        /// communicate with the introspection endpoint.
        /// </summary>
        public string ClientSecret { get; set; }

        /// <summary>
        /// Gets or sets the optional "realm" value returned to
        /// the caller as part of the WWW-Authenticate header.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets a boolean determining whether the access token should be stored in the
        /// <see cref="AuthenticationProperties"/> after a successful authentication process.
        /// </summary>
        public bool SaveToken { get; set; } = true;

        /// <summary>
        /// Gets or sets a boolean determining whether the token validation errors should be returned to the caller.
        /// Enabled by default, this option can be disabled to prevent the introspection middleware from returning
        /// an error, an error_description and/or an error_uri in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;

        /// <summary>
        /// Gets or sets the cache used to store the authentication tickets
        /// resolved from the access tokens received by the resource server.
        /// </summary>
        public IDistributedCache Cache { get; set; }

        /// <summary>
        /// Gets or sets the object provided by the application to process events raised by the authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of
        /// <see cref="OAuthIntrospectionEvents"/> and assign delegates only to the events it wants to process.
        /// </summary>
        public OAuthIntrospectionEvents Events { get; set; } = new OAuthIntrospectionEvents();

        /// <summary>
        /// Gets or sets the HTTP client used to communicate
        /// with the remote OAuth2/OpenID Connect server.
        /// </summary>
        public HttpClient HttpClient { get; set; }

        /// <summary>
        /// Gets or sets the logger used by <see cref="OAuthIntrospectionMiddleware"/>.
        /// When unassigned, a default instance is created using the logger factory.
        /// </summary>
        public ILogger Logger { get; set; }

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to serialize and deserialize
        /// the authenticated tickets stored in the distributed cache.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by <see cref="OAuthIntrospectionMiddleware"/>.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }
    }
}
