/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Exposes various settings needed to control
    /// the behavior of the validation middleware.
    /// </summary>
    public class OAuthValidationOptions : AuthenticationSchemeOptions
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OAuthValidationOptions"/> class.
        /// </summary>
        public OAuthValidationOptions()
        {
            Events = new OAuthValidationEvents();
        }

        /// <summary>
        /// Gets the intended audiences of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public ISet<string> Audiences { get; } = new HashSet<string>(StringComparer.Ordinal);

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
        /// Enabled by default, this option can be disabled to prevent the validation middleware from returning
        /// an error, an error_description and/or an error_uri in the WWW-Authenticate header.
        /// </summary>
        public bool IncludeErrorDetails { get; set; } = true;

        /// <summary>
        /// Gets or sets the object provided by the application to process events raised by the authentication middleware.
        /// The application may implement the interface fully, or it may create an instance of
        /// <see cref="OAuthValidationEvents"/> and assign delegates only to the events it wants to process.
        /// </summary>
        public new OAuthValidationEvents Events
        {
            get => (OAuthValidationEvents) base.Events;
            set => base.Events = value;
        }

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to unprotect the
        /// access tokens received by the validation middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> AccessTokenFormat { get; set; }

        /// <summary>
        /// Gets or sets the data protection provider used to create the default
        /// data protectors used by the OAuth2 validation handler.
        /// When this property is set to <c>null</c>, the data protection provider
        /// is directly retrieved from the dependency injection container.
        /// </summary>
        public IDataProtectionProvider DataProtectionProvider { get; set; }
    }
}
