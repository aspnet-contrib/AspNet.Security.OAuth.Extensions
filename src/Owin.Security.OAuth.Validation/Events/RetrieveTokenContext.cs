/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Notifications;

namespace Owin.Security.OAuth.Validation {
    /// <summary>
    /// Allows custom parsing of access tokens from requests.
    /// </summary>
    public class RetrieveTokenContext : BaseNotification<OAuthValidationOptions> {
        public RetrieveTokenContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthValidationOptions options)
            : base(context, options) {
        }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string Token { get; set; }

        /// <summary>
        /// Gets or sets the <see cref="AuthenticationTicket"/> created by the application.
        /// </summary>
        public AuthenticationTicket Ticket { get; set; }
    }
}
