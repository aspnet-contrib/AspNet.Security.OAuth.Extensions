/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows interception of the AuthenticationTicket creation process.
    /// </summary>
    public class CreateTicketContext : ResultContext<OAuthIntrospectionOptions>
    {
        public CreateTicketContext(
            [NotNull] HttpContext context,
            [NotNull] AuthenticationScheme scheme,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] AuthenticationTicket ticket,
            [NotNull] JObject payload)
            : base(context, scheme, options)
        {
            Principal = ticket.Principal;
            Properties = ticket.Properties;
            Payload = payload;
        }

        /// <summary>
        /// Gets the identity containing the user claims.
        /// </summary>
        public ClaimsIdentity Identity => Principal?.Identity as ClaimsIdentity;

        /// <summary>
        /// Gets the payload extracted from the introspection response.
        /// </summary>
        public JObject Payload { get; }
    }
}
