/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Security.Claims;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Validation {
    /// <summary>
    /// Allows interception of the AuthenticationTicket creation process.
    /// </summary>
    public class CreateTicketContext : BaseControlContext {
        public CreateTicketContext(
            [NotNull] HttpContext context,
            [NotNull] OAuthValidationOptions options,
            [NotNull] AuthenticationTicket ticket)
            : base(context) {
            Options = options;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the options used by the introspection middleware.
        /// </summary>
        public OAuthValidationOptions Options { get; }

        /// <summary>
        /// Gets the identity containing the user claims.
        /// </summary>
        public ClaimsIdentity Identity => Principal?.Identity as ClaimsIdentity;

        /// <summary>
        /// Gets the principal containing the user claims.
        /// </summary>
        public ClaimsPrincipal Principal => Ticket?.Principal;
    }
}
