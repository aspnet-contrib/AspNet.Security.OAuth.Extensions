/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Allows customization of the token validation logic.
    /// </summary>
    public class ValidateTokenContext : BaseControlContext
    {
        public ValidateTokenContext(
            [NotNull] HttpContext context,
            [NotNull] OAuthValidationOptions options,
            [NotNull] AuthenticationTicket ticket)
            : base(context)
        {
            Options = options;
            Ticket = ticket;
        }

        /// <summary>
        /// Gets the options used by the validation middleware.
        /// </summary>
        public OAuthValidationOptions Options { get; }
    }
}
