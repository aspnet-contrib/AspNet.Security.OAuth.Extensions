/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows custom parsing of access tokens from requests.
    /// </summary>
    public class RetrieveTokenContext : ResultContext<OAuthIntrospectionOptions>
    {
        public RetrieveTokenContext(
            [NotNull] HttpContext context,
            [NotNull] AuthenticationScheme scheme,
            [NotNull] OAuthIntrospectionOptions options)
            : base(context, scheme, options)
        {
        }

        /// <summary>
        /// Gets or sets the access token.
        /// </summary>
        public string Token { get; set; }
    }
}
