/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Exposes the OAuth2 introspection details
    /// associated with the current request.
    /// </summary>
    public class OAuthIntrospectionFeature
    {
        /// <summary>
        /// Gets or sets the error details returned
        /// as part of the challenge response.
        /// </summary>
        public OAuthIntrospectionError Error { get; set; }
    }
}
