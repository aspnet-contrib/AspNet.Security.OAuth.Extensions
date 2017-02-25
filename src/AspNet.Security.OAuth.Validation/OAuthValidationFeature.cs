/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Exposes the OAuth2 validation details
    /// associated with the current request.
    /// </summary>
    public class OAuthValidationFeature
    {
        /// <summary>
        /// Gets or sets the error details returned
        /// as part of the challenge response.
        /// </summary>
        public OAuthValidationError Error { get; set; }
    }
}
