/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

namespace Owin.Security.OAuth.Introspection
{
    /// <summary>
    /// Represents an OAuth2 introspection error.
    /// </summary>
    public class OAuthIntrospectionError
    {
        /// <summary>
        /// Gets or sets the error code.
        /// </summary>
        public string Error { get; set; }

        /// <summary>
        /// Gets or sets the error_description.
        /// </summary>
        public string ErrorDescription { get; set; }

        /// <summary>
        /// Gets or sets the error_uri.
        /// </summary>
        public string ErrorUri { get; set; }

        /// <summary>
        /// Gets or sets the realm.
        /// </summary>
        public string Realm { get; set; }

        /// <summary>
        /// Gets or sets the scope.
        /// </summary>
        public string Scope { get; set; }
    }
}
