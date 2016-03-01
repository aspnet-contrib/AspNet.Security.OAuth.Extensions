/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.Owin;
using Microsoft.Owin.Security.Provider;

namespace Owin.Security.OAuth.Introspection {
    /// <summary>
    /// Allows for custom handling of the call to the Authorization Server's Introspection endpoint.
    /// </summary>
    public class RequestTokenIntrospectionContext : BaseContext<OAuthIntrospectionOptions> {
        public RequestTokenIntrospectionContext(
            [NotNull] IOwinContext context,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] HttpRequestMessage message,
            [NotNull] string token)
            : base(context, options) {
            Message = message;
            Token = token;
        }

        /// <summary>
        /// An <see cref="HttpClient"/> for use by the application to call the authorization server.
        /// </summary>
        public HttpClient Client => Options.HttpClient;

        /// <summary>
        /// Gets the HTTP message sent to the introspection endpoint.
        /// </summary>
        public HttpRequestMessage Message { get; }

        /// <summary>
        /// The access token parsed from the client request.
        /// </summary>
        public string Token { get; }
    }
}
