/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Allows for custom handling of the call to the Authorization Server's Introspection endpoint.
    /// </summary>
    public class SendIntrospectionRequestContext : BaseControlContext
    {
        public SendIntrospectionRequestContext(
            [NotNull] HttpContext context,
            [NotNull] OAuthIntrospectionOptions options,
            [NotNull] HttpRequestMessage request,
            [NotNull] string token)
            : base(context)
        {
            Options = options;
            Request = request;
            Token = token;
        }

        /// <summary>
        /// Gets the options used by the introspection middleware.
        /// </summary>
        public OAuthIntrospectionOptions Options { get; }

        /// <summary>
        /// An <see cref="HttpClient"/> for use by the application to call the authorization server.
        /// </summary>
        public HttpClient Client => Options.HttpClient;

        /// <summary>
        /// Gets the HTTP request sent to the introspection endpoint.
        /// </summary>
        public new HttpRequestMessage Request { get; }

        /// <summary>
        /// Gets or sets the HTTP response returned by the introspection endpoint.
        /// </summary>
        public new HttpResponseMessage Response { get; set; }

        /// <summary>
        /// The access token parsed from the client request.
        /// </summary>
        public string Token { get; }
    }
}
