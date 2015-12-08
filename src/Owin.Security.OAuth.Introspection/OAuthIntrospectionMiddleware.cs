/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OAuth.Introspection {
    public class OAuthIntrospectionMiddleware : AuthenticationMiddleware<OAuthIntrospectionOptions> {
        public OAuthIntrospectionMiddleware(OwinMiddleware next, IAppBuilder app, OAuthIntrospectionOptions options)
            : base(next, options) {
            if (string.IsNullOrEmpty(options.Authority) &&
                string.IsNullOrEmpty(options.IntrospectionEndpoint)) {
                throw new ArgumentException("The authority or the introspection endpoint must be configured.", nameof(options));
            }

            if (string.IsNullOrEmpty(options.ClientId) ||
                string.IsNullOrEmpty(options.ClientSecret)) {
                throw new ArgumentException("Client credentials must be configured.", nameof(options));
            }

            if (options.Cache == null) {
                options.Cache = new LocalCache(new MemoryCache(new MemoryCacheOptions {
                    CompactOnMemoryPressure = true
                }));
            }

            if (options.Logger == null) {
                options.Logger = app.CreateLogger<OAuthIntrospectionMiddleware>();
            }

            if (options.HttpClient == null) {
                options.HttpClient = new HttpClient {
                    Timeout = TimeSpan.FromSeconds(60),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET OAuth2 introspection middleware");
            }
        }

        protected override AuthenticationHandler<OAuthIntrospectionOptions> CreateHandler() {
            return new OAuthIntrospectionHandler();
        }
    }
}
