/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OAuth.Introspection
{
    public class OAuthIntrospectionMiddleware : AuthenticationMiddleware<OAuthIntrospectionOptions>
    {
        public OAuthIntrospectionMiddleware(
            [NotNull] OwinMiddleware next,
            [NotNull] IDictionary<string, object> properties,
            [NotNull] OAuthIntrospectionOptions options)
            : base(next, options)
        {
            if (string.IsNullOrEmpty(options.Authority) &&
                string.IsNullOrEmpty(options.IntrospectionEndpoint))
            {
                throw new ArgumentException("The authority or the introspection endpoint must be configured.", nameof(options));
            }

            if (string.IsNullOrEmpty(options.ClientId) ||
                string.IsNullOrEmpty(options.ClientSecret))
            {
                throw new ArgumentException("Client credentials must be configured.", nameof(options));
            }

            if (Options.Events == null)
            {
                Options.Events = new OAuthIntrospectionEvents();
            }

            if (options.DataProtectionProvider == null)
            {
                // Use the application name provided by the OWIN host as the Data Protection discriminator.
                // If the application name cannot be resolved, throw an invalid operation exception.
                var discriminator = new AppProperties(properties).AppName;
                if (string.IsNullOrEmpty(discriminator))
                {
                    throw new InvalidOperationException("The application name cannot be resolved from the OWIN application builder. " +
                                                        "Consider manually setting the 'DataProtectionProvider' property in the " +
                                                        "options using 'DataProtectionProvider.Create([unique application name])'.");
                }

                options.DataProtectionProvider = DataProtectionProvider.Create(discriminator);
            }

            if (options.AccessTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OAuthIntrospectionMiddleware),
                    Options.AuthenticationType, "Access_Token", "v1");

                options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (options.Cache == null)
            {
                options.Cache = new MemoryDistributedCache(new MemoryCache(new MemoryCacheOptions
                {
                    CompactOnMemoryPressure = true
                }));
            }

            if (options.Logger == null)
            {
                options.Logger = new LoggerFactory().CreateLogger<OAuthIntrospectionMiddleware>();
            }

            if (options.HttpClient == null)
            {
                options.HttpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(15),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("OWIN OAuth2 introspection middleware");
            }
        }

        protected override AuthenticationHandler<OAuthIntrospectionOptions> CreateHandler()
        {
            return new OAuthIntrospectionHandler();
        }
    }
}
