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
using Microsoft.IdentityModel.Protocols;
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
            if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
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

            if (Options.ConfigurationManager == null)
            {
                if (Options.Configuration != null)
                {
                    if (string.IsNullOrEmpty(Options.Configuration.IntrospectionEndpoint))
                    {
                        throw new ArgumentException("The introspection endpoint address cannot be null or empty.", nameof(options));
                    }

                    Options.ConfigurationManager = new StaticConfigurationManager<OAuthIntrospectionConfiguration>(Options.Configuration);
                }

                else
                {
                    if (Options.Authority == null && Options.MetadataAddress == null)
                    {
                        throw new ArgumentException("The authority or an absolute metadata endpoint address must be provided.", nameof(options));
                    }

                    if (Options.MetadataAddress == null)
                    {
                        Options.MetadataAddress = new Uri(".well-known/openid-configuration", UriKind.Relative);
                    }

                    if (!Options.MetadataAddress.IsAbsoluteUri)
                    {
                        if (Options.Authority == null || !Options.Authority.IsAbsoluteUri)
                        {
                            throw new ArgumentException("The authority must be provided and must be an absolute URL.", nameof(options));
                        }

                        if (!string.IsNullOrEmpty(Options.Authority.Fragment) || !string.IsNullOrEmpty(Options.Authority.Query))
                        {
                            throw new ArgumentException("The authority cannot contain a fragment or a query string.", nameof(options));
                        }

                        if (!Options.Authority.OriginalString.EndsWith("/"))
                        {
                            Options.Authority = new Uri(Options.Authority.OriginalString + "/", UriKind.Absolute);
                        }

                        Options.MetadataAddress = new Uri(Options.Authority, Options.MetadataAddress);
                    }

                    if (Options.RequireHttpsMetadata && !Options.MetadataAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new ArgumentException("The metadata endpoint address must be a HTTPS URL when " +
                                                    "'RequireHttpsMetadata' is not set to 'false'.", nameof(options));
                    }

                    Options.ConfigurationManager = new ConfigurationManager<OAuthIntrospectionConfiguration>(
                        Options.MetadataAddress.AbsoluteUri, new OAuthIntrospectionConfiguration.Retriever(),
                        (IDocumentRetriever) Activator.CreateInstance(
                            type: typeof(OpenIdConnectConfiguration).Assembly.GetType("Microsoft.IdentityModel.Protocols.HttpDocumentRetriever"),
                            args: Options.HttpClient));
                }
            }
        }

        protected override AuthenticationHandler<OAuthIntrospectionOptions> CreateHandler()
        {
            return new OAuthIntrospectionHandler();
        }
    }
}
