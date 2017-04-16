/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Net.Http;
using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Provides the entry point necessary to register the
    /// OAuth2 introspection handler in an ASP.NET Core pipeline.
    /// </summary>
    public class OAuthIntrospectionMiddleware : AuthenticationMiddleware<OAuthIntrospectionOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OAuthIntrospectionMiddleware"/> class.
        /// </summary>
        public OAuthIntrospectionMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OAuthIntrospectionOptions> options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDistributedCache cache,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder)
        {
            if (string.IsNullOrEmpty(Options.ClientId) || string.IsNullOrEmpty(Options.ClientSecret))
            {
                throw new ArgumentException("Client credentials must be configured.", nameof(options));
            }

            if (Options.Events == null)
            {
                Options.Events = new OAuthIntrospectionEvents();
            }

            if (Options.DataProtectionProvider == null)
            {
                Options.DataProtectionProvider = dataProtectionProvider;
            }

            if (Options.AccessTokenFormat == null)
            {
                var protector = Options.DataProtectionProvider.CreateProtector(
                    nameof(OAuthIntrospectionHandler),
                    nameof(Options.AccessTokenFormat), Options.AuthenticationScheme);

                Options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            if (Options.Cache == null)
            {
                Options.Cache = cache;
            }

            if (Options.HttpClient == null)
            {
                Options.HttpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(15),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                Options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Core OAuth2 introspection middleware");
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
                        new HttpDocumentRetriever(Options.HttpClient) { RequireHttps = Options.RequireHttpsMetadata });
                }
            }
        }

        /// <summary>
        /// Returns a new <see cref="OAuthIntrospectionHandler"/> instance.
        /// </summary>
        /// <returns>A new instance of the <see cref="OAuthIntrospectionHandler"/> class.</returns>
        protected override AuthenticationHandler<OAuthIntrospectionOptions> CreateHandler()
        {
            return new OAuthIntrospectionHandler();
        }
    }
}
