/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using System.Net.Http;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Protocols;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Contains the methods required to ensure that the configuration used by
    /// the OAuth2 introspection handler is in a consistent and valid state.
    /// </summary>
    [EditorBrowsable(EditorBrowsableState.Never)]
    public class OAuthIntrospectionInitializer : IPostConfigureOptions<OAuthIntrospectionOptions>
    {
        private readonly IDistributedCache _cache;
        private readonly IDataProtectionProvider _dataProtectionProvider;

        /// <summary>
        /// Creates a new instance of the <see cref="OAuthIntrospectionInitializer"/> class.
        /// </summary>
        public OAuthIntrospectionInitializer(
            [NotNull] IDistributedCache cache,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
        {
            _cache = cache;
            _dataProtectionProvider = dataProtectionProvider;
        }

        /// <summary>
        /// Populates the default OAuth2 introspection options and ensure
        /// that the configuration is in a consistent and valid state.
        /// </summary>
        /// <param name="name">The authentication scheme associated with the handler instance.</param>
        /// <param name="options">The options instance to initialize.</param>
        public void PostConfigure([NotNull] string name, [NotNull] OAuthIntrospectionOptions options)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (string.IsNullOrEmpty(name))
            {
                throw new ArgumentException("The options instance name cannot be null or empty.", nameof(name));
            }

            if (string.IsNullOrEmpty(options.ClientId) || string.IsNullOrEmpty(options.ClientSecret))
            {
                throw new InvalidOperationException("Client credentials must be configured.");
            }

            if (options.Events == null)
            {
                options.Events = new OAuthIntrospectionEvents();
            }

            if (options.DataProtectionProvider == null)
            {
                options.DataProtectionProvider = _dataProtectionProvider;
            }

            if (options.AccessTokenFormat == null)
            {
                var protector = options.DataProtectionProvider.CreateProtector(
                    nameof(OAuthIntrospectionHandler),
                    nameof(options.AccessTokenFormat), name);

                options.AccessTokenFormat = new TicketDataFormat(protector);
            }

            if (options.Cache == null)
            {
                options.Cache = _cache;
            }

            if (options.HttpClient == null)
            {
                options.HttpClient = new HttpClient
                {
                    Timeout = TimeSpan.FromSeconds(15),
                    MaxResponseContentBufferSize = 1024 * 1024 * 10
                };

                options.HttpClient.DefaultRequestHeaders.UserAgent.ParseAdd("ASP.NET Core OAuth2 introspection middleware");
            }

            if (options.ConfigurationManager == null)
            {
                if (options.Configuration != null)
                {
                    if (string.IsNullOrEmpty(options.Configuration.IntrospectionEndpoint))
                    {
                        throw new InvalidOperationException("The introspection endpoint address cannot be null or empty.");
                    }

                    options.ConfigurationManager = new StaticConfigurationManager<OAuthIntrospectionConfiguration>(options.Configuration);
                }

                else
                {
                    if (options.Authority == null && options.MetadataAddress == null)
                    {
                        throw new InvalidOperationException("The authority or an absolute metadata endpoint address must be provided.");
                    }

                    if (options.MetadataAddress == null)
                    {
                        options.MetadataAddress = new Uri(".well-known/openid-configuration", UriKind.Relative);
                    }

                    if (!options.MetadataAddress.IsAbsoluteUri)
                    {
                        if (options.Authority == null || !options.Authority.IsAbsoluteUri)
                        {
                            throw new InvalidOperationException("The authority must be provided and must be an absolute URL.");
                        }

                        if (!string.IsNullOrEmpty(options.Authority.Fragment) || !string.IsNullOrEmpty(options.Authority.Query))
                        {
                            throw new InvalidOperationException("The authority cannot contain a fragment or a query string.");
                        }

                        if (!options.Authority.OriginalString.EndsWith("/"))
                        {
                            options.Authority = new Uri(options.Authority.OriginalString + "/", UriKind.Absolute);
                        }

                        options.MetadataAddress = new Uri(options.Authority, options.MetadataAddress);
                    }

                    if (options.RequireHttpsMetadata && !options.MetadataAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
                    {
                        throw new InvalidOperationException("The metadata endpoint address must be a HTTPS URL when " +
                                                            "'RequireHttpsMetadata' is not set to 'false'.");
                    }

                    options.ConfigurationManager = new ConfigurationManager<OAuthIntrospectionConfiguration>(
                        options.MetadataAddress.AbsoluteUri, new OAuthIntrospectionConfiguration.Retriever(),
                        new HttpDocumentRetriever(options.HttpClient) { RequireHttps = options.RequireHttpsMetadata });
                }
            }
        }
    }
}
