/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OAuth.Validation
{
    /// <summary>
    /// Provides the entry point necessary to register the
    /// OAuth2 validation handler in an OWIN/Katana pipeline.
    /// </summary>
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OAuthValidationMiddleware"/> class.
        /// </summary>
        public OAuthValidationMiddleware(
            [NotNull] OwinMiddleware next,
            [NotNull] IDictionary<string, object> properties,
            [NotNull] OAuthValidationOptions options)
            : base(next, options)
        {
            if (Options.Events == null)
            {
                Options.Events = new OAuthValidationEvents();
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
                // Note: the following purposes must match the ones used by the OpenID Connect server middleware.
                var protector = Options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerHandler", nameof(Options.AccessTokenFormat), "ASOS");

                options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (options.Logger == null)
            {
                options.Logger = NullLogger.Instance;
            }
        }

        /// <summary>
        /// Returns a new <see cref="OAuthValidationHandler"/> instance.
        /// </summary>
        /// <returns>A new instance of the <see cref="OAuthValidationHandler"/> class.</returns>
        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler()
        {
            return new OAuthValidationHandler();
        }
    }
}
