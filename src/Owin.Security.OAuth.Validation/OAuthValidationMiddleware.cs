/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Security.Infrastructure;
using Microsoft.Owin.Security.Interop;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(
            [NotNull] OwinMiddleware next,
            [NotNull] IAppBuilder app,
            [NotNull] OAuthValidationOptions options)
            : base(next, options) {
            if (Options.Events == null) {
                Options.Events = new OAuthValidationEvents();
            }

            if (options.DataProtectionProvider == null) {
                // Create a new DI container and register
                // the data protection services.
                var services = new ServiceCollection();

                services.AddDataProtection(configuration => {
                    // Try to use the application name provided by
                    // the OWIN host as the application discriminator.
                    var discriminator = new AppProperties(app.Properties).AppName;

                    // When an application discriminator cannot be resolved from
                    // the OWIN host properties, generate a temporary identifier.
                    if (string.IsNullOrEmpty(discriminator)) {
                        discriminator = Guid.NewGuid().ToString();
                    }

                    configuration.ApplicationDiscriminator = discriminator;
                });

                var container = services.BuildServiceProvider();

                // Resolve a data protection provider from the services container.
                options.DataProtectionProvider = container.GetRequiredService<IDataProtectionProvider>();
            }

            if (options.AccessTokenFormat == null) {
                // Note: the following purposes must match the ones used by ASOS.
                var protector = options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerMiddleware", "ASOS", "Access_Token", "v1");

                options.AccessTokenFormat = new AspNetTicketDataFormat(new DataProtectorShim(protector));
            }

            if (options.Logger == null) {
                options.Logger = new LoggerFactory().CreateLogger<OAuthValidationMiddleware>();
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            return new OAuthValidationHandler();
        }
    }
}
