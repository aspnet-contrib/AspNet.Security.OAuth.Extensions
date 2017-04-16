/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System.Text.Encodings.Web;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Provides the entry point necessary to register the
    /// OAuth2 validation handler in an ASP.NET Core pipeline.
    /// </summary>
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions>
    {
        /// <summary>
        /// Creates a new instance of the <see cref="OAuthValidationMiddleware"/> class.
        /// </summary>
        public OAuthValidationMiddleware(
            [NotNull] RequestDelegate next,
            [NotNull] IOptions<OAuthValidationOptions> options,
            [NotNull] ILoggerFactory loggerFactory,
            [NotNull] UrlEncoder encoder,
            [NotNull] IDataProtectionProvider dataProtectionProvider)
            : base(next, options, loggerFactory, encoder)
        {
            if (Options.Events == null)
            {
                Options.Events = new OAuthValidationEvents();
            }

            if (Options.DataProtectionProvider == null)
            {
                Options.DataProtectionProvider = dataProtectionProvider;
            }

            if (Options.AccessTokenFormat == null)
            {
                // Note: the following purposes must match the ones used by the OpenID Connect server middleware.
                var protector = Options.DataProtectionProvider.CreateProtector(
                    "OpenIdConnectServerHandler", nameof(Options.AccessTokenFormat), "ASOS");

                Options.AccessTokenFormat = new TicketDataFormat(protector);
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
