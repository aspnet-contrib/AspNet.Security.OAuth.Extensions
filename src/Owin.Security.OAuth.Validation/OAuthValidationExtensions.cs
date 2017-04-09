/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using JetBrains.Annotations;
using Microsoft.Extensions.Logging;
using Owin.Security.OAuth.Validation;

namespace Owin
{
    /// <summary>
    /// Provides extension methods used to configure the OAuth2
    /// validation middleware in an OWIN/Katana pipeline.
    /// </summary>
    public static class OAuthValidationExtensions
    {
        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the OWIN/Katana pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOAuthValidation([NotNull] this IAppBuilder app)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            return app.UseOAuthValidation(options => { });
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the OWIN/Katana pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOAuthValidation(
            [NotNull] this IAppBuilder app,
            [NotNull] Action<OAuthValidationOptions> configuration)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OAuthValidationOptions();
            configuration(options);

            return app.UseOAuthValidation(options);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the OWIN/Katana pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="options">The options used to configure the validation middleware.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOAuthValidation(
            [NotNull] this IAppBuilder app,
            [NotNull] OAuthValidationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            return app.Use<OAuthValidationMiddleware>(app.Properties, options);
        }

        /// <summary>
        /// Configures the OAuth2 validation middleware to enable logging.
        /// </summary>
        /// <param name="options">The options used to configure the OAuth2 validation middleware.</param>
        /// <param name="configuration">The delegate used to configure the logger factory.</param>
        /// <returns>The options used to configure the OAuth2 validation middleware.</returns>
        public static OAuthValidationOptions UseLogging(
            [NotNull] this OAuthValidationOptions options,
            [NotNull] Action<ILoggerFactory> configuration)
        {
            if (options == null)
            {
                throw new ArgumentNullException(nameof(options));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            var factory = new LoggerFactory();
            configuration(factory);

            options.Logger = factory.CreateLogger<OAuthValidationMiddleware>();

            return options;
        }
    }
}
