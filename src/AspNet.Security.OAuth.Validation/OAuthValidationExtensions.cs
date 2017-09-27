/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.ComponentModel;
using AspNet.Security.OAuth.Validation;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace Microsoft.Extensions.DependencyInjection
{
    /// <summary>
    /// Provides extension methods used to configure the OAuth2
    /// validation middleware in an ASP.NET Core pipeline.
    /// </summary>
    public static class OAuthValidationExtensions
    {
        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOAuthValidation([NotNull] this AuthenticationBuilder builder)
        {
            return builder.AddOAuthValidation(OAuthValidationDefaults.AuthenticationScheme);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The authentication builder.</returns>
        public static AuthenticationBuilder AddOAuthValidation(
            [NotNull] this AuthenticationBuilder builder,
            [NotNull] Action<OAuthValidationOptions> configuration)
        {
            return builder.AddOAuthValidation(OAuthValidationDefaults.AuthenticationScheme, configuration);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOAuthValidation(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme)
        {
            return builder.AddOAuthValidation(scheme, options => { });
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 validation middleware in the ASP.NET Core pipeline.
        /// </summary>
        /// <param name="builder">The authentication builder.</param>
        /// <param name="scheme">The authentication scheme associated with this instance.</param>
        /// <param name="configuration">The delegate used to configure the validation options.</param>
        /// <returns>The authentication builder.</returns>
        [EditorBrowsable(EditorBrowsableState.Advanced)]
        public static AuthenticationBuilder AddOAuthValidation(
            [NotNull] this AuthenticationBuilder builder, [NotNull] string scheme,
            [NotNull] Action<OAuthValidationOptions> configuration)
        {
            if (builder == null)
            {
                throw new ArgumentNullException(nameof(builder));
            }

            if (configuration == null)
            {
                throw new ArgumentNullException(nameof(configuration));
            }

            if (string.IsNullOrEmpty(scheme))
            {
                throw new ArgumentException("The scheme cannot be null or empty.", nameof(scheme));
            }

            // Note: TryAddEnumerable() is used here to ensure the initializer is only registered once.
            builder.Services.TryAddEnumerable(
                ServiceDescriptor.Singleton<IPostConfigureOptions<OAuthValidationOptions>,
                                            OAuthValidationInitializer>());

            return builder.AddScheme<OAuthValidationOptions, OAuthValidationHandler>(scheme, configuration);
        }
    }
}
