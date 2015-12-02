using System;
using Microsoft.Extensions.Internal;
using Owin.Security.OAuth.Introspection;

namespace Owin {
    /// <summary>
    /// Provides extension methods used to configure the OAuth2
    /// introspection middleware in an OWIN/Katana pipeline.
    /// </summary>
    public static class OAuthIntrospectionExtensions {
        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the OWIN/Katana pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="configuration">The delegate used to configure the introspection options.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOAuthIntrospection(
            [NotNull] this IAppBuilder app,
            [NotNull] Action<OAuthIntrospectionOptions> configuration) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (configuration == null) {
                throw new ArgumentNullException(nameof(configuration));
            }

            var options = new OAuthIntrospectionOptions();
            configuration(options);

            return app.UseOAuthIntrospection(options);
        }

        /// <summary>
        /// Adds a new instance of the OAuth2 introspection middleware in the OWIN/Katana pipeline.
        /// </summary>
        /// <param name="app">The application builder.</param>
        /// <param name="options">The options used to configure the introspection middleware.</param>
        /// <returns>The application builder.</returns>
        public static IAppBuilder UseOAuthIntrospection(
            [NotNull] this IAppBuilder app,
            [NotNull] OAuthIntrospectionOptions options) {
            if (app == null) {
                throw new ArgumentNullException(nameof(app));
            }

            if (options == null) {
                throw new ArgumentNullException(nameof(options));
            }

            return app.Use<OAuthIntrospectionMiddleware>(app, options);
        }
    }
}
