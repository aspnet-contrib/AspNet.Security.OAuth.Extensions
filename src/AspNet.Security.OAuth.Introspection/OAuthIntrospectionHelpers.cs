using System;
using JetBrains.Annotations;
using Microsoft.AspNetCore.Http.Authentication;

namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Defines a set of commonly used helpers.
    /// </summary>
    internal static class OAuthIntrospectionHelpers
    {
        /// <summary>
        /// Gets a given property from the authentication properties.
        /// </summary>
        /// <param name="properties">The authentication properties.</param>
        /// <param name="property">The specific property to look for.</param>
        /// <returns>The value corresponding to the property, or <c>null</c> if the property cannot be found.</returns>
        public static string GetProperty([NotNull] this AuthenticationProperties properties, [NotNull] string property)
        {
            if (properties == null)
            {
                throw new ArgumentNullException(nameof(properties));
            }

            if (string.IsNullOrEmpty(property))
            {
                throw new ArgumentException("The property name cannot be null or empty.", nameof(property));
            }

            if (!properties.Items.TryGetValue(property, out string value))
            {
                return null;
            }

            return value;
        }
    }
}
