/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

namespace AspNet.Security.OAuth.Validation
{
    public static class OAuthValidationConstants
    {
        public static class Claims
        {
            public const string Scope = "scope";
        }

        public static class Errors
        {
            public const string InsufficientScope = "insufficient_scope";
            public const string InvalidRequest = "invalid_request";
            public const string InvalidToken = "invalid_token";
        }

        public static class Parameters
        {
            public const string Error = "error";
            public const string ErrorDescription = "error_description";
            public const string ErrorUri = "error_uri";
            public const string Realm = "realm";
            public const string Scope = "scope";
        }

        public static class Properties
        {
            public const string Audiences = ".audiences";
            public const string Error = ".error";
            public const string ErrorDescription = ".error_description";
            public const string ErrorUri = ".error_uri";
            public const string Realm = ".realm";
            public const string Scope = ".scope";
            public const string Scopes = ".scopes";
            public const string Token = "access_token";
        }

        public static class Schemes
        {
            public const string Bearer = "Bearer";
        }
    }
}
