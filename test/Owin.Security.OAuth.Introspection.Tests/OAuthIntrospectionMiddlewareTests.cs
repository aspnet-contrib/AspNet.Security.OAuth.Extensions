/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Testing;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests
{
    public class OAuthIntrospectionMiddlewareTests
    {
        [Theory]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("client_id", null)]
        [InlineData("client_id", "")]
        [InlineData(null, "client_secret")]
        [InlineData("", "client_secret")]
        public void Constructor_ThrowsAnExceptionForMissingCredentials(string identifier, string secret)
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.ClientId = identifier;
                options.ClientSecret = secret;
                options.RequireHttpsMetadata = false;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("Client credentials must be configured.", exception.InnerException.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ThrowsAnExceptionForMissingAppName(string name)
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => TestServer.Create(app =>
            {
                var properties = new AppProperties(app.Properties);
                properties.AppName = name;

                app.UseOAuthIntrospection(options =>
                {
                    options.Authority = new Uri("http://www.fabrikam.com/");
                    options.ClientId = "Fabrikam";
                    options.ClientSecret = "B4657E03-D619";
                    options.RequireHttpsMetadata = false;
                });
            }));

            Assert.IsType<InvalidOperationException>(exception.InnerException);
            Assert.StartsWith("The application name cannot be resolved from the OWIN application builder. " +
                              "Consider manually setting the 'DataProtectionProvider' property in the " +
                              "options using 'DataProtectionProvider.Create([unique application name])'.",
                              exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingEndpoint()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Configuration = new OAuthIntrospectionConfiguration
                {
                    IntrospectionEndpoint = null
                };
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The introspection endpoint address cannot be null or empty.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Authority = null;
                options.MetadataAddress = null;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The authority or an absolute metadata endpoint address must be provided.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForRelativeAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("/relative-path", UriKind.Relative);
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The authority must be provided and must be an absolute URL.", exception.InnerException.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public void Constructor_ThrowsAnExceptionForInvalidAuthority(string authority)
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri(authority);
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The authority cannot contain a fragment or a query string.", exception.InnerException.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForNonHttpsAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.RequireHttpsMetadata = true;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The metadata endpoint address must be a HTTPS URL when " +
                              "'RequireHttpsMetadata' is not set to 'false'.", exception.InnerException.Message);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration = null)
        {
            return TestServer.Create(app =>
            {
                app.UseOAuthIntrospection(options =>
                {
                    options.Authority = new Uri("http://www.fabrikam.com/");
                    options.RequireHttpsMetadata = false;

                    options.ClientId = "Fabrikam";
                    options.ClientSecret = "B4657E03-D619";

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider(new LoggerFactory());

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });
        }
    }
}
