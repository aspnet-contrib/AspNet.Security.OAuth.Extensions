/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.IdentityModel.Protocols.OpenIdConnect;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests
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
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.ClientId = identifier;
                options.ClientSecret = secret;
                options.RequireHttpsMetadata = false;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("Client credentials must be configured.", exception.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingEndpoint()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Configuration = new OAuthIntrospectionConfiguration
                {
                    IntrospectionEndpoint = null
                };
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The introspection endpoint address cannot be null or empty.", exception.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Authority = null;
                options.MetadataAddress = null;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The authority or an absolute metadata endpoint address must be provided.", exception.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForRelativeAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("/relative-path", UriKind.Relative);
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The authority must be provided and must be an absolute URL.", exception.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public void Constructor_ThrowsAnExceptionForInvalidAuthority(string authority)
        {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri(authority);
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The authority cannot contain a fragment or a query string.", exception.Message);
        }

        [Fact]
        public void Constructor_ThrowsAnExceptionForNonHttpsAuthority()
        {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.RequireHttpsMetadata = true;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The metadata endpoint address must be a HTTPS URL when " +
                              "'RequireHttpsMetadata' is not set to 'false'.", exception.Message);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration = null)
        {
            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services =>
            {
                services.AddAuthentication();
                services.AddDistributedMemoryCache();
            });

            builder.Configure(app =>
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
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider();

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });
            });

            return new TestServer(builder);
        }
    }
}
