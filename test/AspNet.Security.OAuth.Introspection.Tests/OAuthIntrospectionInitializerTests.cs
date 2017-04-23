/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests
{
    public class OAuthIntrospectionInitializerTests
    {
        [Theory]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("client_id", null)]
        [InlineData("client_id", "")]
        [InlineData(null, "client_secret")]
        [InlineData("", "client_secret")]
        public async Task PostConfigure_ThrowsAnExceptionForMissingCredentials(string identifier, string secret)
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.ClientId = identifier;
                options.ClientSecret = secret;
                options.RequireHttpsMetadata = false;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("Client credentials must be configured.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionForMissingEndpoint()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Configuration = new OAuthIntrospectionConfiguration
                {
                    IntrospectionEndpoint = null
                };
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The introspection endpoint address cannot be null or empty.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionForMissingAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = null;
                options.MetadataAddress = null;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The authority or an absolute metadata endpoint address must be provided.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionForRelativeAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("/relative-path", UriKind.Relative);
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The authority must be provided and must be an absolute URL.", exception.Message);
        }

        [Theory]
        [InlineData("http://www.fabrikam.com/path?param=value")]
        [InlineData("http://www.fabrikam.com/path#param=value")]
        public async Task PostConfigure_ThrowsAnExceptionForInvalidAuthority(string authority)
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri(authority);
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The authority cannot contain a fragment or a query string.", exception.Message);
        }

        [Fact]
        public async Task PostConfigure_ThrowsAnExceptionForNonHttpsAuthority()
        {
            // Arrange
            var server = CreateResourceServer(options =>
            {
                options.Authority = new Uri("http://www.fabrikam.com/");
                options.RequireHttpsMetadata = true;
            });

            var client = server.CreateClient();

            // Act and assert
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(delegate
            {
                return client.GetAsync("/");
            });

            Assert.Equal("The metadata endpoint address must be a HTTPS URL when " +
                         "'RequireHttpsMetadata' is not set to 'false'.", exception.Message);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration = null)
        {
            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services =>
            {
                services.AddDistributedMemoryCache();

                services.AddAuthentication()
                    .AddOAuthIntrospection(options =>
                    {
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

            builder.Configure(app =>
            {
                app.Run(context => context.ChallengeAsync(OAuthIntrospectionDefaults.AuthenticationScheme));
            });

            return new TestServer(builder);
        }
    }
}
