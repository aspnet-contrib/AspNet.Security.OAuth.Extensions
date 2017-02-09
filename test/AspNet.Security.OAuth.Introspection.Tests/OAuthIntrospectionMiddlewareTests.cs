/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingAuthority() {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.Message);
        }

        [Theory]
        [InlineData(null, null)]
        [InlineData("", "")]
        [InlineData("client_id", null)]
        [InlineData("client_id", "")]
        [InlineData(null, "client_secret")]
        [InlineData("", "client_secret")]
        public void Constructor_ThrowsAnExceptionForMissingCredentials(string identifier, string secret) {
            // Arrange, act, assert
            var exception = Assert.Throws<ArgumentException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
                options.ClientId = identifier;
                options.ClientSecret = secret;
            }));

            Assert.Equal("options", exception.ParamName);
            Assert.StartsWith("Client credentials must be configured.", exception.Message);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration) {
            var builder = new WebHostBuilder();
            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => {
                services.AddAuthentication();
                services.AddDistributedMemoryCache();
            });

            builder.Configure(app => {
                app.UseOAuthIntrospection(options => configuration(options));
            });

            return new TestServer(builder);
        }
    }
}
