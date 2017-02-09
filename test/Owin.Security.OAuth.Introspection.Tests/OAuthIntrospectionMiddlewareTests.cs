/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Reflection;
using Microsoft.Owin.BuilderProperties;
using Microsoft.Owin.Testing;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [Fact]
        public void Constructor_ThrowsAnExceptionForMissingAuthority() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.InnerException.Message);
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
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
                options.ClientId = identifier;
                options.ClientSecret = secret;
            }));

            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.Equal("options", ((ArgumentException) exception.InnerException).ParamName);
            Assert.StartsWith("Client credentials must be configured.", exception.InnerException.Message);
        }

        [Theory]
        [InlineData(null)]
        [InlineData("")]
        public void Constructor_ThrowsAnExceptionForMissingAppName(string name) {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => TestServer.Create(app => {
                var properties = new AppProperties(app.Properties);
                properties.AppName = name;

                app.UseOAuthIntrospection(options => {
                    options.Authority = "http://www.fabrikam.com/";
                    options.ClientId = "Fabrikam";
                    options.ClientSecret = "B4657E03-D619";
                });
            }));

            Assert.IsType<InvalidOperationException>(exception.InnerException);
            Assert.StartsWith("The application name cannot be resolved from the OWIN application builder. " +
                              "Consider manually setting the 'DataProtectionProvider' property in the " +
                              "options using 'DataProtectionProvider.Create([unique application name])'.",
                              exception.InnerException.Message);
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration) {
            return TestServer.Create(app => app.UseOAuthIntrospection(options => configuration(options)));
        }
    }
}
