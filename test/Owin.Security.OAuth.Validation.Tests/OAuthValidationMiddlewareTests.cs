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

namespace Owin.Security.OAuth.Validation.Tests
{
    public class OAuthValidationMiddlewareTests
    {
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

                app.UseOAuthValidation();
            }));

            Assert.IsType<InvalidOperationException>(exception.InnerException);
            Assert.StartsWith("The application name cannot be resolved from the OWIN application builder. " +
                              "Consider manually setting the 'DataProtectionProvider' property in the " +
                              "options using 'DataProtectionProvider.Create([unique application name])'.",
                              exception.InnerException.Message);
        }
    }
}
