/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Http.Authentication;
using Microsoft.AspNetCore.Http.Features.Authentication;
using Microsoft.AspNetCore.TestHost;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace AspNet.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionHandlerTests {
        [Fact]
        public async Task HandleAuthenticateAsync_MissingTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MissingAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AnyMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-multiple-audiences");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_MultipleMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-multiple-audiences");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ExpiredTicketCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredClaims() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token-with-scopes");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var claims = from claim in ticket.Value<JArray>("Claims")
                         select new {
                             Type = claim.Value<string>(nameof(Claim.Type)),
                             Value = claim.Value<string>(nameof(Claim.Value))
                         };

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Contains(claims, claim => claim.Type == ClaimTypes.NameIdentifier &&
                                             claim.Value == "Fabrikam");

            Assert.Contains(claims, claim => claim.Type == OAuthIntrospectionConstants.Claims.Scope &&
                                             claim.Value == "C54A8F5E-0387-43F4-BA43-FD4B50DC190D");

            Assert.Contains(claims, claim => claim.Type == OAuthIntrospectionConstants.Claims.Scope &&
                                             claim.Value == "5C57E3BD-9EFB-4224-9AB8-C8C5E009FFD7");
        }

        [Fact]
        public async Task HandleAuthenticateAsync_AuthenticationTicketContainsRequiredProperties() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.SaveToken = true;
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/ticket");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            var ticket = JObject.Parse(await response.Content.ReadAsStringAsync());
            var properties = from claim in ticket.Value<JArray>("Properties")
                             select new {
                                 Name = claim.Value<string>("Name"),
                                 Value = claim.Value<string>("Value")
                             };

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);

            Assert.Contains(properties, property => property.Name == ".Token.access_token" &&
                                                    property.Value == "valid-token");
        }

        [Fact]
        public async Task HandleAuthenticateAsync_InvalidReplacedTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnRetrieveToken = context => {
                    context.Token = "invalid-token";

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ValidReplacedTokenCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnRetrieveToken = context => {
                    context.Token = "valid-token";

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SkipToNextMiddlewareFromReceiveTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnRetrieveToken = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NullTicketAndHandleResponseFromReceiveTokenCauseInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnRetrieveToken = context => {
                    context.Ticket = null;
                    context.HandleResponse();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ReplacedTicketAndHandleResponseFromReceiveTokenCauseSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnRetrieveToken = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.HandleResponse();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_SkipToNextMiddlewareFromValidateTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnValidateToken = context => {
                    context.SkipToNextMiddleware();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_NullTicketAndHandleResponseFromValidateTokenCauseInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnValidateToken = context => {
                    context.Ticket = null;
                    context.HandleResponse();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task HandleAuthenticateAsync_ReplacedTicketAndHandleResponseFromValidateTokenCauseSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnValidateToken = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Contoso"));

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.HandleResponse();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Contoso", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task HandleAuthenticateAsync_UpdatedTicketFromValidateTokenCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events.OnValidateToken = context => {
                    var identity = new ClaimsIdentity(context.Options.AuthenticationScheme);
                    identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Contoso"));

                    context.Ticket = new AuthenticationTicket(
                        new ClaimsPrincipal(identity),
                        new AuthenticationProperties(),
                        context.Options.AuthenticationScheme);

                    context.HandleResponse();

                    return Task.FromResult(0);
                };
            });

            var client = server.CreateClient();

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Contoso", await response.Content.ReadAsStringAsync());
        }

        private static TestServer CreateResourceServer(Action<OAuthIntrospectionOptions> configuration) {
            var server = CreateAuthorizationServer();

            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureServices(services => {
                services.AddAuthentication();
                services.AddDistributedMemoryCache();
            });

            builder.Configure(app => {
                app.UseOAuthIntrospection(options => {
                    options.AutomaticAuthenticate = true;
                    options.AutomaticChallenge = true;

                    options.Authority = server.BaseAddress.AbsoluteUri;
                    options.HttpClient = server.CreateClient();

                    // Note: overriding the default data protection provider is not necessary for the tests to pass,
                    // but is useful to ensure unnecessary keys are not persisted in testing environments, which also
                    // helps make the unit tests run faster, as no registry or disk access is required in this case.
                    options.DataProtectionProvider = new EphemeralDataProtectionProvider();

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Map("/ticket", map => map.Run(async context => {
                    var ticket = new AuthenticateContext(OAuthIntrospectionDefaults.AuthenticationScheme);
                    await context.Authentication.AuthenticateAsync(ticket);

                    if (!ticket.Accepted || ticket.Principal == null || ticket.Properties == null) {
                        await context.Authentication.ChallengeAsync();

                        return;
                    }

                    context.Response.ContentType = "application/json";

                    // Return the authentication ticket as a JSON object.
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        Claims = from claim in ticket.Principal.Claims
                                 select new { claim.Type, claim.Value },

                        Properties = from property in ticket.Properties
                                     select new { Name = property.Key, property.Value }
                    }));
                }));

                app.Run(context => {
                    if (!context.User.Identities.Any(identity => identity.IsAuthenticated)) {
                        return context.Authentication.ChallengeAsync();
                    }

                    return context.Response.WriteAsync(context.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                });
            });

            return new TestServer(builder);
        }

        private static TestServer CreateAuthorizationServer() {
            var builder = new WebHostBuilder();

            builder.UseEnvironment("Testing");

            builder.ConfigureLogging(options => options.AddDebug());

            builder.ConfigureServices(services => {
                services.AddAuthentication();
                services.AddDistributedMemoryCache();
                services.AddLogging();
            });

            builder.Configure(app => {
                app.Map("/.well-known/openid-configuration", map => map.Run(async context => {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                        var payload = new JObject {
                            [OAuthIntrospectionConstants.Metadata.IntrospectionEndpoint] = "http://localhost/connect/introspect"
                        };

                        payload.WriteTo(writer);
                        writer.Flush();

                        context.Response.ContentLength = buffer.Length;
                        context.Response.ContentType = "application/json;charset=UTF-8";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.RequestAborted);
                    }
                }));

                app.Map("/connect/introspect", map => map.Run(async context => {
                    using (var buffer = new MemoryStream())
                    using (var writer = new JsonTextWriter(new StreamWriter(buffer))) {
                        var payload = new JObject();
                        var form = await context.Request.ReadFormAsync();

                        switch (form[OAuthIntrospectionConstants.Parameters.Token]) {
                            case "invalid-token": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = false;

                                break;
                            }

                            case "expired-token": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                // 1451602800 = 01/01/2016 - 00:00:00 AM.
                                payload[OAuthIntrospectionConstants.Claims.ExpiresAt] = 1455359642;

                                break;
                            }

                            case "valid-token": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";

                                break;
                            }

                            case "valid-token-with-scopes": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Scope] =
                                    "C54A8F5E-0387-43F4-BA43-FD4B50DC190D 5C57E3BD-9EFB-4224-9AB8-C8C5E009FFD7";

                                break;
                            }

                            case "valid-token-with-single-audience": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = "http://www.google.com/";

                                break;
                            }

                            case "valid-token-with-multiple-audiences": {
                                payload[OAuthIntrospectionConstants.Claims.Active] = true;
                                payload[OAuthIntrospectionConstants.Claims.JwtId] = "jwt-token-identifier";
                                payload[OAuthIntrospectionConstants.Claims.Subject] = "Fabrikam";
                                payload[OAuthIntrospectionConstants.Claims.Audience] = JArray.FromObject(new[] {
                                    "http://www.google.com/", "http://www.fabrikam.com/"
                                });

                                break;
                            }
                        }

                        payload.WriteTo(writer);
                        writer.Flush();

                        context.Response.ContentLength = buffer.Length;
                        context.Response.ContentType = "application/json;charset=UTF-8";

                        buffer.Seek(offset: 0, loc: SeekOrigin.Begin);
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.RequestAborted);
                    }
                }));
            });

            return new TestServer(builder);
        }
    }
}
