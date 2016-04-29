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
using System.Reflection;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin.Security;
using Microsoft.Owin.Testing;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;
using Xunit;

namespace Owin.Security.OAuth.Introspection.Tests {
    public class OAuthIntrospectionMiddlewareTests {
        [Fact]
        public void MissingAuthorityThrowsAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = null;
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("The authority or the introspection endpoint must be configured.", exception.InnerException.Message);
        }

        [Fact]
        public void MissingCredentialsThrowAnException() {
            // Arrange, act, assert
            var exception = Assert.Throws<TargetInvocationException>(() => CreateResourceServer(options => {
                options.Authority = "http://www.fabrikam.com/";
            }));

            Assert.NotNull(exception.InnerException);
            Assert.IsType<ArgumentException>(exception.InnerException);
            Assert.StartsWith("Client credentials must be configured.", exception.InnerException.Message);
        }

        [Fact]
        public async Task MissingTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidTokenAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task MissingAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task InvalidAudienceCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue(
                "Bearer", "valid-token-with-single-audience");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AnyMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

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
        public async Task ValidAudienceAllowsSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

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
        public async Task MultipleMatchingAudienceCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.Audiences.Add("http://www.fabrikam.com/");
                options.Audiences.Add("http://www.google.com/");
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

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
        public async Task ExpiredTicketCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "expired-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task AuthenticationTicketContainsRequiredClaims() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
            });

            var client = server.HttpClient;

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
        public async Task AuthenticationTicketContainsRequiredProperties() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";
                options.SaveToken = true;
            });

            var client = server.HttpClient;

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

            Assert.Contains(properties, property => property.Name == "access_token" &&
                                                    property.Value == "valid-token");
        }

        [Fact]
        public async Task InvalidReplacedTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnRetrieveToken = context => {
                        context.Token = "invalid-token";

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ValidReplacedTokenCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnRetrieveToken = context => {
                        context.Token = "valid-token";

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task SkipToNextMiddlewareFromReceiveTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnRetrieveToken = context => {
                        context.SkipToNextMiddleware();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task NullTicketAndHandleResponseFromReceiveTokenCauseInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnRetrieveToken = context => {
                        context.Ticket = null;
                        context.HandleResponse();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ReplacedTicketAndHandleResponseFromReceiveTokenCauseSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnRetrieveToken = context => {
                        var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Fabrikam"));

                        context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());

                        context.HandleResponse();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "invalid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Fabrikam", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task SkipToNextMiddlewareFromValidateTokenCausesInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        context.SkipToNextMiddleware();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task NullTicketAndHandleResponseFromValidateTokenCauseInvalidAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        context.Ticket = null;
                        context.HandleResponse();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
        }

        [Fact]
        public async Task ReplacedTicketAndHandleResponseFromValidateTokenCauseSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Contoso"));

                        context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                        context.HandleResponse();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

            var request = new HttpRequestMessage(HttpMethod.Get, "/");
            request.Headers.Authorization = new AuthenticationHeaderValue("Bearer", "valid-token");

            // Act
            var response = await client.SendAsync(request);

            // Assert
            Assert.Equal(HttpStatusCode.OK, response.StatusCode);
            Assert.Equal("Contoso", await response.Content.ReadAsStringAsync());
        }

        [Fact]
        public async Task UpdatedTicketFromValidateTokenCausesSuccessfulAuthentication() {
            // Arrange
            var server = CreateResourceServer(options => {
                options.ClientId = "Fabrikam";
                options.ClientSecret = "B4657E03-D619";

                options.Events = new OAuthIntrospectionEvents {
                    OnValidateToken = context => {
                        var identity = new ClaimsIdentity(context.Options.AuthenticationType);
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "Contoso"));

                        context.Ticket = new AuthenticationTicket(identity, new AuthenticationProperties());
                        context.HandleResponse();

                        return Task.FromResult(0);
                    }
                };
            });

            var client = server.HttpClient;

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

            return TestServer.Create(app => {
                app.UseOAuthIntrospection(options => {
                    options.AuthenticationMode = AuthenticationMode.Active;

                    options.Authority = server.BaseAddress.AbsoluteUri;
                    options.HttpClient = server.HttpClient;

                    // Run the configuration delegate
                    // registered by the unit tests.
                    configuration?.Invoke(options);
                });

                app.Map("/ticket", map => map.Run(async context => {
                    var ticket = await context.Authentication.AuthenticateAsync(OAuthIntrospectionDefaults.AuthenticationScheme);
                    if (ticket == null) {
                        context.Authentication.Challenge();

                        return;
                    }

                    context.Response.ContentType = "application/json";

                    // Return the authentication ticket as a JSON object.
                    await context.Response.WriteAsync(JsonConvert.SerializeObject(new {
                        Claims = from claim in ticket.Identity.Claims
                                 select new { claim.Type, claim.Value },

                        Properties = from property in ticket.Properties.Dictionary
                                     select new { Name = property.Key, property.Value }
                    }));
                }));

                app.Run(context => {
                    if (context.Authentication.User == null ||
                       !context.Authentication.User.Identities.Any(identity => identity.IsAuthenticated)) {
                        context.Authentication.Challenge();

                        return Task.FromResult(0);
                    }

                    return context.Response.WriteAsync(context.Authentication.User.FindFirst(ClaimTypes.NameIdentifier)?.Value);
                });
            });
        }

        private static TestServer CreateAuthorizationServer() {
            return TestServer.Create(app => {
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
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.Request.CallCancelled);
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
                        await buffer.CopyToAsync(context.Response.Body, 4096, context.Request.CallCancelled);
                    }
                }));
            });
        }
    }
}
