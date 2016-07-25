/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net.Http;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.Extensions.Caching.Distributed;
using Microsoft.Extensions.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.OAuth.Introspection
{
    public class OAuthIntrospectionHandler : AuthenticationHandler<OAuthIntrospectionOptions>
    {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            var context = new RetrieveTokenContext(Context, Options);
            await Options.Events.RetrieveToken(context);

            if (context.HandledResponse)
            {
                // If no ticket has been provided, return a failed result to
                // indicate that authentication was rejected by application code.
                if (context.Ticket == null)
                {
                    Options.Logger.LogInformation("Authentication was stopped by application code.");

                    return null;
                }

                return context.Ticket;
            }

            else if (context.Skipped)
            {
                Options.Logger.LogInformation("Authentication was skipped by application code.");

                return null;
            }

            var token = context.Token;

            if (string.IsNullOrEmpty(token))
            {
                // Try to retrieve the access token from the authorization header.
                var header = Request.Headers[OAuthIntrospectionConstants.Headers.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Options.Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return null;
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith(OAuthIntrospectionConstants.Schemes.Bearer + ' ', StringComparison.OrdinalIgnoreCase))
                {
                    Options.Logger.LogDebug("Authentication was skipped because an incompatible " +
                                            "scheme was used in the 'Authorization' header.");

                    return null;
                }

                // Extract the token from the authorization header.
                token = header.Substring(OAuthIntrospectionConstants.Schemes.Bearer.Length + 1).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Options.Logger.LogDebug("Authentication was skipped because the bearer token " +
                                            "was missing from the 'Authorization' header.");

                    return null;
                }
            }

            // Try to resolve the authentication ticket from the distributed cache. If none
            // can be found, a new introspection request is sent to the authorization server.
            var ticket = await RetrieveTicketAsync(token);
            if (ticket == null)
            {
                // Return a failed authentication result if the introspection
                // request failed or if the "active" claim was false.
                var payload = await GetIntrospectionPayloadAsync(token);
                if (payload == null || !payload.Value<bool>(OAuthIntrospectionConstants.Claims.Active))
                {
                    Options.Logger.LogError("Authentication failed because the authorization " +
                                            "server rejected the access token.");

                    Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                    {
                        Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                        ErrorDescription = "The access token is not valid."
                    });

                    return null;
                }

                // Create a new authentication ticket from the introspection
                // response returned by the authorization server.
                ticket = await CreateTicketAsync(token, payload);
                Debug.Assert(ticket != null);

                await StoreTicketAsync(token, ticket);
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                Options.Logger.LogError("Authentication failed because the access token was expired.");

                Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                {
                    Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is expired."
                });

                return null;
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!ValidateAudience(ticket))
            {
                Options.Logger.LogError("Authentication failed because the access token " +
                                        "was not valid for this resource server.");

                Context.Set(typeof(OAuthIntrospectionError).FullName, new OAuthIntrospectionError
                {
                    Error = OAuthIntrospectionConstants.Errors.InvalidToken,
                    ErrorDescription = "The access token is not valid for this resource server."
                });

                return null;
            }

            var notification = new ValidateTokenContext(Context, Options, ticket);
            await Options.Events.ValidateToken(notification);

            if (notification.HandledResponse)
            {
                // If no ticket has been provided, return a failed result to
                // indicate that authentication was rejected by application code.
                if (notification.Ticket == null)
                {
                    Options.Logger.LogInformation("Authentication was stopped by application code.");

                    return null;
                }

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                Options.Logger.LogInformation("Authentication was skipped by application code.");

                return null;
            }

            // Allow the application code to replace the ticket
            // reference from the ValidateToken event.
            return notification.Ticket;
        }

        protected override async Task ApplyResponseChallengeAsync()
        {
            var context = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);
            if (context == null || Response.StatusCode != 401)
            {
                return;
            }

            Response.StatusCode = 200;

            // Note: always return the error/error_description/error_uri/realm/scope specified
            // in the authentication properties even if IncludeErrorDetails is set to false.
            var notification = new ApplyChallengeContext(Context, Options, context.Properties)
            {
                Error = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Error),
                ErrorDescription = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.ErrorDescription),
                ErrorUri = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.ErrorUri),
                Realm = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Realm),
                Scope = context.Properties.GetProperty(OAuthIntrospectionConstants.Properties.Scope),
            };

            // If an error was stored by HandleAuthenticateAsync,
            // add the corresponding details to the notification.
            var error = Context.Get<OAuthIntrospectionError>(typeof(OAuthIntrospectionError).FullName);
            if (error != null && Options.IncludeErrorDetails)
            {
                // If no error was specified in the authentication properties,
                // try to use the error returned from HandleAuthenticateAsync.
                if (string.IsNullOrEmpty(notification.Error))
                {
                    notification.Error = error.Error;
                }

                // If no error_description was specified in the authentication properties,
                // try to use the error_description returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.ErrorDescription))
                {
                    notification.ErrorDescription = error.ErrorDescription;
                }

                // If no error_uri was specified in the authentication properties,
                // try to use the error_uri returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.ErrorUri))
                {
                    notification.ErrorUri = error.ErrorUri;
                }

                // If no realm was specified in the authentication properties,
                // try to use the realm returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.Realm))
                {
                    notification.Realm = error.Realm;
                }

                // If no scope was specified in the authentication properties,
                // try to use the scope returned from AuthenticateCoreAsync.
                if (string.IsNullOrEmpty(notification.Scope))
                {
                    notification.Scope = error.Scope;
                }
            }

            // At this stage, if no realm was provided, try to
            // fallback to the realm registered in the options.
            if (string.IsNullOrEmpty(notification.Realm))
            {
                notification.Realm = Options.Realm;
            }

            await Options.Events.ApplyChallenge(notification);

            if (notification.HandledResponse || notification.Skipped)
            {
                return;
            }

            Response.StatusCode = 401;

            // Optimization: avoid allocating a StringBuilder if the
            // WWW-Authenticate header doesn't contain any parameter.
            if (string.IsNullOrEmpty(notification.Realm) &&
                string.IsNullOrEmpty(notification.Error) &&
                string.IsNullOrEmpty(notification.ErrorDescription) &&
                string.IsNullOrEmpty(notification.ErrorUri) &&
                string.IsNullOrEmpty(notification.Scope))
            {
                Response.Headers.Append(OAuthIntrospectionConstants.Headers.WWWAuthenticate,
                                        OAuthIntrospectionConstants.Schemes.Bearer);
            }

            else
            {
                var builder = new StringBuilder(OAuthIntrospectionConstants.Schemes.Bearer);

                // Append the realm if one was specified.
                if (!string.IsNullOrEmpty(notification.Realm))
                {
                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Realm);
                    builder.Append("=\"");
                    builder.Append(notification.Realm);
                    builder.Append('"');
                }

                // Append the error if one was specified.
                if (!string.IsNullOrEmpty(notification.Error))
                {
                    if (!string.IsNullOrEmpty(notification.Realm))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Error);
                    builder.Append("=\"");
                    builder.Append(notification.Error);
                    builder.Append('"');
                }

                // Append the error_description if one was specified.
                if (!string.IsNullOrEmpty(notification.ErrorDescription))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.ErrorDescription);
                    builder.Append("=\"");
                    builder.Append(notification.ErrorDescription);
                    builder.Append('"');
                }

                // Append the error_uri if one was specified.
                if (!string.IsNullOrEmpty(notification.ErrorUri))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error) ||
                        !string.IsNullOrEmpty(notification.ErrorDescription))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.ErrorUri);
                    builder.Append("=\"");
                    builder.Append(notification.ErrorUri);
                    builder.Append('"');
                }

                // Append the scope if one was specified.
                if (!string.IsNullOrEmpty(notification.Scope))
                {
                    if (!string.IsNullOrEmpty(notification.Realm) ||
                        !string.IsNullOrEmpty(notification.Error) ||
                        !string.IsNullOrEmpty(notification.ErrorDescription) ||
                        !string.IsNullOrEmpty(notification.ErrorUri))
                    {
                        builder.Append(',');
                    }

                    builder.Append(' ');
                    builder.Append(OAuthIntrospectionConstants.Parameters.Scope);
                    builder.Append("=\"");
                    builder.Append(notification.Scope);
                    builder.Append('"');
                }

                Response.Headers.Append(OAuthIntrospectionConstants.Headers.WWWAuthenticate, builder.ToString());
            }
        }

        protected virtual async Task<string> ResolveIntrospectionEndpointAsync(string issuer)
        {
            if (issuer.EndsWith("/"))
            {
                issuer = issuer.Substring(0, issuer.Length - 1);
            }

            // Create a new discovery request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Get, issuer + "/.well-known/openid-configuration");
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Request.CallCancelled);
            if (!response.IsSuccessStatusCode)
            {
                Options.Logger.LogError("An error occurred when retrieving the issuer metadata: the remote server " +
                                        "returned a {Status} response with the following payload: {Headers} {Body}.",
                                        /* Status: */ response.StatusCode,
                                        /* Headers: */ response.Headers.ToString(),
                                        /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            var payload = JObject.Parse(await response.Content.ReadAsStringAsync());

            var address = payload[OAuthIntrospectionConstants.Metadata.IntrospectionEndpoint];
            if (address == null)
            {
                return null;
            }

            return (string) address;
        }

        protected virtual async Task<JObject> GetIntrospectionPayloadAsync(string token)
        {
            // Note: updating the options during a request is not thread safe but is harmless in this case:
            // in the worst case, it will only send multiple configuration requests to the authorization server.
            if (string.IsNullOrEmpty(Options.IntrospectionEndpoint))
            {
                Options.IntrospectionEndpoint = await ResolveIntrospectionEndpointAsync(Options.Authority);
            }

            if (string.IsNullOrEmpty(Options.IntrospectionEndpoint))
            {
                throw new InvalidOperationException("The OAuth2 introspection middleware was unable to retrieve " +
                                                    "the provider configuration from the OAuth2 authorization server.");
            }

            var credentials = Convert.ToBase64String(Encoding.ASCII.GetBytes($"{Options.ClientId}:{Options.ClientSecret}"));

            // Create a new introspection request containing the access token and the client credentials.
            var request = new HttpRequestMessage(HttpMethod.Post, Options.IntrospectionEndpoint);
            request.Headers.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            request.Headers.Authorization = new AuthenticationHeaderValue("Basic", credentials);

            request.Content = new FormUrlEncodedContent(new Dictionary<string, string>
            {
                [OAuthIntrospectionConstants.Parameters.Token] = token,
                [OAuthIntrospectionConstants.Parameters.TokenTypeHint] = OAuthIntrospectionConstants.TokenTypes.AccessToken
            });

            var notification = new RequestTokenIntrospectionContext(Context, Options, request, token);
            await Options.Events.RequestTokenIntrospection(notification);

            var response = await Options.HttpClient.SendAsync(request, HttpCompletionOption.ResponseHeadersRead, Request.CallCancelled);
            if (!response.IsSuccessStatusCode)
            {
                Options.Logger.LogError("An error occurred when validating an access token: the remote server " +
                                        "returned a {Status} response with the following payload: {Headers} {Body}.",
                                        /* Status: */ response.StatusCode,
                                        /* Headers: */ response.Headers.ToString(),
                                        /* Body: */ await response.Content.ReadAsStringAsync());

                return null;
            }

            return JObject.Parse(await response.Content.ReadAsStringAsync());
        }

        protected virtual bool ValidateAudience(AuthenticationTicket ticket)
        {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (Options.Audiences.Count == 0)
            {
                return true;
            }

            string audiences;
            // Extract the audiences from the authentication ticket.
            if (!ticket.Properties.Dictionary.TryGetValue(OAuthIntrospectionConstants.Properties.Audiences, out audiences))
            {
                return false;
            }

            // Ensure that the authentication ticket contains one of the registered audiences.
            foreach (var audience in JArray.Parse(audiences).Values<string>())
            {
                if (Options.Audiences.Contains(audience))
                {
                    return true;
                }
            }

            return false;
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(string token, JObject payload)
        {
            var identity = new ClaimsIdentity(Options.AuthenticationType);
            var properties = new AuthenticationProperties();

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                properties.Dictionary[OAuthIntrospectionConstants.Properties.Token] = token;
            }

            foreach (var property in payload.Properties())
            {
                switch (property.Name)
                {
                    // Ignore the unwanted claims.
                    case OAuthIntrospectionConstants.Claims.Active:
                    case OAuthIntrospectionConstants.Claims.TokenType:
                    case OAuthIntrospectionConstants.Claims.NotBefore:
                        continue;

                    case OAuthIntrospectionConstants.Claims.IssuedAt:
                    {
                        properties.IssuedUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                               TimeSpan.FromSeconds((long) property.Value);
                        continue;
                    }

                    case OAuthIntrospectionConstants.Claims.ExpiresAt:
                    {
                        properties.ExpiresUtc = new DateTimeOffset(1970, 1, 1, 0, 0, 0, 0, TimeSpan.Zero) +
                                                TimeSpan.FromSeconds((long) property.Value);

                        continue;
                    }

                    // Add the subject identifier as a new ClaimTypes.NameIdentifier claim.
                    case OAuthIntrospectionConstants.Claims.Subject:
                    {
                        identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, (string) property.Value));

                        continue;
                    }

                    // Add the subject identifier as a new ClaimTypes.Name claim.
                    case OAuthIntrospectionConstants.Claims.Username:
                    {
                        identity.AddClaim(new Claim(ClaimTypes.Name, (string) property.Value));

                        continue;
                    }

                    // Add the token identifier as a property on the authentication ticket.
                    case OAuthIntrospectionConstants.Claims.JwtId:
                    {
                        properties.Dictionary[OAuthIntrospectionConstants.Properties.TicketId] = (string) property;

                        continue;
                    }

                    // Extract the scope values from the space-delimited
                    // "scope" claim and store them as individual claims.
                    // See https://tools.ietf.org/html/rfc7662#section-2.2
                    case OAuthIntrospectionConstants.Claims.Scope:
                    {
                        var scopes = (string) property.Value;

                        // Store the scopes list in the authentication properties.
                        properties.Dictionary[OAuthIntrospectionConstants.Properties.Scopes] =
                            new JArray(scopes.Split(' ')).ToString(Formatting.None);

                        foreach (var scope in scopes.Split(' '))
                        {
                            identity.AddClaim(new Claim(property.Name, scope));
                        }

                        continue;
                    }

                    // Store the audience(s) in the ticket properties.
                    // Note: the "aud" claim may be either a list of strings or a unique string.
                    // See https://tools.ietf.org/html/rfc7662#section-2.2
                    case OAuthIntrospectionConstants.Claims.Audience:
                    {
                        if (property.Value.Type == JTokenType.Array)
                        {
                            var value = (JArray) property.Value;
                            if (value == null)
                            {
                                continue;
                            }

                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] = value.ToString(Formatting.None);
                        }

                        else if (property.Value.Type == JTokenType.String)
                        {
                            properties.Dictionary[OAuthIntrospectionConstants.Properties.Audiences] =
                                new JArray((string) property.Value).ToString(Formatting.None);
                        }

                        continue;
                    }
                }

                switch (property.Value.Type)
                {
                    // Ignore null values.
                    case JTokenType.None:
                    case JTokenType.Null:
                        continue;

                    case JTokenType.Array:
                    {
                        foreach (var item in (JArray) property.Value)
                        {
                            identity.AddClaim(new Claim(property.Name, (string) item));
                        }

                        continue;
                    }

                    case JTokenType.String:
                    {
                        identity.AddClaim(new Claim(property.Name, (string) property.Value));

                        continue;
                    }

                    case JTokenType.Integer:
                    {
                        identity.AddClaim(new Claim(property.Name, (string) property.Value, ClaimValueTypes.Integer));

                        continue;
                    }
                }
            }

            // Create a new authentication ticket containing the identity
            // built from the claims returned by the authorization server.
            var ticket = new AuthenticationTicket(identity, properties);

            var notification = new CreateTicketContext(Context, Options, ticket, payload);
            await Options.Events.CreateTicket(notification);

            if (notification.HandledResponse)
            {
                // If no ticket has been provided, return a failed result to
                // indicate that authentication was rejected by application code.
                if (notification.Ticket == null)
                {
                    return null;
                }

                return notification.Ticket;
            }

            else if (notification.Skipped)
            {
                return null;
            }

            return notification.Ticket;
        }

        protected virtual Task StoreTicketAsync(string token, AuthenticationTicket ticket)
        {
            var bytes = Encoding.UTF8.GetBytes(Options.AccessTokenFormat.Protect(ticket));
            Debug.Assert(bytes != null);

            return Options.Cache.SetAsync(token, bytes, new DistributedCacheEntryOptions
            {
                AbsoluteExpiration = Options.SystemClock.UtcNow + TimeSpan.FromMinutes(15)
            });
        }

        protected virtual async Task<AuthenticationTicket> RetrieveTicketAsync(string token)
        {
            // Retrieve the serialized ticket from the distributed cache.
            // If no corresponding entry can be found, null is returned.
            var bytes = await Options.Cache.GetAsync(token);
            if (bytes == null)
            {
                return null;
            }

            return Options.AccessTokenFormat.Unprotect(Encoding.UTF8.GetString(bytes));
        }
    }
}
