/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Net.Http.Headers;
using Newtonsoft.Json.Linq;

namespace AspNet.Security.OAuth.Validation
{
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions>
    {
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            var context = new RetrieveTokenContext(Context, Options);
            await Options.Events.RetrieveToken(context);

            if (context.HandledResponse)
            {
                // If no ticket has been provided, return a failed result to
                // indicate that authentication was rejected by application code.
                if (context.Ticket == null)
                {
                    return AuthenticateResult.Fail("Authentication was stopped by application code.");
                }

                return AuthenticateResult.Success(context.Ticket);
            }

            else if (context.Skipped)
            {
                Logger.LogInformation("Authentication was skipped by application code.");

                return AuthenticateResult.Skip();
            }

            var token = context.Token;

            if (string.IsNullOrEmpty(token))
            {
                // Try to retrieve the access token from the authorization header.
                string header = Request.Headers[HeaderNames.Authorization];
                if (string.IsNullOrEmpty(header))
                {
                    Logger.LogDebug("Authentication was skipped because no bearer token was received.");

                    return AuthenticateResult.Skip();
                }

                // Ensure that the authorization header contains the mandatory "Bearer" scheme.
                // See https://tools.ietf.org/html/rfc6750#section-2.1
                if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase))
                {
                    Logger.LogDebug("Authentication was skipped because an incompatible " +
                                    "scheme was used in the 'Authorization' header.");

                    return AuthenticateResult.Skip();
                }

                // Extract the token from the authorization header.
                token = header.Substring("Bearer ".Length).Trim();

                if (string.IsNullOrEmpty(token))
                {
                    Logger.LogDebug("Authentication was skipped because the bearer token " +
                                    "was missing from the 'Authorization' header.");

                    return AuthenticateResult.Skip();
                }
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = await CreateTicketAsync(token);
            if (ticket == null)
            {
                return AuthenticateResult.Fail("Authentication failed because the access token was invalid.");
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!ValidateAudience(ticket))
            {
                return AuthenticateResult.Fail("Authentication failed because the access token " +
                                               "was not valid for this resource server.");
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow)
            {
                return AuthenticateResult.Fail("Authentication failed because the access token was expired.");
            }

            var notification = new ValidateTokenContext(Context, Options, ticket);
            await Options.Events.ValidateToken(notification);

            if (notification.HandledResponse)
            {
                // If no ticket has been provided, return a failed result to
                // indicate that authentication was rejected by application code.
                if (notification.Ticket == null)
                {
                    return AuthenticateResult.Fail("Authentication was stopped by application code.");
                }

                return AuthenticateResult.Success(notification.Ticket);
            }

            else if (notification.Skipped)
            {
                Logger.LogInformation("Authentication was skipped by application code.");

                return AuthenticateResult.Skip();
            }

            // Allow the application code to replace the ticket
            // reference from the ValidateToken event.
            ticket = notification.Ticket;

            if (ticket == null)
            {
                return AuthenticateResult.Fail("Authentication was stopped by application code.");
            }

            return AuthenticateResult.Success(ticket);
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
            if (!ticket.Properties.Items.TryGetValue(OAuthValidationConstants.Properties.Audiences, out audiences))
            {
                return false;
            }

            if (string.IsNullOrEmpty(audiences))
            {
                return false;
            }

            // Ensure that the authentication ticket contains one of the registered audiences.
            foreach (var audience in JArray.Parse(audiences).Values<string>())
            {
                if (string.IsNullOrEmpty(audience))
                {
                    continue;
                }

                if (Options.Audiences.Contains(audience))
                {
                    return true;
                }
            }

            return false;
        }

        protected virtual async Task<AuthenticationTicket> CreateTicketAsync(string token)
        {
            var ticket = Options.AccessTokenFormat.Unprotect(token);
            if (ticket == null)
            {
                return null;
            }

            if (Options.SaveToken)
            {
                // Store the access token in the authentication ticket.
                ticket.Properties.StoreTokens(new[]
                {
                    new AuthenticationToken { Name = OAuthValidationConstants.Properties.Token, Value = token }
                });
            }

            // Resolve the primary identity associated with the principal.
            var identity = (ClaimsIdentity) ticket.Principal.Identity;

            string scopes;
            // Copy the scopes extracted from the authentication ticket to the
            // ClaimsIdentity to make them easier to retrieve from application code.
            if (ticket.Properties.Items.TryGetValue(OAuthValidationConstants.Properties.Scopes, out scopes))
            {
                foreach (var scope in JArray.Parse(scopes).Values<string>())
                {
                    if (string.IsNullOrEmpty(scope))
                    {
                        continue;
                    }

                    identity.AddClaim(new Claim(OAuthValidationConstants.Claims.Scope, scope));
                }
            }

            var notification = new CreateTicketContext(Context, Options, ticket);
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
    }
}
