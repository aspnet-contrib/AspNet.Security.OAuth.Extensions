/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Owin.Security.OpenIdConnect.Extensions;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationHandler : AuthenticationHandler<OAuthValidationOptions> {
        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync() {
            var header = Request.Headers.Get("Authorization");
            if (string.IsNullOrEmpty(header)) {
                Options.Logger.WriteError("Authentication failed because the bearer token " +
                                          "was missing from the 'Authorization' header.");

                return null;
            }

            // Ensure that the authorization header contains the mandatory "Bearer" scheme.
            // See https://tools.ietf.org/html/rfc6750#section-2.1
            if (!header.StartsWith("Bearer ", StringComparison.OrdinalIgnoreCase)) {
                Options.Logger.WriteError("Authentication failed because an invalid scheme " +
                                          "was used in the 'Authorization' header.");

                return null;
            }

            var token = header.Substring("Bearer ".Length);
            if (string.IsNullOrWhiteSpace(token)) {
                Options.Logger.WriteError("Authentication failed because the bearer token " +
                                          "was missing from the 'Authorization' header.");

                return null;
            }

            // Try to unprotect the token and return an error
            // if the ticket can't be decrypted or validated.
            var ticket = Options.TicketFormat.Unprotect(token);
            if (ticket == null) {
                Options.Logger.WriteError("Authentication failed because the access token was invalid.");

                return null;
            }

            // Ensure that the access token was issued
            // to be used with this resource server.
            if (!await ValidateAudienceAsync(ticket)) {
                Options.Logger.WriteError("Authentication failed because the access token " +
                                          "was not valid for this resource server.");

                return null;
            }

            // Ensure that the authentication ticket is still valid.
            if (ticket.Properties.ExpiresUtc.HasValue &&
                ticket.Properties.ExpiresUtc.Value < Options.SystemClock.UtcNow) {
                Options.Logger.WriteError("Authentication failed because the access token was expired.");

                return null;
            }

            return ticket;
        }

        protected virtual Task<bool> ValidateAudienceAsync(AuthenticationTicket ticket) {
            // If no explicit audience has been configured,
            // skip the default audience validation.
            if (string.IsNullOrEmpty(Options.Audience)) {
                return Task.FromResult(true);
            }

            // Ensure that the registered audience can be found in the
            // "audiences" property stored in the authentication ticket.
            var audiences = ticket.GetAudiences();
            if (audiences.Contains(Options.Audience, StringComparer.Ordinal)) {
                return Task.FromResult(true);
            }

            return Task.FromResult(false);
        }
    }
}
