using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(OwinMiddleware next, IAppBuilder app, OAuthValidationOptions options)
            : base(next, options) {
            if (options.TicketFormat == null) {
                // Note: the purposes of the default ticket
                // format must match the values used by ASOS.
                options.TicketFormat = new TicketDataFormat(
                    app.CreateDataProtector(
                        "Microsoft.Owin.Security.OAuth",
                        "Access_Token", "v1"));
            }

            if (options.Logger == null) {
                options.Logger = app.CreateLogger<OAuthValidationMiddleware>();
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            return new OAuthValidationHandler();
        }
    }
}
