using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationOptions : AuthenticationOptions {
        public OAuthValidationOptions()
            : base(OAuthValidationDefaults.AuthenticationScheme) {
        }

        /// <summary>
        /// Gets or sets the intended audience of this resource server.
        /// Setting this property is recommended when the authorization
        /// server issues access tokens for multiple distinct resource servers.
        /// </summary>
        public string Audience { get; set; }

        /// <summary>
        /// Gets or sets the logger used by <see cref="OAuthValidationMiddleware"/>.
        /// When unassigned, a default instance is created using the logger factory.
        /// </summary>
        public ILogger Logger { get; set; }

        /// <summary>
        /// Gets or sets the clock used to determine the current date/time.
        /// </summary>
        public ISystemClock SystemClock { get; set; } = new SystemClock();

        /// <summary>
        /// Gets or sets the data format used to unprotect the
        /// authenticated tickets received by the validation middleware.
        /// </summary>
        public ISecureDataFormat<AuthenticationTicket> TicketFormat { get; set; }
    }
}
