namespace AspNet.Security.OAuth.Validation
{
    /// <summary>
    /// Exposes the OAuth2 validation details
    /// associated with the current request.
    /// </summary>
    public class OAuthValidationFeature
    {
        /// <summary>
        /// Gets or sets the error details returned
        /// as part of the challenge response.
        /// </summary>
        public OAuthValidationError Error { get; set; }
    }
}
