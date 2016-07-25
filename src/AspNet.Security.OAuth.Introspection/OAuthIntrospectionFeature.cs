namespace AspNet.Security.OAuth.Introspection
{
    /// <summary>
    /// Exposes the OAuth2 introspection details
    /// associated with the current request.
    /// </summary>
    public class OAuthIntrospectionFeature
    {
        /// <summary>
        /// Gets or sets the error details returned
        /// as part of the challenge response.
        /// </summary>
        public OAuthIntrospectionError Error { get; set; }
    }
}
