/*
 * Licensed under the Apache License, Version 2.0 (http://www.apache.org/licenses/LICENSE-2.0)
 * See https://github.com/aspnet-contrib/AspNet.Security.OAuth.Extensions for more information
 * concerning the license and the contributors participating to this project.
 */

using System;
using System.IdentityModel.Tokens;
using System.IO;
using System.Linq;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.DataHandler;
using Microsoft.Owin.Security.DataHandler.Encoder;
using Microsoft.Owin.Security.DataHandler.Serializer;
using Microsoft.Owin.Security.DataProtection;
using Microsoft.Owin.Security.Infrastructure;

namespace Owin.Security.OAuth.Validation {
    public class OAuthValidationMiddleware : AuthenticationMiddleware<OAuthValidationOptions> {
        public OAuthValidationMiddleware(OwinMiddleware next, IAppBuilder app, OAuthValidationOptions options)
            : base(next, options) {
            if (options.TicketFormat == null) {
                // Note: the purposes of the default ticket
                // format must match the values used by ASOS.
                options.TicketFormat = new EnhancedTicketDataFormat(
                    app.CreateDataProtector(
                        "Owin.Security.OpenIdConnect.Server.OpenIdConnectServerMiddleware",
                        "oidc-server", "Access_Token", "v1"));
            }

            if (options.Logger == null) {
                options.Logger = app.CreateLogger<OAuthValidationMiddleware>();
            }
        }

        protected override AuthenticationHandler<OAuthValidationOptions> CreateHandler() {
            return new OAuthValidationHandler();
        }

        internal sealed class EnhancedTicketDataFormat : SecureDataFormat<AuthenticationTicket> {
            private static readonly EnhancedTicketSerializer Serializer = new EnhancedTicketSerializer();

            public EnhancedTicketDataFormat(IDataProtector protector)
                : base(Serializer, protector, TextEncodings.Base64Url) {
            }

            private sealed class EnhancedTicketSerializer : IDataSerializer<AuthenticationTicket> {
                private const int FormatVersion = 3;

                public byte[] Serialize(AuthenticationTicket model) {
                    if (model == null) {
                        throw new ArgumentNullException("model");
                    }

                    using (var buffer = new MemoryStream())
                    using (var writer = new BinaryWriter(buffer)) {
                        writer.Write(FormatVersion);

                        WriteIdentity(writer, model.Identity);
                        PropertiesSerializer.Write(writer, model.Properties);

                        return buffer.ToArray();
                    }
                }

                public AuthenticationTicket Deserialize(byte[] data) {
                    if (data == null) {
                        throw new ArgumentNullException("data");
                    }

                    using (var buffer = new MemoryStream(data))
                    using (var reader = new BinaryReader(buffer)) {
                        if (reader.ReadInt32() != FormatVersion) {
                            return null;
                        }

                        var identity = ReadIdentity(reader);
                        var properties = PropertiesSerializer.Read(reader);

                        return new AuthenticationTicket(identity, properties);
                    }
                }

                private static void WriteIdentity(BinaryWriter writer, ClaimsIdentity identity) {
                    writer.Write(identity.AuthenticationType);
                    WriteWithDefault(writer, identity.NameClaimType, DefaultValues.NameClaimType);
                    WriteWithDefault(writer, identity.RoleClaimType, DefaultValues.RoleClaimType);
                    writer.Write(identity.Claims.Count());

                    foreach (var claim in identity.Claims) {
                        WriteClaim(writer, claim, identity.NameClaimType);
                    }

                    var context = identity.BootstrapContext as BootstrapContext;
                    if (context == null || string.IsNullOrEmpty(context.Token)) {
                        writer.Write(0);
                    }

                    else {
                        writer.Write(context.Token.Length);
                        writer.Write(context.Token);
                    }

                    if (identity.Actor != null) {
                        writer.Write(true);
                        WriteIdentity(writer, identity.Actor);
                    }

                    else {
                        writer.Write(false);
                    }
                }

                private static ClaimsIdentity ReadIdentity(BinaryReader reader) {
                    var authenticationType = reader.ReadString();
                    var nameClaimType = ReadWithDefault(reader, DefaultValues.NameClaimType);
                    var roleClaimType = ReadWithDefault(reader, DefaultValues.RoleClaimType);
                    var count = reader.ReadInt32();

                    var claims = new Claim[count];

                    for (int index = 0; index != count; ++index) {
                        claims[index] = ReadClaim(reader, nameClaimType);
                    }

                    var identity = new ClaimsIdentity(claims, authenticationType, nameClaimType, roleClaimType);

                    int bootstrapContextSize = reader.ReadInt32();
                    if (bootstrapContextSize > 0) {
                        identity.BootstrapContext = new BootstrapContext(reader.ReadString());
                    }

                    if (reader.ReadBoolean()) {
                        identity.Actor = ReadIdentity(reader);
                    }

                    return identity;
                }

                private static void WriteClaim(BinaryWriter writer, Claim claim, string nameClaimType) {
                    WriteWithDefault(writer, claim.Type, nameClaimType);
                    writer.Write(claim.Value);
                    WriteWithDefault(writer, claim.ValueType, DefaultValues.StringValueType);
                    WriteWithDefault(writer, claim.Issuer, DefaultValues.LocalAuthority);
                    WriteWithDefault(writer, claim.OriginalIssuer, claim.Issuer);
                    writer.Write(claim.Properties.Count);

                    foreach (var property in claim.Properties) {
                        writer.Write(property.Key);
                        writer.Write(property.Value);
                    }
                }

                private static Claim ReadClaim(BinaryReader reader, string nameClaimType) {
                    var type = ReadWithDefault(reader, nameClaimType);
                    var value = reader.ReadString();
                    var valueType = ReadWithDefault(reader, DefaultValues.StringValueType);
                    var issuer = ReadWithDefault(reader, DefaultValues.LocalAuthority);
                    var originalIssuer = ReadWithDefault(reader, issuer);
                    var count = reader.ReadInt32();

                    var claim = new Claim(type, value, valueType, issuer, originalIssuer);

                    for (var index = 0; index != count; ++index) {
                        claim.Properties.Add(key: reader.ReadString(), value: reader.ReadString());
                    }

                    return claim;
                }

                private static void WriteWithDefault(BinaryWriter writer, string value, string defaultValue) {
                    if (string.Equals(value, defaultValue, StringComparison.Ordinal)) {
                        writer.Write(DefaultValues.DefaultStringPlaceholder);
                    }

                    else {
                        writer.Write(value);
                    }
                }

                private static string ReadWithDefault(BinaryReader reader, string defaultValue) {
                    string value = reader.ReadString();
                    if (string.Equals(value, DefaultValues.DefaultStringPlaceholder, StringComparison.Ordinal)) {
                        return defaultValue;
                    }

                    return value;
                }

                private static class DefaultValues {
                    public const string DefaultStringPlaceholder = "\0";
                    public const string NameClaimType = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/name";
                    public const string RoleClaimType = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
                    public const string LocalAuthority = "LOCAL AUTHORITY";
                    public const string StringValueType = "http://www.w3.org/2001/XMLSchema#string";
                }
            }
        }
    }
}
