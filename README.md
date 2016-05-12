AspNet.Security.OAuth.Extensions
================================

**AspNet.Security.OAuth.Extensions** is a collection of **token validation middleware** for ASP.NET Core 1.0 and OWIN/Katana.

**The latest nightly builds can be found on [MyGet](https://www.myget.org/gallery/aspnet-contrib)**.

[![Build status](https://ci.appveyor.com/api/projects/status/aa7t5nfxpiri1e85/branch/release?svg=true)](https://ci.appveyor.com/project/aspnet-contrib/aspnet-security-oauth-extensions/branch/release)
[![Build status](https://travis-ci.org/aspnet-contrib/AspNet.Security.OAuth.Extensions.svg?branch=release)](https://travis-ci.org/aspnet-contrib/AspNet.Security.OAuth.Extensions)

## Get started

```csharp
app.UseOAuthValidation(options => {
    options.Audiences.Add("resource_server");
});
```

```csharp
app.UseOAuthIntrospection(options => {
    options.AutomaticAuthenticate = true;
    options.AutomaticChallenge = true;
    options.Audiences.Add("resource_server");
    options.Authority = "http://localhost:54540/";
    options.ClientId = "resource_server";
    options.ClientSecret = "875sqd4s5d748z78z7ds1ff8zz8814ff88ed8ea4z4zzd";
});
```

## Support

**Need help or wanna share your thoughts?** Don't hesitate to join our dedicated chat rooms:

- **JabbR: [https://jabbr.net/#/rooms/aspnet-contrib](https://jabbr.net/#/rooms/aspnet-contrib)**
- **Gitter: [https://gitter.im/aspnet-contrib/AspNet.Security.OAuth.Extensions](https://gitter.im/aspnet-contrib/AspNet.Security.OAuth.Extensions)**

## Contributors

**AspNet.Security.OAuth.Extensions** is actively maintained by **[Kévin Chalet](https://github.com/PinpointTownes)**. Contributions are welcome and can be submitted using pull requests.

## License

This project is licensed under the **Apache License**. This means that you can use, modify and distribute it freely. See [http://www.apache.org/licenses/LICENSE-2.0.html](http://www.apache.org/licenses/LICENSE-2.0.html) for more details.