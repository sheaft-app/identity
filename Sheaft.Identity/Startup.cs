using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;
using IdentityModel;
using System.Threading.Tasks;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.Twitter;
using Sheaft.Identity.Data;
using Sheaft.Identity.Models;
using Microsoft.EntityFrameworkCore.Infrastructure;
using IdentityServer4.EntityFramework.DbContexts;
using System.Linq;
using IdentityServer4.EntityFramework.Entities;
using System.Collections.Generic;
using Amazon.SimpleEmail;
using RazorLight;
using Amazon;
using Serilog;
using Serilog.Events;
using NewRelic.LogEnrichers.Serilog;
using Microsoft.IdentityModel.Logging;

namespace Sheaft.Identity
{
    public class Startup
    {
        readonly string MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

        public IConfiguration Configuration { get; }
        public IWebHostEnvironment Env { get; }

        public Startup(IWebHostEnvironment environment, IConfiguration configuration)
        {
            Env = environment;
            Configuration = configuration;

            var logger = new LoggerConfiguration()
                .ReadFrom.Configuration(configuration)
                .Enrich.WithNewRelicLogsInContext();

            if (Env.IsProduction())
            {
                logger = logger
                    .WriteTo.Async(a => a.NewRelicLogs(
                        endpointUrl: Configuration.GetValue<string>("NEW_RELIC_LOG_API"),
                        applicationName: Configuration.GetValue<string>("NEW_RELIC_APP_NAME"),
                        licenseKey: Configuration.GetValue<string>("NEW_RELIC_LICENSE_KEY"),
                        insertKey: Configuration.GetValue<string>("NEW_RELIC_INSERT_KEY"),
                        restrictedToMinimumLevel: Configuration.GetValue<LogEventLevel>("NEW_RELIC_LOG_LEVEL"),
                        batchSizeLimit: Configuration.GetValue<int>("NEW_RELIC_BATCH_SIZE")
                    ));
            }
            else
            {
                logger = logger
                    .WriteTo.Async(a => a.Console());
            }

            Log.Logger = logger.CreateLogger();
        }

        public void ConfigureServices(IServiceCollection services)
        {
            IdentityModelEventSource.ShowPII = Configuration.GetValue<bool?>("ShowPII") ?? false;

            services.AddCors(options =>
            {
                options.AddPolicy(MyAllowSpecificOrigins,
                builder =>
                {
                    builder.WithOrigins(Configuration.GetValue<string>("Urls:Cors").Split(","))
                        .AllowAnyHeader()
                        .AllowAnyMethod();
                });
            });

            services.Configure<CookiePolicyOptions>(options =>
            {
                options.CheckConsentNeeded = context => true;
                options.MinimumSameSitePolicy = SameSiteMode.None;
            });

            var assembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;
            var databaseConfig = Configuration.GetSection(DatabaseOptions.SETTING).Get<DatabaseOptions>();
            services.AddDbContext<AuthDbContext>(options =>
                        options.UseSqlServer(databaseConfig.ConnectionString,
                                sql => sql.MigrationsAssembly(assembly).MigrationsHistoryTable("AuthMigrationTable", "ef")));

            services.AddIdentity<AppUser, IdentityRole>(c =>
            {
                c.Password.RequireDigit = false;
                c.Password.RequireLowercase = false;
                c.Password.RequireUppercase = false;
                c.Password.RequiredUniqueChars = 0;
                c.Password.RequireNonAlphanumeric = false;
                c.Password.RequiredLength = 6;
            }).AddEntityFrameworkStores<AuthDbContext>()
            .AddDefaultTokenProviders();

            services.AddScoped<SignInManager<AppUser>>();
            services.AddScoped<UserManager<AppUser>>();
            services.AddScoped<RoleManager<IdentityRole>>();

            services.AddMvc(o => o.EnableEndpointRouting = false).AddRazorRuntimeCompilation();

            services.AddAuthentication()
                .AddMicrosoftAccount("ms", "Microsoft", options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:Microsoft:clientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:Microsoft:secret");
                    options.RemoteAuthenticationTimeout = TimeSpan.FromSeconds(60);
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.CallbackPath = "/signin-microsoft";
                    options.UsePkce = true;
                    options.Events = new OAuthEvents();
                })
                .AddGoogle("gg", "Google", options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:Google:clientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:Google:secret");
                    options.RemoteAuthenticationTimeout = TimeSpan.FromSeconds(60);
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.Scope.Add("openid");
                    options.Scope.Add("profile");
                    options.Scope.Add("email");
                    options.CallbackPath = "/signin-google";
                    options.UsePkce = true;
                    options.Events = new OAuthEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            var profileImg = context.User.GetProperty("picture").ToString();
                            identity.AddClaim(new Claim(JwtClaimTypes.Picture, profileImg));
                            return Task.CompletedTask;
                        }
                    };
                })
                .AddFacebook("fb", "Facebook", options =>
                {
                    options.ClientId = Configuration.GetValue<string>("Authentication:Facebook:clientId");
                    options.ClientSecret = Configuration.GetValue<string>("Authentication:Facebook:secret");
                    options.RemoteAuthenticationTimeout = TimeSpan.FromSeconds(60);
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.Scope.Add("public_profile");
                    options.Fields.Add("picture");
                    options.Scope.Add("email");
                    options.CallbackPath = "/signin-facebook";
                    options.UsePkce = true;
                    options.Events = new OAuthEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            var profileImg = context.User.GetProperty("picture").GetProperty("data").GetProperty("url").ToString();
                            identity.AddClaim(new Claim(JwtClaimTypes.Picture, profileImg));
                            return Task.CompletedTask;
                        }
                    };
                });
                //.AddTwitter("tw", "Twitter", options =>
                //{
                //    options.ConsumerKey = Configuration.GetValue<string>("Authentication:Twitter:clientId");
                //    options.ConsumerSecret = Configuration.GetValue<string>("Authentication:Twitter:secret");
                //    options.RemoteAuthenticationTimeout = TimeSpan.FromSeconds(60);
                //    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                //    options.RetrieveUserDetails = true;
                //    options.CallbackPath = "/signin-twitter";
                //    options.Events = new TwitterEvents
                //    {
                //        OnCreatingTicket = context =>
                //        {
                //            var identity = (ClaimsIdentity)context.Principal.Identity;
                //            var profileImg = context.User.GetProperty("profile_image_url_https").ToString();
                //            var name = context.User.GetProperty("name").ToString();

                //            identity.AddClaim(new Claim(JwtClaimTypes.Picture, profileImg));
                //            identity.AddClaim(new Claim(JwtClaimTypes.Name, name));

                //            if (name.Split(" ").Length > 1)
                //            {
                //                identity.AddClaim(new Claim(JwtClaimTypes.GivenName, name.Split(" ")[0]));
                //                identity.AddClaim(new Claim(JwtClaimTypes.FamilyName, name.Split(" ")[1]));
                //            }

                //            return Task.CompletedTask;
                //        }
                //    };
                //});

            services.AddIdentityServer(options =>
            {
                options.Events.RaiseErrorEvents = true;
                options.Events.RaiseInformationEvents = true;
                options.Events.RaiseFailureEvents = true;
                options.Events.RaiseSuccessEvents = true;

                options.EmitStaticAudienceClaim = true;
            })
            .AddAspNetIdentity<AppUser>()
            .AddConfigurationStore(options =>
            {
                options.ConfigureDbContext = builder =>
                    builder.UseSqlServer(databaseConfig.ConnectionString,
                        sql => sql.MigrationsAssembly(assembly).MigrationsHistoryTable("ConfigMigrationTable", "ef"));
            })
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = builder =>
                    builder.UseSqlServer(databaseConfig.ConnectionString,
                        sql => sql.MigrationsAssembly(assembly).MigrationsHistoryTable("GrantsMigrationTable", "ef"));

                options.EnableTokenCleanup = true;
                options.TokenCleanupInterval = 30;
            })
            .AddDeveloperSigningCredential();

            var rootDir = System.IO.Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);

            services.AddScoped<IAmazonSimpleEmailService, AmazonSimpleEmailServiceClient>(_ => new AmazonSimpleEmailServiceClient(Configuration.GetValue<string>("Mailer:ApiId"), Configuration.GetValue<string>("Mailer:ApiKey"), RegionEndpoint.EUCentral1));
            services.AddScoped<IRazorLightEngine>(_ => new RazorLightEngineBuilder()
                                                .UseFileSystemProject($"{(Env.IsDevelopment() ? rootDir.Replace("file:\\", string.Empty) : Env.ContentRootPath)}/Templates")
                                                .UseMemoryCachingProvider()
                                                .Build());

            services.AddLogging(config =>
            {
                config.AddSerilog(dispose: true);
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                //app.UseDatabaseErrorPage();                
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            using (var serviceScope = app.ApplicationServices.GetRequiredService<IServiceScopeFactory>().CreateScope())
            {
                var authContext = serviceScope.ServiceProvider.GetService<AuthDbContext>();
                if (!authContext.AllMigrationsApplied())
                {
                    authContext.Database.Migrate();
                }

                var configContext = serviceScope.ServiceProvider.GetService<ConfigurationDbContext>();
                if (!configContext.AllMigrationsApplied())
                {
                    configContext.Database.Migrate();
                }

                var grantContext = serviceScope.ServiceProvider.GetService<PersistedGrantDbContext>();
                if (!grantContext.AllMigrationsApplied())
                {
                    grantContext.Database.Migrate();
                }

                if (!authContext.Roles.Any())
                {
                    var rm = serviceScope.ServiceProvider.GetService<RoleManager<IdentityRole>>();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Admin:value")) { Id = Configuration.GetValue<string>("Roles:Admin:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Support:value")) { Id = Configuration.GetValue<string>("Roles:Support:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:AppUser:value")) { Id = Configuration.GetValue<string>("Roles:AppUser:id") }).Wait();
                    //specific for sheaft
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:User:value")) { Id = Configuration.GetValue<string>("Roles:User:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Consumer:value")) { Id = Configuration.GetValue<string>("Roles:Consumer:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Owner:value")) { Id = Configuration.GetValue<string>("Roles:Owner:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Producer:value")) { Id = Configuration.GetValue<string>("Roles:Producer:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Store:value")) { Id = Configuration.GetValue<string>("Roles:Store:id") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Anonymous:value")) { Id = Configuration.GetValue<string>("Roles:Anonymous:id") }).Wait();

                    authContext.SaveChanges();
                }

                var adminEmail = Configuration.GetValue<string>("Users:admin:email");
                if (!authContext.Users.Any(u => u.UserName == adminEmail))
                {
                    var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                    var result = um.CreateAsync(new AppUser()
                    {
                        Id = Configuration.GetValue<string>("Users:admin:id").Replace("-", ""),
                        UserName = adminEmail,
                        Email = adminEmail,
                        LastName = Configuration.GetValue<string>("Users:admin:lastname"),
                        FirstName = Configuration.GetValue<string>("Users:admin:firstname")
                    }, Configuration.GetValue<string>("Users:admin:password")).Result;

                    if (result.Succeeded)
                    {
                        var admin = authContext.Users.FirstOrDefault(u => u.Email == adminEmail);
                        um.AddToRoleAsync(admin, Configuration.GetValue<string>("Roles:Admin:value")).Wait();

                        um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Name, $"{admin.FirstName} {admin.LastName}")).Wait();
                        um.AddClaimAsync(admin, new Claim(JwtClaimTypes.GivenName, admin.FirstName)).Wait();
                        um.AddClaimAsync(admin, new Claim(JwtClaimTypes.FamilyName, admin.LastName)).Wait();
                        um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Email, admin.Email)).Wait();
                        um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Admin:value"))).Wait();
                    }

                    authContext.SaveChanges();
                }

                var supportEmail = Configuration.GetValue<string>("Users:support:email");
                if (!authContext.Users.Any(u => u.UserName == supportEmail))
                {
                    var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                    var result = um.CreateAsync(new AppUser()
                    {
                        Id = Configuration.GetValue<string>("Users:support:id").Replace("-", ""),
                        UserName = supportEmail,
                        Email = supportEmail,
                        LastName = Configuration.GetValue<string>("Users:support:lastname"),
                        FirstName = Configuration.GetValue<string>("Users:support:firstname")
                    }, Configuration.GetValue<string>("Users:support:password")).Result;

                    if (result.Succeeded)
                    {
                        var support = authContext.Users.FirstOrDefault(u => u.Email == supportEmail);
                        um.AddToRoleAsync(support, Configuration.GetValue<string>("Roles:Support:value")).Wait();

                        um.AddClaimAsync(support, new Claim(JwtClaimTypes.Name, $"{support.FirstName} {support.LastName}")).Wait();
                        um.AddClaimAsync(support, new Claim(JwtClaimTypes.GivenName, support.FirstName)).Wait();
                        um.AddClaimAsync(support, new Claim(JwtClaimTypes.FamilyName, support.LastName)).Wait();
                        um.AddClaimAsync(support, new Claim(JwtClaimTypes.Email, support.Email)).Wait();
                        um.AddClaimAsync(support, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Support:value"))).Wait();
                    }

                    authContext.SaveChanges();
                }

                if (!configContext.IdentityResources.Any())
                {
                    configContext.IdentityResources.AddRange(new List<IdentityResource>
                         {
                             new IdentityResource { Name = IdentityServerConstants.StandardScopes.OpenId, UserClaims = new List<IdentityResourceClaim>{ new IdentityResourceClaim { Type = JwtClaimTypes.Subject} } },
                             new IdentityResource { Name = IdentityServerConstants.StandardScopes.OfflineAccess, UserClaims = new List<IdentityResourceClaim>{ new IdentityResourceClaim { Type = IdentityServerConstants.StandardScopes.OfflineAccess } } },
                             new IdentityResource { Name = JwtClaimTypes.Role, UserClaims = new List<IdentityResourceClaim>{ new IdentityResourceClaim { Type = JwtClaimTypes.Role } } },
                             new IdentityResource {
                                 Name = IdentityServerConstants.StandardScopes.Email,
                                 UserClaims = new List<IdentityResourceClaim>{
                                     new IdentityResourceClaim { Type = JwtClaimTypes.Email },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.EmailVerified }
                                 }
                             },
                             new IdentityResource { Name = IdentityServerConstants.StandardScopes.Address, UserClaims = new List<IdentityResourceClaim>{ new IdentityResourceClaim { Type = JwtClaimTypes.Address } } },
                             new IdentityResource {
                                 Name = IdentityServerConstants.StandardScopes.Phone,
                                 UserClaims = new List<IdentityResourceClaim>{
                                     new IdentityResourceClaim { Type = JwtClaimTypes.PhoneNumber },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.PhoneNumberVerified }
                                 }
                             },
                             new IdentityResource {
                                 Name = IdentityServerConstants.StandardScopes.Profile,
                                 UserClaims = new List<IdentityResourceClaim>{
                                     new IdentityResourceClaim { Type = JwtClaimTypes.GivenName },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.FamilyName },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.Name },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.Gender },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.BirthDate },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.NickName },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.MiddleName },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.Picture },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.PreferredUserName },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.WebSite },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.ZoneInfo },
                                     new IdentityResourceClaim { Type = JwtClaimTypes.UpdatedAt },
                                     new IdentityResourceClaim { Type = "company_id" }
                                 }
                             }
                         });

                    configContext.SaveChanges();
                }

                if (!configContext.ApiScopes.Any(c => c.Name == "list"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "list",
                        DisplayName = "List Scope"
                    });
                    configContext.SaveChanges();
                }

                if (!configContext.ApiScopes.Any(c => c.Name == "read"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "read",
                        DisplayName = "Read Scope"
                    });
                    configContext.SaveChanges();
                }

                if (!configContext.ApiScopes.Any(c => c.Name == "create"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "create",
                        DisplayName = "Create Scope"
                    });
                    configContext.SaveChanges();
                }


                if (!configContext.ApiScopes.Any(c => c.Name == "update"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "update",
                        DisplayName = "Update Scope"
                    });
                    configContext.SaveChanges();
                }

                if (!configContext.ApiScopes.Any(c => c.Name == "delete"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "delete",
                        DisplayName = "Delete Scope"
                    });
                    configContext.SaveChanges();
                }

                if (!configContext.ApiScopes.Any(c => c.Name == "crud"))
                {
                    configContext.ApiScopes.Add(new ApiScope()
                    {
                        Enabled = true,
                        Name = "crud",
                        DisplayName = "Crud Scope"
                    });
                    configContext.SaveChanges();
                }

                var appName = Configuration.GetValue<string>("Clients:App:Name");
                if (configContext.Clients.All(c => c.ClientName != appName))
                {
                    configContext.Clients.AddRange(new List<Client>
                         {
                             new Client
                             {
                                 ClientId = Configuration.GetValue<string>("Clients:App:Id"),
                                 ClientSecrets = new List<ClientSecret>
                                 {
                                     new ClientSecret{Value = Configuration.GetValue<string>("Clients:App:Secret")}
                                 },
                                 ClientName = appName,
                                 ClientUri = "https://app.sheaft.com",
                                 RequireClientSecret = false,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "http://localhost:4200" },
                                     new ClientCorsOrigin { Origin = "https://localhost:5003" },
                                     new ClientCorsOrigin { Origin = "https://www.sheaft.com" },
                                     new ClientCorsOrigin { Origin = "https://app.sheaft.com" },
                                     new ClientCorsOrigin { Origin = "https://api.sheaft.com" },
                                     new ClientCorsOrigin { Origin = "https://sheaft-app.azurewebsites.net" },
                                     new ClientCorsOrigin { Origin = "https://sheaft-api.azurewebsites.net" },
                                     new ClientCorsOrigin { Origin = "https://sheaft.z28.web.core.windows.net" }
                                 },
                                 AllowedScopes = new List<ClientScope>() {
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OpenId },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OfflineAccess },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Profile },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Email },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Address },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Phone },
                                     new ClientScope { Scope = JwtClaimTypes.Role },
                                     new ClientScope { Scope = "crud" }
                                 },
                                 RequireConsent = false,
                                 AllowedGrantTypes = IdentityServer4.Models.GrantTypes.CodeAndClientCredentials.Select(c => new ClientGrantType{ GrantType = c } ).ToList(),
                                 Enabled = true,
                                 RedirectUris = new List<ClientRedirectUri>() {
                                     new ClientRedirectUri { RedirectUri = "http://localhost:4200" },
                                     new ClientRedirectUri { RedirectUri = "http://localhost:4200/#/" },
                                     new ClientRedirectUri { RedirectUri = "http://localhost:4200/#/callback" },
                                     new ClientRedirectUri { RedirectUri = "http://localhost:4200/#/callback-silent" },
                                     new ClientRedirectUri { RedirectUri = "https://app.sheaft.com" },
                                     new ClientRedirectUri { RedirectUri = "https://app.sheaft.com/#/" },
                                     new ClientRedirectUri { RedirectUri = "https://app.sheaft.com/#/callback" },
                                     new ClientRedirectUri { RedirectUri = "https://app.sheaft.com/#/callback-silent" },
                                     new ClientRedirectUri { RedirectUri = "https://www.sheaft.com" },
                                     new ClientRedirectUri { RedirectUri = "https://www.sheaft.com/#/" },
                                     new ClientRedirectUri { RedirectUri = "https://www.sheaft.com/#/callback" },
                                     new ClientRedirectUri { RedirectUri = "https://www.sheaft.com/#/callback-silent" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-app.azurewebsites.net" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-app.azurewebsites.net/#/" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-app.azurewebsites.net/#/callback" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-app.azurewebsites.net/#/callback-silent" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft.z28.web.core.windows.net" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft.z28.web.core.windows.net/#/" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft.z28.web.core.windows.net/#/callback" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft.z28.web.core.windows.net/#/callback-silent" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft.freshworks.com/sp/OAUTH/170950321282462678/callback" },
                                     new ClientRedirectUri { RedirectUri = "https://support.sheaft.com/sp/OAUTH/170950321282462678/callback" },
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200"},
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200/#/logout" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://app.sheaft.com" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://app.sheaft.com/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://app.sheaft.com/#/logout" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://www.sheaft.com" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://www.sheaft.com/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://www.sheaft.com/#/logout" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft-app.azurewebsites.net" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft-app.azurewebsites.net/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft-app.azurewebsites.net/#/logout" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft.z28.web.core.windows.net" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft.z28.web.core.windows.net/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft.z28.web.core.windows.net/#/logout" }
                                 },
                                 EnableLocalLogin = true,
                                 AllowOfflineAccess = true,
                                 UpdateAccessTokenClaimsOnRefresh = true,
                                 IncludeJwtId = true
                             }
                         });
                }

                if (configContext.ApiResources.All(c => c.Name != appName))
                {
                    configContext.ApiResources.Add(new ApiResource()
                    {
                        Enabled = true,
                        Name = appName,
                        DisplayName = "Sheaft Api",
                        Scopes = new List<ApiResourceScope> {
                                new ApiResourceScope(){ Scope = "list" },
                                new ApiResourceScope(){ Scope = "read" },
                                new ApiResourceScope(){ Scope = "create" },
                                new ApiResourceScope(){ Scope = "update" },
                                new ApiResourceScope(){ Scope = "delete" },
                                new ApiResourceScope(){ Scope = "crud" }
                            }
                    });

                    configContext.SaveChanges();
                }

                var manageName = Configuration.GetValue<string>("Clients:Manage:Name");
                if (configContext.Clients.All(c => c.ClientName != manageName))
                {
                    configContext.Clients.AddRange(new List<Client>
                         {
                             new Client
                             {
                                 ClientId = Configuration.GetValue<string>("Clients:Manage:Id"),
                                 ClientSecrets = new List<ClientSecret>
                                 {
                                     new ClientSecret{Value = Configuration.GetValue<string>("Clients:Manage:Secret")}
                                 },
                                 ClientName = manageName,
                                 ClientUri = "https://manage.sheaft.com",
                                 RequireClientSecret = true,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "https://manage.sheaft.com" },
                                     new ClientCorsOrigin { Origin = "https://sheaft-manage.azurewebsites.net" }
                                 },
                                 AllowedScopes = new List<ClientScope>() {
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OpenId },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OfflineAccess },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Email },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Profile },
                                     new ClientScope { Scope = JwtClaimTypes.Role }
                                 },
                                 RequireConsent = false,
                                 AllowedGrantTypes = IdentityServer4.Models.GrantTypes.CodeAndClientCredentials.Select(c => new ClientGrantType{ GrantType = c } ).ToList(),
                                 Enabled = true,
                                 RedirectUris = new List<ClientRedirectUri>() {
                                     new ClientRedirectUri { RedirectUri = "https://manage.sheaft.com/signin-oidc" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-manage.azurewebsites.net/signin-oidc" }
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://manage.sheaft.com/signout-oidc" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft-manage.azurewebsites.net/signout-oidc" }
                                 },
                                 EnableLocalLogin = true,
                                 AllowOfflineAccess = true,
                                 UpdateAccessTokenClaimsOnRefresh = true,
                                 IncludeJwtId = true,
                                 AlwaysIncludeUserClaimsInIdToken = true,
                                 AlwaysSendClientClaims = true
                             }
                         });

                    configContext.SaveChanges();
                }

                if (configContext.ApiResources.All(c => c.Name != manageName))
                {
                    configContext.ApiResources.Add(new ApiResource()
                    {
                        Enabled = true,
                        Name = manageName,
                        DisplayName = "Sheaft Manage",
                        Scopes = new List<ApiResourceScope> {
                                new ApiResourceScope(){ Scope = "list" },
                                new ApiResourceScope(){ Scope = "read" },
                                new ApiResourceScope(){ Scope = "create" },
                                new ApiResourceScope(){ Scope = "update" },
                                new ApiResourceScope(){ Scope = "delete" },
                                new ApiResourceScope(){ Scope = "crud" }
                            }
                    });

                    configContext.SaveChanges();
                }

                var jobName = Configuration.GetValue<string>("Clients:Jobs:Name");
                if (configContext.Clients.All(c => c.ClientName != jobName))
                {
                    configContext.Clients.AddRange(new List<Client>
                         {
                             new Client
                             {
                                 ClientId = Configuration.GetValue<string>("Clients:Jobs:Id"),
                                 ClientSecrets = new List<ClientSecret>
                                 {
                                     new ClientSecret{Value = Configuration.GetValue<string>("Clients:Jobs:Secret")}
                                 },
                                 ClientName = jobName,
                                 ClientUri = "https://jobs.sheaft.com",
                                 RequireClientSecret = true,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "https://jobs.sheaft.com" },
                                     new ClientCorsOrigin { Origin = "https://sheaft-jobs.azurewebsites.net" }
                                 },
                                 AllowedScopes = new List<ClientScope>() {
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OpenId },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.OfflineAccess },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Email },
                                     new ClientScope { Scope = IdentityServerConstants.StandardScopes.Profile },
                                     new ClientScope { Scope = JwtClaimTypes.Role }
                                 },
                                 RequireConsent = false,
                                 AllowedGrantTypes = IdentityServer4.Models.GrantTypes.CodeAndClientCredentials.Select(c => new ClientGrantType{ GrantType = c } ).ToList(),
                                 Enabled = true,
                                 RedirectUris = new List<ClientRedirectUri>() {
                                     new ClientRedirectUri { RedirectUri = "https://jobs.sheaft.com/signin-oidc" },
                                     new ClientRedirectUri { RedirectUri = "https://sheaft-jobs.azurewebsites.net/signin-oidc" }
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://jobs.sheaft.com/signout-oidc" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://sheaft-jobs.azurewebsites.net/signout-oidc" }
                                 },
                                 EnableLocalLogin = true,
                                 AllowOfflineAccess = true,
                                 UpdateAccessTokenClaimsOnRefresh = true,
                                 IncludeJwtId = true,
                                 AlwaysIncludeUserClaimsInIdToken = true,
                                 AlwaysSendClientClaims = true
                             }
                         });

                    configContext.SaveChanges();
                }

                if (configContext.ApiResources.All(c => c.Name != jobName))
                {
                    configContext.ApiResources.Add(new ApiResource()
                    {
                        Enabled = true,
                        Name = jobName,
                        DisplayName = "Sheaft Jobs",
                        Scopes = new List<ApiResourceScope> {
                                new ApiResourceScope(){ Scope = "list" },
                                new ApiResourceScope(){ Scope = "read" },
                                new ApiResourceScope(){ Scope = "create" },
                                new ApiResourceScope(){ Scope = "update" },
                                new ApiResourceScope(){ Scope = "delete" },
                                new ApiResourceScope(){ Scope = "crud" }
                            }
                    });

                    configContext.SaveChanges();
                }
            }

            app.Use(async (context, next) =>
            {
                if (context.Request.Path.Value.StartsWith("/robots"))
                {
                    if (NewRelic.Api.Agent.NewRelic.GetAgent().CurrentTransaction != null)
                        NewRelic.Api.Agent.NewRelic.SetTransactionName("SEO", "Robots");

                    context.Response.ContentType = "text/plain";
                    await context.Response.WriteAsync("User-agent: *  \nDisallow: /");
                }
                else await next();
            });

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseCors(MyAllowSpecificOrigins);
            app.UseRouting();
           
            app.UseSerilogRequestLogging();

            app.UseIdentityServer();
            app.UseAuthorization();

            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}