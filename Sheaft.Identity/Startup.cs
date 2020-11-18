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
                options.TokenCleanupInterval = 3600;
            })
            .AddDeveloperSigningCredential();

            services.AddScoped<IAmazonSimpleEmailService, AmazonSimpleEmailServiceClient>(_ => new AmazonSimpleEmailServiceClient(Configuration.GetValue<string>("Mailer:ApiId"), Configuration.GetValue<string>("Mailer:ApiKey"), RegionEndpoint.EUCentral1));

            services.AddScoped<IRazorLightEngine>(_ => {
                var rootDir = System.IO.Path.GetDirectoryName(Assembly.GetExecutingAssembly().CodeBase);
                return new RazorLightEngineBuilder()
                .UseFileSystemProject($"{rootDir.Replace("file:\\", string.Empty).Replace("file:", string.Empty)}/Templates")
                .UseMemoryCachingProvider()
                .Build();
            });

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

                app.UseCookiePolicy(new CookiePolicyOptions
                {
                    MinimumSameSitePolicy = SameSiteMode.Lax,
                    Secure = CookieSecurePolicy.SameAsRequest
                });
            }
            else
            {
                app.UseHttpsRedirection();
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
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Admin:value")) { Id = Configuration.GetValue<Guid>("Roles:Admin:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Support:value")) { Id = Configuration.GetValue<Guid>("Roles:Support:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:AppUser:value")) { Id = Configuration.GetValue<Guid>("Roles:AppUser:id").ToString("D") }).Wait();
                    //specific for sheaft
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:User:value")) { Id = Configuration.GetValue<Guid>("Roles:User:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Consumer:value")) { Id = Configuration.GetValue<Guid>("Roles:Consumer:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Owner:value")) { Id = Configuration.GetValue<Guid>("Roles:Owner:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Producer:value")) { Id = Configuration.GetValue<Guid>("Roles:Producer:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Store:value")) { Id = Configuration.GetValue<Guid>("Roles:Store:id").ToString("D") }).Wait();
                    rm.CreateAsync(new IdentityRole(Configuration.GetValue<string>("Roles:Anonymous:value")) { Id = Configuration.GetValue<Guid>("Roles:Anonymous:id").ToString("D") }).Wait();

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

                if (Env.IsDevelopment())
                {
                    var prod1Email = "contact@prod1.xyz";
                    if (!authContext.Users.Any(u => u.UserName == prod1Email))
                    {
                        var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                        var user = new AppUser()
                        {
                            Id = "5a8f0ae2b70147f0a8efe7c2365a72eb",
                            UserName = prod1Email,
                            Email = prod1Email,
                            LastName = "Piquet",
                            FirstName = "Arnold"
                        };

                        var result = um.CreateAsync(user, "password").Result;

                        if (result.Succeeded)
                        {
                            var userCreated = authContext.Users.FirstOrDefault(u => u.Email == user.Email);

                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Producer:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Owner:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:AppUser:value")).Wait();

                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Name, $"La Ferme des Piquets")).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.GivenName, user.FirstName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.FamilyName, user.LastName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Email, user.Email)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Owner:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:AppUser:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Producer:value"))).Wait();
                        }

                        authContext.SaveChanges();
                    }

                    var prod2Email = "contact@prod2.xyz";
                    if (!authContext.Users.Any(u => u.UserName == prod2Email))
                    {
                        var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                        var user = new AppUser()
                        {
                            Id = "442e31e3eea94aa0b7413245ed1c6f2f",
                            UserName = prod2Email,
                            Email = prod2Email,
                            LastName = "Fotdakor",
                            FirstName = "Peter"
                        };

                        var result = um.CreateAsync(user, "password").Result;

                        if (result.Succeeded)
                        {
                            var userCreated = authContext.Users.FirstOrDefault(u => u.Email == user.Email);

                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Producer:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Owner:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:AppUser:value")).Wait();

                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Name, $"La ferme pas d'accord")).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.GivenName, user.FirstName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.FamilyName, user.LastName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Email, user.Email)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Owner:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:AppUser:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Producer:value"))).Wait();
                        }

                        authContext.SaveChanges();
                    }

                    var mag1Email = "contact@mag1.xyz";
                    if (!authContext.Users.Any(u => u.UserName == mag1Email))
                    {
                        var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                        var user = new AppUser()
                        {
                            Id = "28491432175442859f675386a898a48f",
                            UserName = mag1Email,
                            Email = mag1Email,
                            LastName = "Debussy",
                            FirstName = "Elia"
                        };

                        var result = um.CreateAsync(user, "password").Result;

                        if (result.Succeeded)
                        {
                            var userCreated = authContext.Users.FirstOrDefault(u => u.Email == user.Email);

                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Store:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Owner:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:AppUser:value")).Wait();

                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Name, $"O'local")).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.GivenName, user.FirstName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.FamilyName, user.LastName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Email, user.Email)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Owner:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:AppUser:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Store:value"))).Wait();
                        }

                        authContext.SaveChanges();
                    }

                    var mag2Email = "contact@mag2.xyz";
                    if (!authContext.Users.Any(u => u.UserName == mag2Email))
                    {
                        var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                        var user = new AppUser()
                        {
                            Id = "0eafd299d0e64a63af8d6d154db96f55",
                            UserName = mag2Email,
                            Email = mag2Email,
                            LastName = "Syntax",
                            FirstName = "John"
                        };

                        var result = um.CreateAsync(user, "password").Result;

                        if (result.Succeeded)
                        {
                            var userCreated = authContext.Users.FirstOrDefault(u => u.Email == user.Email);

                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Store:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:Owner:value")).Wait();
                            um.AddToRoleAsync(userCreated, Configuration.GetValue<string>("Roles:AppUser:value")).Wait();

                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Name, $"Mes p'tits plats")).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.GivenName, user.FirstName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.FamilyName, user.LastName)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Email, user.Email)).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Owner:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:AppUser:value"))).Wait();
                            um.AddClaimAsync(userCreated, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Store:value"))).Wait();
                        }

                        authContext.SaveChanges();
                    }
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
                                 ClientUri = "http://localhost:4200",
                                 RequireClientSecret = false,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "http://localhost:4200" },
                                     new ClientCorsOrigin { Origin = "http://localhost:5002" },
                                     new ClientCorsOrigin { Origin = "https://localhost:5003" },
                                     new ClientCorsOrigin { Origin = "http://localhost:5009" },
                                     new ClientCorsOrigin { Origin = "https://localhost:5010" }
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
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200"},
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200/#/" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:4200/#/logout" },
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
                                 ClientUri = "http://localhost:5007",
                                 RequireClientSecret = false,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "https://localhost:5008" },
                                     new ClientCorsOrigin { Origin = "http://localhost:5007" },
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
                                     new ClientRedirectUri { RedirectUri = "https://localhost:5008/signin-oidc" },
                                     new ClientRedirectUri { RedirectUri = "http://localhost:5007/signin-oidc" },
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://localhost:5008/signout-oidc" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:5007/signout-oidc" },
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
                                 ClientUri = "http://localhost:5019",
                                 RequireClientSecret = false,
                                 AllowAccessTokensViaBrowser = true,
                                 RequirePkce = true,
                                 AllowedCorsOrigins = new List<ClientCorsOrigin>() {
                                     new ClientCorsOrigin { Origin = "https://localhost:5020" },
                                     new ClientCorsOrigin { Origin = "http://localhost:5019" },
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
                                     new ClientRedirectUri { RedirectUri = "https://localhost:5020/signin-oidc" },
                                     new ClientRedirectUri { RedirectUri = "http://localhost:5019/signin-oidc" },
                                 },
                                 PostLogoutRedirectUris = new List<ClientPostLogoutRedirectUri>() {
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "https://localhost:5020/signout-oidc" },
                                     new ClientPostLogoutRedirectUri { PostLogoutRedirectUri = "http://localhost:5019/signout-oidc" },
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