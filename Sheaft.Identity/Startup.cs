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
using Microsoft.Extensions.Logging;
using Microsoft.EntityFrameworkCore.Infrastructure;
using IdentityServer4.EntityFramework.DbContexts;
using System.Linq;

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
        }

        public void ConfigureServices(IServiceCollection services)
        {
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

            var connectionString = Configuration.GetConnectionString("IdentityConnection");
            var assembly = typeof(Startup).GetTypeInfo().Assembly.GetName().Name;

            services.AddDbContext<AuthDbContext>(options =>
                        options.UseSqlServer(connectionString,
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
                })
                .AddTwitter("tw", "Twitter", options =>
                {
                    options.ConsumerKey = Configuration.GetValue<string>("Authentication:Twitter:clientId");
                    options.ConsumerSecret = Configuration.GetValue<string>("Authentication:Twitter:secret");
                    options.RemoteAuthenticationTimeout = TimeSpan.FromSeconds(60);
                    options.SignInScheme = IdentityServerConstants.ExternalCookieAuthenticationScheme;
                    options.RetrieveUserDetails = true;
                    options.CallbackPath = "/signin-twitter";
                    options.Events = new TwitterEvents
                    {
                        OnCreatingTicket = context =>
                        {
                            var identity = (ClaimsIdentity)context.Principal.Identity;
                            var profileImg = context.User.GetProperty("profile_image_url_https").ToString();
                            var name = context.User.GetProperty("name").ToString();

                            identity.AddClaim(new Claim(JwtClaimTypes.Picture, profileImg));
                            identity.AddClaim(new Claim(JwtClaimTypes.Name, name));

                            if (name.Split(" ").Length > 1)
                            {
                                identity.AddClaim(new Claim(JwtClaimTypes.GivenName, name.Split(" ")[0]));
                                identity.AddClaim(new Claim(JwtClaimTypes.FamilyName, name.Split(" ")[1]));
                            }

                            return Task.CompletedTask;
                        }
                    };
                });

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
                    builder.UseSqlServer(connectionString,
                        sql => sql.MigrationsAssembly(assembly).MigrationsHistoryTable("ConfigMigrationTable", "ef"));
            })
            .AddOperationalStore(options =>
            {
                options.ConfigureDbContext = builder =>
                    builder.UseSqlServer(connectionString,
                        sql => sql.MigrationsAssembly(assembly).MigrationsHistoryTable("GrantsMigrationTable", "ef"));

                options.EnableTokenCleanup = true;
                options.TokenCleanupInterval = 30;
            })
            .AddDeveloperSigningCredential();

            services.AddApplicationInsightsTelemetry();

            services.AddLogging(config =>
            {
                config.ClearProviders();

                config.AddConfiguration(Configuration.GetSection("Logging"));
                config.AddDebug();
                config.AddEventSourceLogger();
                config.AddApplicationInsights();

                if (Env.IsDevelopment())
                {
                    config.AddConsole();
                }
            });
        }

        public void Configure(IApplicationBuilder app)
        {
            if (Env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
                app.UseDatabaseErrorPage();

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

                    var id = Configuration.GetValue<string>("admin:id");
                    var email = Configuration.GetValue<string>("admin:email");
                    var pwd = Configuration.GetValue<string>("admin:password");
                    var firstname = Configuration.GetValue<string>("admin:firstname");
                    var lastname = Configuration.GetValue<string>("admin:lastname");

                    if (!authContext.Users.Any(u => u.UserName == email))
                    {
                        var um = serviceScope.ServiceProvider.GetService<UserManager<AppUser>>();
                        var result = um.CreateAsync(new AppUser() { Id = id, UserName = email, Email = email, LastName = lastname, FirstName = firstname }, pwd).Result;
                        if (result.Succeeded)
                        {
                            var admin = authContext.Users.FirstOrDefault(u => u.Email == email);
                            um.AddToRoleAsync(admin, Configuration.GetValue<string>("Roles:Admin:value")).Wait();

                            um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Name, $"{admin.FirstName} {admin.LastName}")).Wait();
                            um.AddClaimAsync(admin, new Claim(JwtClaimTypes.GivenName, admin.FirstName)).Wait();
                            um.AddClaimAsync(admin, new Claim(JwtClaimTypes.FamilyName, admin.LastName)).Wait();
                            um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Email, admin.Email)).Wait();
                            um.AddClaimAsync(admin, new Claim(JwtClaimTypes.Role, Configuration.GetValue<string>("Roles:Admin:value"))).Wait();
                        }

                        authContext.SaveChanges();
                    }
                }
            }

            app.UseStaticFiles();

            app.UseRouting();
            app.UseIdentityServer();
            app.UseAuthorization();
            app.UseEndpoints(endpoints =>
            {
                endpoints.MapDefaultControllerRoute();
            });
        }
    }
}