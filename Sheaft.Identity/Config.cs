﻿using IdentityModel;
using IdentityServer4;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using Microsoft.AspNetCore.Identity;
using Sheaft.Identity.Models;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Sheaft.Identity
{
    public class ProfileService : IProfileService
    {
        private readonly IUserClaimsPrincipalFactory<AppUser> _claimsFactory;
        private readonly UserManager<AppUser> _userManager;

        public ProfileService(UserManager<AppUser> userManager, IUserClaimsPrincipalFactory<AppUser> claimsFactory)
        {
            _userManager = userManager;
            _claimsFactory = claimsFactory;
        }

        public async Task GetProfileDataAsync(ProfileDataRequestContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            var principal = await _claimsFactory.CreateAsync(user);

            if (context.Client.AlwaysSendClientClaims)
            {
                var claims = new List<System.Security.Claims.Claim>();
                foreach (var claim in context.Subject.Claims)
                {
                    foreach (var scope in context.RequestedResources.ParsedScopes)
                    {
                        var resource = context.RequestedResources.Resources.IdentityResources.FirstOrDefault(r => r.Name == scope.ParsedName);
                        if (resource == null)
                            continue;

                        var cl = resource.UserClaims.FirstOrDefault(uc => uc == claim.Type);
                        if (cl == null)
                            continue;

                        claims.Add(claim);
                    }
                }

                context.IssuedClaims = claims.ToList();
            }
            else
            {
                var claims = principal.Claims.ToList();
                claims = claims.Where(claim => context.RequestedClaimTypes.Contains(claim.Type)).ToList();

                context.IssuedClaims = claims;
            }
        }

        public async Task IsActiveAsync(IsActiveContext context)
        {
            var sub = context.Subject.GetSubjectId();
            var user = await _userManager.FindByIdAsync(sub);
            context.IsActive = user != null;
        }
    }
    public class Config
    {
        public static IEnumerable<IdentityResource> GetIdentityResources()
        {
            return new List<IdentityResource>
            {
                new IdentityResource { Name = IdentityServerConstants.StandardScopes.OpenId, UserClaims = { IdentityServerConstants.StandardScopes.OpenId } },
                new IdentityResource { Name = IdentityServerConstants.StandardScopes.OfflineAccess, UserClaims = { IdentityServerConstants.StandardScopes.OfflineAccess } },
                new IdentityResource { Name = IdentityServerConstants.StandardScopes.Address, UserClaims = { IdentityServerConstants.StandardScopes.Address } },
                new IdentityResource { Name = JwtClaimTypes.Role, UserClaims = { JwtClaimTypes.Role } },
                new IdentityResource { Name = "company_id", UserClaims = { "company_id" } },
                new IdentityResource {
                    Name = IdentityServerConstants.StandardScopes.Profile,
                    UserClaims = {
                        IdentityServerConstants.StandardScopes.Profile,
                        JwtClaimTypes.GivenName,
                        JwtClaimTypes.FamilyName,
                        JwtClaimTypes.Name,
                    }
                },
                new IdentityResource {
                    Name = IdentityServerConstants.StandardScopes.Email,
                    UserClaims = {
                        IdentityServerConstants.StandardScopes.Email,
                        JwtClaimTypes.EmailVerified
                    }
                },
                new IdentityResource {
                    Name = IdentityServerConstants.StandardScopes.Phone,
                    UserClaims = {
                        IdentityServerConstants.StandardScopes.Phone,
                        JwtClaimTypes.PhoneNumberVerified
                    }
                },
            };
        }

        public static IEnumerable<ApiResource> GetApiResources()
        {
            return new List<ApiResource>
            {
                new ApiResource()
                {
                    Enabled = true,
                    Name = "api",
                    DisplayName = "Sheaft API",
                    Scopes = new List<string>
                    {
                       "api.all"
                    }
                }
            };
        }

        public static IEnumerable<Client> GetClients()
        {
            return new List<Client>
            {
                new Client
                {
                    ClientId = "990966C64E554C6298970F5D6FBEEDEA",
                    ClientName = "Sheaft",
                    ClientUri = "https://www.sheaft.com",
                    RequireClientSecret = false,
                    AllowAccessTokensViaBrowser = true,
                    AllowedCorsOrigins = {
                        "http://localhost:4200",
                        "https://localhost:5005",
                        "https://localhost:5003",
                        "https://app.sheaft.com",
                        "https://api.sheaft.com",
                        "https://sheaft-app.azurewebsites.net",
                        "https://sheaft-api.azurewebsites.net"
                    },
                    AllowedScopes = {
                        IdentityServerConstants.StandardScopes.OpenId,
                        IdentityServerConstants.StandardScopes.OfflineAccess,
                        IdentityServerConstants.StandardScopes.Profile,
                        IdentityServerConstants.StandardScopes.Email,
                        IdentityServerConstants.StandardScopes.Phone,
                        IdentityServerConstants.StandardScopes.Address,
                        JwtClaimTypes.Role,
                        "company_id",
                        "api.all"
                    },
                    RequireConsent = false,
                    AllowedGrantTypes = GrantTypes.CodeAndClientCredentials,
                    Enabled = true,
                    RedirectUris = {
                        "http://localhost:4200",
                        "https://localhost:5005",
                        "https://localhost:5003",
                        "https://app.sheaft.com",
                        "https://api.sheaft.com",
                        "https://sheaft-app.azurewebsites.net",
                        "https://sheaft-api.azurewebsites.net",
                    },
                    PostLogoutRedirectUris = {
                        "http://localhost:4200",
                        "https://localhost:5005",
                        "https://localhost:5003",
                        "https://app.sheaft.com",
                        "https://api.sheaft.com",
                        "https://sheaft-app.azurewebsites.net",
                        "https://sheaft-api.azurewebsites.net",
                    },
                    EnableLocalLogin = true,
                    IncludeJwtId = true,
                    AlwaysIncludeUserClaimsInIdToken = true
                }
            };
        }
    }
}