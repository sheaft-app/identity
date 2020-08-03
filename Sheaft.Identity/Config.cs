using IdentityModel;
using IdentityServer4;
using IdentityServer4.Models;
using System.Collections.Generic;

namespace Sheaft.Identity
{
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