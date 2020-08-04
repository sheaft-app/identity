using IdentityModel;
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

            if (context.Caller == "ClaimsProviderAccessToken")
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
}