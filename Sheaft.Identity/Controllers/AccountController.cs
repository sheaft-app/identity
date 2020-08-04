using IdentityModel;
using IdentityServer4.Events;
using IdentityServer4.Extensions;
using IdentityServer4.Models;
using IdentityServer4.Services;
using IdentityServer4.Stores;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Primitives;
using SendGrid;
using SendGrid.Helpers.Mail;
using Sheaft.Identity.Data;
using Sheaft.Identity.Extensions;
using Sheaft.Identity.Models;
using Sheaft.Identity.Security;
using Sheaft.Identity.ViewModels;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading;
using System.Threading.Tasks;

namespace Sheaft.Identity.Controllers
{
    [SecurityHeaders]
    [AllowAnonymous]
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly SignInManager<AppUser> _signInManager;
        private readonly IIdentityServerInteractionService _interaction;
        private readonly IClientStore _clientStore;
        private readonly IAuthenticationSchemeProvider _schemeProvider;
        private readonly IEventService _events;
        private readonly AuthDbContext _context;
        private readonly IConfiguration _configuration;
        private readonly IHttpContextAccessor _accessor;

        public AccountController(
            AuthDbContext context,
            UserManager<AppUser> userManager,
            SignInManager<AppUser> signInManager,
            IIdentityServerInteractionService interaction,
            IClientStore clientStore,
            IAuthenticationSchemeProvider schemeProvider,
            IHttpContextAccessor accessor,
            IConfiguration configuration,
            IEventService events)
        {
            _context = context;
            _userManager = userManager;
            _signInManager = signInManager;
            _interaction = interaction;
            _clientStore = clientStore;
            _schemeProvider = schemeProvider;
            _events = events;
            _configuration = configuration;
            _accessor = accessor;
        }

        private bool IsAuthorized()
        {
            if (_accessor.HttpContext.Request.Headers.TryGetValue("Authorization", out StringValues apiKey))
            {
                return apiKey.FirstOrDefault()?.Replace("apikey ", "") == _configuration.GetValue<string>("Apikey");
            }

            return false;
        }

        /// <summary>
        /// Entry point into the login workflow
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Login(string returnUrl)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildLoginViewModelAsync(returnUrl);

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        /// <summary>
        /// Handle postback from username/password login
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginInputModel model, string button)
        {
            // check if we are in the context of an authorization request
            var context = await _interaction.GetAuthorizationContextAsync(model.ReturnUrl);

            // the user clicked the "cancel" button
            if (button != "login")
            {
                if (context != null)
                {
                    // if the user cancels, send a result back into IdentityServer as if they 
                    // denied the consent (even if this client does not require consent).
                    // this will send back an access denied OIDC error response to the client.
                    await _interaction.DenyAuthorizationAsync(context, AuthorizationError.AccessDenied);

                    // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                    if (context.IsNativeClient())
                    {
                        // The client is native, so this change in how to
                        // return the response is for better UX for the end user.
                        return this.LoadingPage("Redirect", model.ReturnUrl);
                    }

                    return Redirect(model.ReturnUrl);
                }
                else
                {
                    // since we don't have a valid context, then we just go back to the home page
                    return Redirect("~/");
                }
            }

            if (ModelState.IsValid)
            {
                var result = await _signInManager.PasswordSignInAsync(model.Username, model.Password, model.RememberLogin, lockoutOnFailure: true);
                if (result.Succeeded)
                {
                    var user = await _userManager.FindByNameAsync(model.Username);
                    await _events.RaiseAsync(new UserLoginSuccessEvent(user.UserName, user.Id, user.UserName, clientId: context?.Client.ClientId));

                    if (context != null)
                    {
                        if (context.IsNativeClient())
                        {
                            // The client is native, so this change in how to
                            // return the response is for better UX for the end user.
                            return this.LoadingPage("Redirect", model.ReturnUrl);
                        }

                        // we can trust model.ReturnUrl since GetAuthorizationContextAsync returned non-null
                        return Redirect(model.ReturnUrl);
                    }

                    // request for a local page
                    if (Url.IsLocalUrl(model.ReturnUrl))
                    {
                        return Redirect(model.ReturnUrl);
                    }
                    else if (string.IsNullOrEmpty(model.ReturnUrl))
                    {
                        return Redirect("~/");
                    }
                    else
                    {
                        // user might have clicked on a malicious link - should be logged
                        throw new Exception("invalid return URL");
                    }
                }

                await _events.RaiseAsync(new UserLoginFailureEvent(model.Username, "invalid credentials", clientId:context?.Client.ClientId));
                ModelState.AddModelError(string.Empty, AccountOptions.InvalidCredentialsErrorMessage);
            }

            // something went wrong, show form with error
            var vm = await BuildLoginViewModelAsync(model);
            return View(vm);
        }

        
        /// <summary>
        /// Show logout page
        /// </summary>
        [HttpGet]
        public async Task<IActionResult> Logout(string logoutId)
        {
            // build a model so the logout page knows what to display
            var vm = await BuildLogoutViewModelAsync(logoutId);

            if (vm.ShowLogoutPrompt == false)
            {
                // if the request for logout was properly authenticated from IdentityServer, then
                // we don't need to show the prompt and can just log the user out directly.
                return await Logout(vm);
            }

            return View(vm);
        }

        /// <summary>
        /// Handle logout page postback
        /// </summary>
        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Logout(LogoutInputModel model)
        {
            // build a model so the logged out page knows what to display
            var vm = await BuildLoggedOutViewModelAsync(model.LogoutId);

            if (User?.Identity.IsAuthenticated == true)
            {
                // delete local authentication cookie
                await _signInManager.SignOutAsync();

                // raise the logout event
                await _events.RaiseAsync(new UserLogoutSuccessEvent(User.GetSubjectId(), User.GetDisplayName()));
            }

            // check if we need to trigger sign-out at an upstream identity provider
            if (vm.TriggerExternalSignout)
            {
                // build a return URL so the upstream provider will redirect back
                // to us after the user has logged out. this allows us to then
                // complete our single sign-out processing.
                string url = Url.Action("Logout", new { logoutId = vm.LogoutId });

                // this triggers a redirect to the external provider for sign-out
                return SignOut(new AuthenticationProperties { RedirectUri = url }, vm.ExternalAuthenticationScheme);
            }

            if (vm.AutomaticRedirectAfterSignOut && !string.IsNullOrWhiteSpace(vm.PostLogoutRedirectUri))
                return Redirect(vm.PostLogoutRedirectUri);

            return View("LoggedOut", vm);
        }

        [HttpGet]
        public IActionResult AccessDenied()
        {
            return View();
        }


        [HttpGet]
        public IActionResult ForgotPassword(string username = null, string returnUrl = null)
        {
            var vm = new ForgotPasswordViewModel
            {
                ReturnUrl = returnUrl,
                UserName = username,
                Sent = false
            };

            return View(vm);
        }

        [HttpPost]
        public async Task<IActionResult> ForgotPassword(ForgotPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByEmailAsync(model.UserName);
            if (user == null || !user.EmailConfirmed)
            {
                ModelState.AddModelError("", "Utilisateur introuvable");
                return View(model);
            }

            var token = await _userManager.GeneratePasswordResetTokenAsync(user);
            var url = Url.Action("ResetPassword", "Account", new { userId = user.Id, token = token, returnUrl = model.ReturnUrl }, Url.ActionContext.HttpContext.Request.Scheme);

            var client = new SendGridClient(_configuration.GetValue<string>("sendgrid:apiKey"));
            var msg = new SendGridMessage();

            msg.SetFrom(new EmailAddress(_configuration.GetValue<string>("sendgrid:sender:email"), _configuration.GetValue<string>("sendgrid:sender:name")));

            var recipients = new List<EmailAddress>
                {
                    new EmailAddress(user.Email, user.FirstName + " " + user.LastName)
                };

            msg.AddTos(recipients);

            msg.SetTemplateId(_configuration.GetValue<string>("sendgrid:templates:resetPasswordId"));
            msg.SetTemplateData(new { UserName = user.FirstName + " " + user.LastName, ResetPasswordLink = url });

            var response = await client.SendEmailAsync(msg);
            if ((int)response.StatusCode >= 400)
            {
                ModelState.AddModelError("", "Une erreur est survenue lors de l'envoi de l'email de réinitialisation.");
                return View(model);
            }

            model.Sent = true;
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> ConfirmEmail(string userId, string token, string returnUrl = null)
        {
            if (userId == null || token == null)
            {
                return View("Error");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("Utilisateur introuvable, le lien que vous avez utilisé est peut-être invalide, réessayer de relancer la procédure de vérification d'email ou contactez notre support.");

            var result = await _userManager.ConfirmEmailAsync(user, token);
            if (!result.Succeeded)
                throw new Exception("Le code de vérification est invalide ou expiré, réessayer de relancer la procédure de vérification d'email ou contactez notre support.");

            return View();
        }


        [HttpGet]
        public async Task<IActionResult> ResetPassword(string userId, string token, string returnUrl = null)
        {
            if (userId == null || token == null)
            {
                return View("Error");
            }

            var user = await _userManager.FindByIdAsync(userId);
            if (user == null)
                throw new Exception("Utilisateur introuvable, le lien que vous avez utilisé est peut-être invalide, réessayer de relancer la procédure de récupération de mot de passe ou contactez notre support.");

            var vm = new ResetPasswordViewModel
            {
                ReturnUrl = returnUrl,
                UserName = user.UserName,
                NewPassword = null,
                ConfirmPassword = null,
                Token = token
            };

            return View(vm);
        }

        [HttpPost]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _userManager.FindByNameAsync(model.UserName);
            var result = await _userManager.ResetPasswordAsync(user, model.Token, model.NewPassword);
            if (result.Succeeded)
            {
                return await Login(new LoginInputModel
                {
                    Username = user.UserName,
                    Password = model.NewPassword,
                    ReturnUrl = model.ReturnUrl
                }, "login");
            }

            ModelState.AddModelError("", "Une erreur est survenue pendant la réinitialisation de votre mot de passe.");
            return View(model);
        }

        [HttpGet]
        public async Task<IActionResult> Register(string returnUrl, string username = null)
        {
            // build a model so we know what to show on the login page
            var vm = await BuildRegisterViewModelAsync(returnUrl);
            vm.Username = vm.Username ?? username;

            if (vm.IsExternalLoginOnly)
            {
                // we only have one option for logging in and it's an external provider
                return RedirectToAction("Challenge", "External", new { provider = vm.ExternalLoginScheme, returnUrl });
            }

            return View(vm);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View(model);
            }

            var user = await _context.Set<AppUser>().FirstOrDefaultAsync(r => r.UserName == model.Username);
            if (user != null)
            {
                ModelState.AddModelError(string.Empty, "Un utilisateur avec cette adresse email existe déjà.");
                return View(model);
            }

            user = new AppUser()
            {
                UserName = model.Username,
                Email = model.Username
            };

            var result = await _userManager.CreateAsync(user, model.Password);

            if (!result.Succeeded)
            {
                ModelState.AddModelError(string.Empty, result.Errors.ToString());
                return View(model);
            }

            await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Subject, user.Id));
            await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Email, user.Email));
            await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.EmailVerified, false.ToString()));
            await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Role, _configuration.GetValue<string>("Roles:Anonymous:value")));

            await _userManager.AddToRoleAsync(user, _configuration.GetValue<string>("Roles:AppUser:value"));

            var token = await _userManager.GenerateEmailConfirmationTokenAsync(user);
            var url = Url.Action("ConfirmEmail", "Account", new { userId = user.Id, token = token, returnUrl = model.ReturnUrl }, Url.ActionContext.HttpContext.Request.Scheme);

            var client = new SendGridClient(_configuration.GetValue<string>("sendgrid:apiKey"));
            var msg = new SendGridMessage();

            msg.SetFrom(new EmailAddress(_configuration.GetValue<string>("sendgrid:sender:email"), _configuration.GetValue<string>("sendgrid:sender:name")));

            var recipients = new List<EmailAddress>
                {
                    new EmailAddress(user.Email, user.FirstName + " " + user.LastName)
                };

            msg.AddTos(recipients);

            msg.SetTemplateId(_configuration.GetValue<string>("sendgrid:templates:verifyEmailId"));
            msg.SetTemplateData(new { UserName = user.FirstName + " " + user.LastName, ConfirmEmailLink = url });

            var response = await client.SendEmailAsync(msg);
            if ((int)response.StatusCode >= 400)
            {
                ModelState.AddModelError("", "Une erreur est survenue lors de l'envoi de l'email de confirmation.");
                return View(model);
            }

            return await Login(new LoginInputModel
            {
                Username = model.Username,
                Password = model.Password,
                ReturnUrl = model.ReturnUrl
            }, "login");
        }

        [HttpPut]
        public async Task<IActionResult> Picture([FromBody] UpdateUserPictureModel model)
        {
            if (!IsAuthorized())
                return Unauthorized();

            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var user = await _context.Set<AppUser>().FirstOrDefaultAsync(r => r.Id == model.Id);
            if (user == null)
            {
                return NotFound("Utilisateur introuvable.");
            }

            var claims = await _context.UserClaims.Where(c => c.UserId == user.Id).ToListAsync(CancellationToken.None);

            if (claims.Any(c => c.ClaimType == JwtClaimTypes.Picture))
            {
                await _userManager.RemoveClaimsAsync(user, claims.Where(c => c.ClaimType == JwtClaimTypes.Picture).Select(r => r.ToClaim()));
            }

            await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Picture, model.Picture));
            return Ok();
        }

        [HttpDelete]
        public async Task<IActionResult> UserAccount([FromQuery] string userId)
        {
            if (!IsAuthorized())
                return Unauthorized();

            var user = await _context.Set<AppUser>().FirstOrDefaultAsync(r => r.Id == userId);
            if (user == null)
            {
                return NotFound("Utilisateur introuvable.");
            }

            await _userManager.DeleteAsync(user);
            return Ok();
        }


        [HttpPut]
        public async Task<IActionResult> Profile([FromBody] UpdateUserModel model, CancellationToken token)
        {
            if (!IsAuthorized())
                return Unauthorized();

            if (!ModelState.IsValid)
            {
                return BadRequest();
            }

            var user = await _context.Set<AppUser>().FirstOrDefaultAsync(r => r.Id == model.Id);
            if (user == null)
            {
                return NotFound("Utilisateur introuvable.");
            }

            var claims = (await _context.UserClaims.Where(c => c.UserId == user.Id)?.ToListAsync(token)) ?? new List<IdentityUserClaim<string>>();
            var nameChanged = false;

            if (!string.IsNullOrWhiteSpace(model.FirstName) && user.FirstName != model.FirstName)
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.GivenName);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                user.FirstName = model.FirstName;
                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.GivenName, user.FirstName));
                nameChanged = true;
            }

            if (!string.IsNullOrWhiteSpace(model.LastName) && user.LastName != model.LastName)
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.FamilyName);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                user.LastName = model.LastName;
                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.FamilyName, user.LastName));
                nameChanged = true;
            }

            if (!string.IsNullOrWhiteSpace(model.Email) && user.Email != model.Email)
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.Email);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                user.Email = model.Email;
                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Email, user.Email));
            }

            if (!string.IsNullOrWhiteSpace(model.Phone) && user.PhoneNumber != model.Phone)
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.PhoneNumber);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                user.PhoneNumber = model.Phone;
                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.PhoneNumber, user.PhoneNumber));
            }

            if (!string.IsNullOrWhiteSpace(model.Picture))
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.Picture);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Picture, model.Picture));
            }

            if (nameChanged)
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.Name);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Name, $"{user.FirstName} {user.LastName}"));
            }

            if (model.Roles != null && model.Roles.Any())
            {
                var existingClaims = GetExistingClaimsOfType(claims, JwtClaimTypes.Role);
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                foreach (var role in model.Roles)
                {
                    var entityRole = await _context.Roles.SingleOrDefaultAsync(r => r.Id == role, token);
                    if (entityRole == null)
                        throw new Exception("Le rôle spécifié est introuvable");

                    await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Role, entityRole.NormalizedName));
                }

                await _userManager.AddClaimAsync(user, new Claim(JwtClaimTypes.Role, _configuration.GetValue<string>("Roles:AppUser:Value")));
            }

            if (model.CompanyId.HasValue)
            {
                var existingClaims = GetExistingClaimsOfType(claims, "company_id");
                if (existingClaims.Any())
                    await _userManager.RemoveClaimsAsync(user, existingClaims);

                await _userManager.RemoveClaimsAsync(user, claims.Where(c => c.ClaimType == "company_id").Select(r => r.ToClaim()));
                await _userManager.AddClaimAsync(user, new Claim("company_id", model.CompanyId.Value.ToString("N")));
            }

            var result = await _userManager.UpdateAsync(user);
            if (!result.Succeeded)
            {
                return BadRequest(result.Errors);
            }

            return Ok();
        }



        /*****************************************/
        /* helper APIs for the AccountController */
        /*****************************************/

        private static IEnumerable<Claim> GetExistingClaimsOfType(List<IdentityUserClaim<string>> claims, string type)
        {
            var existingUserClaims = claims.Where(c => c.ClaimType == type);
            if (existingUserClaims == null || !existingUserClaims.Any())
                return new List<Claim>();

            return existingUserClaims.Select(r => r.ToClaim());
        }

        private async Task<RegisterViewModel> BuildRegisterViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new RegisterViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } }.ToList();
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new RegisterViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(string returnUrl)
        {
            var context = await _interaction.GetAuthorizationContextAsync(returnUrl);
            if (context?.IdP != null && await _schemeProvider.GetSchemeAsync(context.IdP) != null)
            {
                var local = context.IdP == IdentityServer4.IdentityServerConstants.LocalIdentityProvider;

                // this is meant to short circuit the UI and only trigger the one external IdP
                var vm = new LoginViewModel
                {
                    EnableLocalLogin = local,
                    ReturnUrl = returnUrl,
                    Username = context?.LoginHint,
                };

                if (!local)
                {
                    vm.ExternalProviders = new[] { new ExternalProvider { AuthenticationScheme = context.IdP } }.ToList();
                }

                return vm;
            }

            var schemes = await _schemeProvider.GetAllSchemesAsync();

            var providers = schemes
                .Where(x => x.DisplayName != null)
                .Select(x => new ExternalProvider
                {
                    DisplayName = x.DisplayName ?? x.Name,
                    AuthenticationScheme = x.Name
                }).ToList();

            var allowLocal = true;
            if (context?.Client.ClientId != null)
            {
                var client = await _clientStore.FindEnabledClientByIdAsync(context.Client.ClientId);
                if (client != null)
                {
                    allowLocal = client.EnableLocalLogin;

                    if (client.IdentityProviderRestrictions != null && client.IdentityProviderRestrictions.Any())
                    {
                        providers = providers.Where(provider => client.IdentityProviderRestrictions.Contains(provider.AuthenticationScheme)).ToList();
                    }
                }
            }

            return new LoginViewModel
            {
                AllowRememberLogin = AccountOptions.AllowRememberLogin,
                EnableLocalLogin = allowLocal && AccountOptions.AllowLocalLogin,
                ReturnUrl = returnUrl,
                Username = context?.LoginHint,
                ExternalProviders = providers.ToArray()
            };
        }

        private async Task<LoginViewModel> BuildLoginViewModelAsync(LoginInputModel model)
        {
            var vm = await BuildLoginViewModelAsync(model.ReturnUrl);
            vm.Username = model.Username;
            vm.RememberLogin = model.RememberLogin;
            return vm;
        }

        private async Task<LogoutViewModel> BuildLogoutViewModelAsync(string logoutId)
        {
            var vm = new LogoutViewModel { LogoutId = logoutId, ShowLogoutPrompt = AccountOptions.ShowLogoutPrompt };

            if (User?.Identity.IsAuthenticated != true)
            {
                // if the user is not authenticated, then just show logged out page
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            var context = await _interaction.GetLogoutContextAsync(logoutId);
            if (context?.ShowSignoutPrompt == false)
            {
                // it's safe to automatically sign-out
                vm.ShowLogoutPrompt = false;
                return vm;
            }

            // show the logout prompt. this prevents attacks where the user
            // is automatically signed out by another malicious web page.
            return vm;
        }

        private async Task<LoggedOutViewModel> BuildLoggedOutViewModelAsync(string logoutId)
        {
            // get context information (client name, post logout redirect URI and iframe for federated signout)
            var logout = await _interaction.GetLogoutContextAsync(logoutId);

            var vm = new LoggedOutViewModel
            {
                AutomaticRedirectAfterSignOut = AccountOptions.AutomaticRedirectAfterSignOut,
                PostLogoutRedirectUri = logout?.PostLogoutRedirectUri,
                ClientName = string.IsNullOrEmpty(logout?.ClientName) ? logout?.ClientId : logout?.ClientName,
                SignOutIframeUrl = logout?.SignOutIFrameUrl,
                LogoutId = logoutId
            };

            if (User?.Identity.IsAuthenticated == true)
            {
                var idp = User.FindFirst(JwtClaimTypes.IdentityProvider)?.Value;
                if (idp != null && idp != IdentityServer4.IdentityServerConstants.LocalIdentityProvider)
                {
                    var providerSupportsSignout = await HttpContext.GetSchemeSupportsSignOutAsync(idp);
                    if (providerSupportsSignout)
                    {
                        if (vm.LogoutId == null)
                        {
                            // if there's no current logout context, we need to create one
                            // this captures necessary info from the current logged in user
                            // before we signout and redirect away to the external IdP for signout
                            vm.LogoutId = await _interaction.CreateLogoutContextAsync();
                        }

                        vm.ExternalAuthenticationScheme = idp;
                    }
                }
            }

            return vm;
        }
    }
}