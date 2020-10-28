using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Sheaft.Identity.ViewModels
{
    public class ForgotPasswordViewModel
    {
        public string ReturnUrl { get; set; }
        [DisplayName("Adresse email")]
        [Required(ErrorMessage = "L'adresse email est requise.")]
        public string UserName { get; set; }
        public bool Sent { get; set; }
    }

    public class ResetPasswordViewModel
    {
        public string ReturnUrl { get; set; }
        [DisplayName("Adresse email")]
        [Required(ErrorMessage = "L'adresse email est requise.")]
        public string UserName { get; set; }
        [Required(ErrorMessage = "Le mot de passe est requis")]
        [MinLength(6, ErrorMessage = "Le mot de passe doit comporter au minimum 6 caractères")]
        [DisplayName("Nouveau mot de passe")]
        public string NewPassword { get; set; }
        [Required(ErrorMessage = "La confirmation du mot de passe est requise.")]
        [DisplayName("Confirmer le mot de passe")]
        [Compare("NewPassword", ErrorMessage = "Le mot de passe et la confirmation ne correspondent pas.")]
        public string ConfirmPassword { get; set; }
        public string Token { get; set; }
    }
}