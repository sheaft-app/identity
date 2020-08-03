using System.ComponentModel.DataAnnotations;

namespace Sheaft.Identity.ViewModels
{
    public class RegisterRequestViewModel
    {
        [Required(ErrorMessage = "L'adresse email est requise.")]
        [EmailAddress]
        [Display(Name = "Addresse email")]
        public string Email { get; set; }

        [Required(ErrorMessage = "Le mot de passe est requis.")]
        [DataType(DataType.Password)]
        [Display(Name = "Mot de passe")]
        public string Password { get; set; }
        [Display(Name = "Nom")]
        public string LastName { get; set; }
        [Display(Name = "Prénom")]
        public string FirstName { get; set; }
    }
}