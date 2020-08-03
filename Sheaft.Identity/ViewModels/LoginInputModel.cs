﻿using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.DataAnnotations;

namespace Sheaft.Identity.ViewModels
{
    public class LoginInputModel
    {
        [Required]
        public string Username { get; set; }
        [Required]
        public string Password { get; set; }
        public bool RememberLogin { get; set; }
        public string ReturnUrl { get; set; }
    }


    public class RegisterInputModel : LoginInputModel
    {
        [DisplayName("Prénom")]
        public string FirstName { get; set; }
        [DisplayName("Nom")]
        public string LastName { get; set; }
        [Required(ErrorMessage = "La confirmation du mot de passe est requise.")]
        [DisplayName("Confirmer le mot de passe")]
        [Compare("Password", ErrorMessage = "Le mot de passe et la confirmation ne correspondent pas.")]
        public string ConfirmPassword { get; set; }
    }

    public class UpdateUserModel
    {
        public string Id { get; set; }
        [DisplayName("Nom d'utilisateur")]
        public string Username { get; set; }
        [DisplayName("Prénom")]
        public string FirstName { get; set; }
        [DisplayName("Nom")]
        public string LastName { get; set; }
        [DisplayName("Email")]
        public string Email { get; set; }
        [DisplayName("Téléphone")]
        public string Phone { get; set; }
        [DisplayName("Image")]
        public string Picture { get; set; }

        public IEnumerable<string> Roles { get; set; }
        public Guid? CompanyId { get; set; }
    }

    public class UpdateUserPictureModel
    {
        public string Id { get; set; }
        public string Picture { get; set; }
    }

    public class UpdatePasswordModel
    {
        public string Id { get; set; }
        public string OldPassword { get; set; }
        public string NewPassword { get; set; }
        public string ConfirmPassword { get; set; }
    }
}