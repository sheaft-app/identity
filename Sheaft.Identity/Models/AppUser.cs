using Microsoft.AspNetCore.Identity;
using System;

namespace Sheaft.Identity.Models
{
    public class AppUser : IdentityUser
    {
        public AppUser()
        {
            Id = Guid.NewGuid().ToString("N");
        }

        public string FirstName { get; set; }
        public string LastName { get; set; }
    }
}
