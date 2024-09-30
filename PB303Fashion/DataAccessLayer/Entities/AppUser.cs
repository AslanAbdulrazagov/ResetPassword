using Microsoft.AspNetCore.Identity;

namespace PB303Fashion.DataAccessLayer.Entities
{
    public class AppUser : IdentityUser
    {
        public string Fullname {  get; set; }
    }
}
