using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using PB303Fashion.DataAccessLayer.Entities;
using PB303Fashion.Models;

namespace PB303Fashion.DataAccessLayer
{
    public class DataInitializer
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly AppDbContext _dbContext;
        private readonly SuperAdmin _superAdmin;
        public DataInitializer(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, AppDbContext dbContext, IOptions<SuperAdmin> superAdmin)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _dbContext = dbContext;
            _superAdmin = superAdmin.Value;
        }

        public async Task SeedDataAsync()
        {
            await _dbContext.Database.MigrateAsync();

            var roles = new List<string>() { RoleConstants.Admin, RoleConstants.Moderator, RoleConstants.User };

            foreach (var role in roles)
            {
                if (await _roleManager.FindByNameAsync(role) != null) continue;

                await _roleManager.CreateAsync(new IdentityRole { Name = role });
            }

            var user = new AppUser
            {
                Fullname = _superAdmin.Fullname,
                UserName = _superAdmin.Username,
                Email = _superAdmin.Email,
            };

            if (await _userManager.FindByNameAsync(user.UserName) != null) return;


            var result = await _userManager.CreateAsync(user, _superAdmin.Password);

            if (result.Succeeded)
            {
                await _userManager.AddToRoleAsync(user, RoleConstants.User);
            }
        }
    }
}
