using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using PB303Fashion.Models;

namespace PB303Fashion.Areas.AdminPanel.Controllers
{
    [Area("AdminPanel")]
    [Authorize(Roles = $"{RoleConstants.Admin},{RoleConstants.Moderator}")]
    public class AdminController : Controller
    {

    }
}
