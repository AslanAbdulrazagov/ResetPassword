using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using PB303Fashion.DataAccessLayer;
using PB303Fashion.DataAccessLayer.Entities;
using PB303Fashion.Models;
using System.Net.Mail;
using System.Net;

namespace PB303Fashion.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<AppUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly SignInManager<AppUser> _signInManager;

        public AccountController(UserManager<AppUser> userManager, RoleManager<IdentityRole> roleManager, SignInManager<AppUser> signInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _signInManager = signInManager;
        }

        public IActionResult Register()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Register(RegisterViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var user = await _userManager.FindByNameAsync(model.Username);

            if (user != null)
            {
                ModelState.AddModelError("", "Bu adda istifadeci movcuddur!");

                return View();
            }

            var createdUser = new AppUser
            {
                Fullname = model.Fullname,
                UserName = model.Username,
                Email = model.Email,
            };

            var result = await _userManager.CreateAsync(createdUser, model.Password);

            
            if (!result.Succeeded)
            {
                foreach (var error in result.Errors)
                {
                    ModelState.AddModelError("", error.Description);
                }

                return View();
            }

            await _userManager.AddToRoleAsync(createdUser, RoleConstants.User);

            return RedirectToAction("index", "home");
        }

        public IActionResult Login()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Login(LoginViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var existUser = await _userManager.FindByNameAsync(model.Username);

            if (existUser == null)
            {
                ModelState.AddModelError("", "Username or password incorrert");

                return View();
            }

            var result = await _signInManager.PasswordSignInAsync(existUser, model.Password, true, true);

            if (result.IsLockedOut)
            {
                ModelState.AddModelError("", "You are blocked");

                return View();
            }

            if (!result.Succeeded)
            {
                ModelState.AddModelError("", "Username or password incorrert");

                return View();
            }

            return RedirectToAction("index", "home");
        }

        public async Task<IActionResult> Logout()
        {
            await _signInManager.SignOutAsync();

            return RedirectToAction("index", "home");
        }

        public IActionResult ForgetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ForgetPassword(ForgetViewModel model)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var existUser = await _userManager.FindByEmailAsync(model.Email);

            if (existUser == null)
            {
                ModelState.AddModelError("", "Bele istifadeci movcud deyil");
                return View();
            }

            var resetToken = await _userManager.GeneratePasswordResetTokenAsync(existUser);

            var resetLink = Url.Action(nameof(ResetPassword), "Account", new { model.Email, resetToken }, Request.Scheme, Request.Host.ToString());
            string test = "test";
            SendEmail(model.Email, test,resetLink);

            return View();
        }

        private void SendEmail(string email, string subject, string body)
        {
            NetworkCredential credential = new NetworkCredential("aslaneab@code.edu.az", "zrca uudk llid alzx");
            MailMessage message = new MailMessage();
            message.From = new MailAddress("aslaneab@code.edu.az");
            message.To.Add(new MailAddress(email));
            message.Subject = subject;
            message.IsBodyHtml = true;
            message.Body = body;
            using (SmtpClient client = new SmtpClient("smtp.gmail.com", 587))
            {

                client.UseDefaultCredentials = false;
                client.Credentials = credential;
                client.DeliveryMethod = SmtpDeliveryMethod.Network;
                client.EnableSsl = true;
               
                client.Send(message);
            }
        }

        public IActionResult ResetPassword()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> ResetPassword(ResetPasswordViewModel model, string email, string resetToken)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var existUser = await _userManager.FindByEmailAsync(email);

            if (existUser == null) return BadRequest();

            var result = await _userManager.ResetPasswordAsync(existUser, resetToken, model.Password);

            return RedirectToAction(nameof(Login));
        }
        
    }
}
