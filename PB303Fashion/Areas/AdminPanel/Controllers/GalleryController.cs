using Microsoft.AspNetCore.Mvc;
using PB303Fashion.DataAccessLayer;
using PB303Fashion.DataAccessLayer.Entities;
using PB303Fashion.Extensions;
using PB303Fashion.Models;
using static System.Net.Mime.MediaTypeNames;

namespace PB303Fashion.Areas.AdminPanel.Controllers
{
    public class GalleryController : AdminController
    {
        private readonly AppDbContext _dbContext;

        public GalleryController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public IActionResult Index()
        {
            return View();
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Gallery gallery)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            var isValid = true;

            foreach (var image in gallery.Images)
            {
                if (!image.IsImage())
                {
                    ModelState.AddModelError("", $"{image.FileName}-Sekil secilmelidir!");

                    isValid = false;

                    //break;
                }

                if (!image.IsAllowedSize(1))
                {
                    ModelState.AddModelError("", $"{image.FileName}-Sekilin hecmi 1mb-den cox olmamalidir!");

                    isValid = false;

                    //break;
                }          
            }

            if (!isValid) return View();

            foreach (var image in gallery.Images)
            {
                var imageName = await image.GenerateFileAsync(Constants.GalleryImagePath);
                gallery.ImageUrl = imageName;

                await _dbContext.Galleries.AddAsync(gallery);
                await _dbContext.SaveChangesAsync();
                gallery.Id = 0;
            }


            return RedirectToAction(nameof(Index));
        }
    }
}
