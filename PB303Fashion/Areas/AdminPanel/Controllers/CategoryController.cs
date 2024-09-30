using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using PB303Fashion.DataAccessLayer;
using PB303Fashion.DataAccessLayer.Entities;
using PB303Fashion.Extensions;
using PB303Fashion.Models;

namespace PB303Fashion.Areas.AdminPanel.Controllers
{
    public class CategoryController : AdminController
    {
        private readonly AppDbContext _dbContext;
        private readonly IWebHostEnvironment _webHostEnvironment;

        public CategoryController(AppDbContext dbContext, IWebHostEnvironment webHostEnvironment)
        {
            _dbContext = dbContext;
            _webHostEnvironment = webHostEnvironment;           
        }

        public async Task<IActionResult> Index()
        {
            var categories = await _dbContext.Categories.ToListAsync();

            return View(categories);
        }

        public IActionResult Create()
        {
            return View();
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Create(Category category)
        {
            if (!ModelState.IsValid)
            {
                return View();
            }

            if (!category.ImageFile.IsImage())
            {
                ModelState.AddModelError("ImageFile", "Sekil secmelisiz");

                return View();
            }

            if (!category.ImageFile.IsAllowedSize(1))
            {
                ModelState.AddModelError("ImageFile", "Sekil olcusu max 1mb olmalidir");

                return View();
            }

            var imageName = await category.ImageFile.GenerateFileAsync(Constants.CategoryImagePath);

            category.ImageUrl = imageName;  

            await _dbContext.Categories.AddAsync(category);
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Delete(int? id)
        {
            if (id == null) return NotFound();

            var category = await _dbContext.Categories.FindAsync(id);

            if (category == null) return NotFound();

            return View(category);
        }

        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> DeleteCategory(int? id)
        {
            if (id == null) return NotFound();

            var category = await _dbContext.Categories.FindAsync(id);

            if (category == null) return NotFound();

            _dbContext.Categories.Remove(category);

            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }

        public async Task<IActionResult> Update(int? id)
        {
            if (id == null) return NotFound();

            var category = await _dbContext.Categories.FindAsync(id);

            if (category == null) return NotFound();

            return View(category);
        }


        [HttpPost]
        [ValidateAntiForgeryToken]
        public async Task<IActionResult> Update(Category category)
        {
            var existCategory = await _dbContext.Categories.FindAsync(category.Id);

            if (existCategory == null) return NotFound();

            if (!ModelState.IsValid)
            {
                return View(existCategory);
            }

            if (category.ImageFile != null)
            {
                if (!category.ImageFile.IsImage())
                {
                    ModelState.AddModelError("ImageFile", "Sekil secmelisiz");

                    return View();
                }

                if (!category.ImageFile.IsAllowedSize(1))
                {
                    ModelState.AddModelError("ImageFile", "Sekil olcusu max 1mb olmalidir");

                    return View();
                }
            }     

            var existCategoryName = await _dbContext.Categories.AnyAsync(x => x.Name.ToLower().Equals(category.Name.ToLower()) && x.Id != existCategory.Id);

            if (existCategoryName)
            {
                ModelState.AddModelError("Name", "Bu adda kateqoriya movcuddur");

                return View(existCategory);
            }

            if (category.ImageFile != null)
            {
                var path = Path.Combine(Constants.CategoryImagePath, existCategory.ImageUrl!);

                if (System.IO.File.Exists(path))
                    System.IO.File.Delete(path);

                var imageName = await category.ImageFile.GenerateFileAsync(Constants.CategoryImagePath);

                existCategory.ImageUrl = imageName;
            }

            existCategory.Name = category.Name;

            _dbContext.Categories.Update(existCategory);
            await _dbContext.SaveChangesAsync();

            return RedirectToAction(nameof(Index));
        }
    }
}
