using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.ViewComponents;
using Microsoft.EntityFrameworkCore;
using PB303Fashion.DataAccessLayer;
using PB303Fashion.Models;

namespace PB303Fashion.ViewComponents
{
    public class FooterViewComponent : ViewComponent
    {
        private readonly AppDbContext _dbContext;

        public FooterViewComponent(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<ViewViewComponentResult> InvokeAsync()
        {
            var footer = await _dbContext.Footers.FirstOrDefaultAsync();

            return View(footer);
        }
    }
}
