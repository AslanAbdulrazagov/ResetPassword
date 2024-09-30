using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Newtonsoft.Json;
using PB303Fashion.DataAccessLayer;
using PB303Fashion.Models;

namespace PB303Fashion.Controllers
{
    public class HomeController : Controller
    {
        private readonly AppDbContext _dbContext;

        public HomeController(AppDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task<IActionResult> Index()
        {
            var categories = await _dbContext.Categories.ToListAsync();
            var products = await _dbContext.Products.Take(5).ToListAsync();

            HttpContext.Session.SetString("ses", "hello");
            Response.Cookies.Append("cookie", "cookieValue",new CookieOptions { Expires = DateTimeOffset.Now.AddMinutes(5)});

            var model = new HomeViewModel()
            {
                Categories = categories,
                Products = products,
            };
            
            return View(model);
        }

        public async Task<IActionResult> Partial()
        {
            var products = await _dbContext.Products.Skip(5).Take(5).ToListAsync();

            return PartialView("_ProductsPartial", products);
        }

        public IActionResult Basket()
        {
            //var sessionValue = HttpContext.Session.GetString("ses");
            //var cookieValue = Request.Cookies["cookie"];

            //return Content(sessionValue + "-" + cookieValue);

            var basketInString = Request.Cookies["basket"];
            var basketViewModels = JsonConvert.DeserializeObject<List<BasketViewModel>>(basketInString);
           
            var newBasketViewModel=new List<BasketViewModel>();

            foreach (var item in basketViewModels)
            {
                var existProduct = _dbContext.Products.Find(item.ProductId);

                if (existProduct == null) continue;

                newBasketViewModel.Add(new BasketViewModel
                {
                    ProductId = existProduct.Id,
                    Name = existProduct.Name,
                    ImageUrl = existProduct.ImageUrl,
                    Price = existProduct.Price,
                    Count = item.Count,
                });
            }

            return Json(newBasketViewModel);
        }

        public async Task<IActionResult> AddToBasket(int? id)
        {
            var product = await _dbContext.Products.FindAsync(id);

            if (product == null) return BadRequest();

            var basketViewModels = new List<BasketViewModel>();

            if (string.IsNullOrEmpty(Request.Cookies["basket"]))
            {
                basketViewModels.Add(new BasketViewModel
                {
                    ProductId = product.Id,
                    Name = product.Name,
                    ImageUrl = product.ImageUrl,
                    Price = product.Price,
                    Count = 1
                });
            }
            else
            {
                basketViewModels = JsonConvert.DeserializeObject<List<BasketViewModel>>(Request.Cookies["basket"]);

                var existProduct = basketViewModels.Find(x => x.ProductId == product.Id);
                if (existProduct == null)
                {
                    basketViewModels.Add(new BasketViewModel
                    {
                        ProductId = product.Id,
                        Name = product.Name,
                        ImageUrl = product.ImageUrl,
                        Price = product.Price,
                        Count = 1
                    });
                }
                else
                {
                    existProduct.Count++;
                    existProduct.Name = product.Name;
                    existProduct.Price = product.Price;
                    existProduct.ImageUrl = product.ImageUrl;
                }
            }

            Response.Cookies.Append("basket", JsonConvert.SerializeObject(basketViewModels));

            return Json(new { basketViewModels, Count = basketViewModels.Sum(x => x.Count), Sum = basketViewModels.Sum(y => y.Count * y.Price) });
        }
    }
}
