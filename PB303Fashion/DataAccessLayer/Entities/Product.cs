using Microsoft.AspNetCore.Mvc.Rendering;
using System.ComponentModel.DataAnnotations.Schema;

namespace PB303Fashion.DataAccessLayer.Entities
{
    public class Product : Entity
    {
        public string Name { get; set; }
        public double Price { get; set; }
        public string ImageUrl { get; set; }
        public int CategoryId {  get; set; }
        [NotMapped]
        public IFormFile? ImageFile { get; set; }
        public Category? Category { get; set; }
        [NotMapped]
        public List<SelectListItem> CategoryListItems { get; set; }
    }
}
