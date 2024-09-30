using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace PB303Fashion.DataAccessLayer.Entities
{
    public class Category : Entity
    {
        public string Name { get; set; }
        public string? ImageUrl {  get; set; }
        [NotMapped]
        public IFormFile? ImageFile { get; set; }
        public ICollection<Product> Products { get; set; } = new List<Product>();
    }
}
