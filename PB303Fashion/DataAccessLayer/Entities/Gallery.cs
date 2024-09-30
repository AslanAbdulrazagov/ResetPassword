using System.ComponentModel.DataAnnotations.Schema;

namespace PB303Fashion.DataAccessLayer.Entities
{
    public class Gallery : Entity
    {
        public string? ImageUrl {  get; set; }
        [NotMapped]
        public IFormFile[] Images { get; set; }
    }
}
