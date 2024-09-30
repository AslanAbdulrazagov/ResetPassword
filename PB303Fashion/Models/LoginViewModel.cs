using System.ComponentModel.DataAnnotations;

namespace PB303Fashion.Models
{
    public class LoginViewModel
    {
        public string Username {  get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
    }
}
