using System.ComponentModel.DataAnnotations;

namespace PB303Fashion.Models
{
    public class RegisterViewModel
    {
        public string Fullname {  get; set; }
        public string Username {  get; set; }
        [DataType(DataType.EmailAddress)]
        public string Email {  get; set; }
        [DataType(DataType.Password)]
        public string Password { get; set; }
        [DataType(DataType.Password), Compare(nameof(Password))]
        public string ConfirmPassword { get; set; }
    }
}
