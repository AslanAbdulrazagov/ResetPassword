using Microsoft.AspNetCore.Hosting;
using PB303Fashion.DataAccessLayer.Entities;
using PB303Fashion.Models;

namespace PB303Fashion.Extensions
{
    public static class FileExtensionMethods
    {
        public static bool IsImage(this IFormFile file)
        {
            return file.ContentType.Contains("image");
        }

        public static bool IsAllowedSize(this IFormFile file, int mb)
        {
            return file.Length <= mb * 1024 * 1024;
        }

        public static async Task<string> GenerateFileAsync(this IFormFile file, string path)
        {
            var imageName = $"{Guid.NewGuid()}-{file.FileName}";
            path = Path.Combine(path, imageName);

            using (var fs = new FileStream(path, FileMode.Create))
                await file.CopyToAsync(fs);


            return imageName;
        }
    }
}
