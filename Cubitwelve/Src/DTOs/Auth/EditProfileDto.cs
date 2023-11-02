using System.ComponentModel.DataAnnotations;

namespace Cubitwelve.Src.Auth.DTOs
{
    public class EditProfileDto
    {
        [Required]
        public string Name { get; set; } = null!;

        [Required]
        public string FirstLastName { get; set; } = null!;

        [Required]
        public string SecondLastName { get; set; } = null!;

        [Required]
        [EmailAddress]
        public string Email { get; set; } = null!;

        [Required]
        public string Career { get; set; } = null!;
    }
}