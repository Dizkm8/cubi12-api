using System.IdentityModel.Tokens.Jwt;
using System.Security.Authentication;
using System.Security.Claims;
using System.Text;
using Cubitwelve.Src.Common.Constants;
using Cubitwelve.Src.DTOs.Auth;
using Cubitwelve.Src.Exceptions;
using Cubitwelve.Src.Models;
using Cubitwelve.Src.Repositories.Interfaces;
using Cubitwelve.Src.Services.Interfaces;
using Microsoft.IdentityModel.Tokens;

namespace Cubitwelve.Src.Services
{
    public class AuthService : IAuthService
    {
        private readonly IUnitOfWork _unitOfWork;
        private readonly IConfiguration _configuration;
        private readonly IMapperService _mapperService;
        private readonly IHttpContextAccessor _ctxAccesor;
        private readonly string _jwtSecret;

        public AuthService(IUnitOfWork unitOfWork,
        IConfiguration configuration,
        IMapperService mapperService,
        IHttpContextAccessor ctxAccesor
        )
        {
            _unitOfWork = unitOfWork;
            _configuration = configuration;
            _mapperService = mapperService;
            _ctxAccesor = ctxAccesor;
            _jwtSecret = Environment.GetEnvironmentVariable("JWT_SECRET") ?? throw new InvalidJwtException("JWT_SECRET not found");
        }

        public async Task<LoginResponseDto> Login(LoginRequestDto loginRequestDto)
        {
            var user = await _unitOfWork.UsersRepository.GetByEmail(loginRequestDto.Email)
                ?? throw new InvalidCredentialException("Invalid Credentials");

            var verifyPassword = BCrypt.Net.BCrypt.Verify(loginRequestDto.Password, user.HashedPassword);
            if (!verifyPassword)
                throw new InvalidCredentialException("Invalid Credentials");

            if (!user.IsEnabled)
                throw new DisabledUserException("User is not enabled - Contact an administrator");

            var token = CreateToken(user.Email, user.Role.Name);
            var response = _mapperService.Map<User, LoginResponseDto>(user);
            MapMissingFields(user, token, response);
            return response;
        }

        public async Task<LoginResponseDto> Register(RegisterStudentDto registerStudentDto)
        {
            await ValidateEmailAndRUT(registerStudentDto.Email, registerStudentDto.RUT);

            var role = (await _unitOfWork.RolesRepository.Get(r => r.Name == RolesEnum.STUDENT)).FirstOrDefault();
            // This should never happen, if it does, something is wrong with the database
            if (role is null)
                throw new InternalErrorException("Role not found");

            var career = await _unitOfWork.CareersRepository.GetByID(registerStudentDto.CareerId);
            if (career is null)
                throw new EntityNotFoundException($"Career with ID: {registerStudentDto.CareerId} not found");

            var mappedUser = _mapperService.Map<RegisterStudentDto, User>(registerStudentDto);
            //TODO: Refactor this to MapperService
            mappedUser.RoleId = role.Id;
            mappedUser.CareerId = career.Id;
            mappedUser.IsEnabled = true;
            var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
            mappedUser.HashedPassword = BCrypt.Net.BCrypt.HashPassword(registerStudentDto.Password, salt);

            var createdUser = await _unitOfWork.UsersRepository.Insert(mappedUser);

            var token = CreateToken(createdUser.Email, createdUser.Role.Name);
            var response = _mapperService.Map<User, LoginResponseDto>(createdUser);
            // Not mapped fields
            MapMissingFields(createdUser, token, response);
            return response;
        }

        //TODO: Refactor this to MapperService
        private static void MapMissingFields(User createdUser, string token, LoginResponseDto response)
        {
            response.Token = token;
            response.Role = createdUser.Role.Name;
            response.Career = createdUser.Career.Name;
        }

        private async Task ValidateEmailAndRUT(string email, string rut)
        {
            var user = await _unitOfWork.UsersRepository.GetByEmail(email);
            if (user is not null)
                throw new DuplicateUserException("Email already in use");

            user = await _unitOfWork.UsersRepository.GetByRut(rut);
            if (user is not null)
                throw new DuplicateUserException("RUT already in use");
        }


        private string CreateToken(string email, string role)
        {
            var claims = new List<Claim>{
                new (ClaimTypes.Email, email),
                new (ClaimTypes.Role, role),
            };

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSecret));

            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256Signature);
            var token = new JwtSecurityToken(
                claims: claims,
                expires: DateTime.Now.AddDays(2),
                signingCredentials: creds
            );

            var jwt = new JwtSecurityTokenHandler().WriteToken(token);
            return jwt;
        }

        public string GetUserEmailInToken()
        {
            var httpUser = GetHttpUser();

            //Get Claims from JWT
            var userEmail = httpUser.FindFirstValue(ClaimTypes.Email) ??
                throw new UnauthorizedAccessException("Invalid user email in token");
            return userEmail;
        }

        public string GetUserRoleInToken()
        {
            var httpUser = GetHttpUser();

            //Get Claims from JWT
            var userRole = httpUser.FindFirstValue(ClaimTypes.Role) ??
                throw new UnauthorizedAccessException("Invalid role in token");
            return userRole;
        }

        private ClaimsPrincipal GetHttpUser()
        {
            //Check if the HttpContext is available to work with
            return (_ctxAccesor.HttpContext?.User) ??
                throw new UnauthorizedAccessException();
        }

        public async Task UpdatePassword(UpdatePasswordDto updatePasswordDto)
        {
            var userEmail = GetUserEmailInToken();
            var user = await _unitOfWork.UsersRepository.GetByEmail(userEmail)
                ?? throw new EntityNotFoundException($"User with email: {userEmail} do not exists");

            var verifyPassword = BCrypt.Net.BCrypt.Verify(updatePasswordDto.CurrentPassword, user.HashedPassword);
            if (!verifyPassword)
                throw new InvalidCredentialException("Invalid Current Password");

            var salt = BCrypt.Net.BCrypt.GenerateSalt(12);
            user.HashedPassword = BCrypt.Net.BCrypt.HashPassword(updatePasswordDto.Password, salt);

            await _unitOfWork.UsersRepository.Update(user);
        }
    }
}