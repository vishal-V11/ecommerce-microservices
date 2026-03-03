using Identity.Api.Data;
using Identity.Api.DTOs;
using Identity.Api.Helpers;
using Identity.Api.Infrastructure;
using Identity.Api.Models;
using Identity.Api.Settings;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;

namespace Identity.Api.Repository
{
    public class AuthRepository : IAuthRepository
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly ApplicationDbContext _context;
        private readonly IRequestContext _requestContext;
        private readonly ILogger<AuthRepository> _logger;
        private readonly JwtSettings _jwtSettings;
        public AuthRepository
            (
                UserManager<ApplicationUser> userManager,
                ApplicationDbContext context,
                IRequestContext requestContext,
                ILogger<AuthRepository> logger,
                IOptions<JwtSettings> jwtSettings
            )
        {
            _userManager = userManager;
            _context = context;
            _requestContext = requestContext;
            _logger = logger;
            _jwtSettings = jwtSettings.Value;
        }
        public async Task<Response<RegisterResponseDto>> RegisterUser(RegisterRequestDto register)
        {

            var normalizedEmail = register.Email.Trim().ToLowerInvariant();

            var newUser = new ApplicationUser
            {
                UserName = normalizedEmail,
                Email = normalizedEmail,
                FirstName = register.FirstName.Trim(),
                LastName = register.LastName.Trim(),
            };


            // Hand off directly to Identity — CreateAsync handles duplicate detection
            // atomically at the DB level, eliminating the race condition of a pre-check.
            var result = await _userManager.CreateAsync(newUser, register.Password);

            if (result.Succeeded)
            {
                _logger.LogInformation("User registered successfully. UserId: {UserId}", newUser.Id);

                return Response<RegisterResponseDto>.Success(
                    data: new RegisterResponseDto
                    {
                        UserId = newUser.Id,
                        Email = newUser.Email!,
                        FullName = $"{newUser.FirstName} {newUser.LastName}",
                        CreatedAt = DateTimeOffset.UtcNow
                    },
                    message: "User registered successfully",
                    statusCode: 201);
            }

            // Separate duplicate email errors from other identity errors (e.g. weak password)
            // to give the caller accurate HTTP semantics without leaking enumeration details.
            bool isDuplicateEmail = result.Errors.Any(e =>
                e.Code is "DuplicateUserName" or "DuplicateEmail");

            if (isDuplicateEmail)
            {
                _logger.LogWarning("Registration attempted with already registered email. Email: {Email}", normalizedEmail);
                return Response<RegisterResponseDto>.Fail(
                    errorMessage: "An account with this email already exists",
                    statusCode: 409);
            }


            // Collect all other identity errors (e.g. password policy violations)
            var errors = result.Errors
                .Select(e => e.Description)
                .ToList();

            _logger.LogWarning("Registration failed for {Email}. Errors: {Errors}",
                normalizedEmail, string.Join(", ", errors));

            return Response<RegisterResponseDto>.Fail(
                errorMessage: string.Join(" ", errors),
                statusCode: 422);

        }

        public async Task<Response<TokenResponseDto>> AuthenticateUser(LoginRequestDto login, CancellationToken ct)
        {
            //Get User
            var normalizedEmail = login.Email.Trim().ToLowerInvariant();
            var user = await _userManager.FindByEmailAsync(normalizedEmail);
            if (user == null || !await _userManager.CheckPasswordAsync(user, login.Password))
            {
                _logger.LogWarning("Failed login attempt. Email: {Email}, IP: {Ip}",
                    normalizedEmail, _requestContext.IpAddress);
                return Response<TokenResponseDto>.Fail(errorMessage: "Invalid credentials", statusCode: 401);
            }

            var JwtUserInfo = new JwtUserInfo
            {
                Email = user.Email!,
                UserName = user.UserName!,
                UserId = user.Id
            };

            //Generate Token
            string accessToken = GenerateJwtToken(JwtUserInfo);

            var refreshToken = await CreateRefreshTokenAsync(user.Id, true, ct);

            _logger.LogInformation("User authenticated successfully. UserId: {UserId}", user.Id);

            return Response<TokenResponseDto>
                .Success(
                    data: new TokenResponseDto
                    {
                        AccessToken = accessToken,
                        RefreshToken = refreshToken,
                        ExpiryTime = DateTime.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes)
                    }, message: "Logged in successfully", statusCode: 200);
        }

        public async Task<Response<TokenResponseDto>> RefreshAccessToken(RefreshRequestDto dto, CancellationToken ct)
        {
            var tokenHash = TokenHasher.Hash(dto.RefreshToken);
            //Check if its a valid refresh token
            var tokenData = await _context.RefreshToken
                                        .Include(x => x.User)
                                        .Where(x =>
                                            x.TokenHash == tokenHash)
                                        .Select(x => new
                                        {
                                            x.Id,
                                            x.UserId,
                                            x.TokenHash,
                                            x.Expires,
                                            x.Revoked,
                                            x.CreatedByIp,
                                            x.UserAgent,
                                            x.Device,
                                            x.DeviceId,
                                            UserEmail = x.User.Email,
                                            UserName = x.User.UserName
                                        })
                                        .FirstOrDefaultAsync(ct);

            //Case 1: Invalid refresh token
            if (tokenData == null)
            {
                _logger.LogWarning("Refresh attempt with unknown token. IP: {Ip}", _requestContext.IpAddress);
                return Response<TokenResponseDto>.Fail(errorMessage: "Invalid refresh token", statusCode: 401);
            }

            //Case 2: Token expired
            if (tokenData.Expires <= DateTimeOffset.UtcNow)
            {
                _logger.LogInformation("Expired refresh token used. UserId: {UserId}", tokenData.UserId);
                return Response<TokenResponseDto>.Fail(errorMessage: "Refresh token has expired", statusCode: 401);
            }

            // Case 3: Revoked token reused → security breach, revoke all sessions
            if (tokenData.Revoked != null)
            {
                _logger.LogCritical("Refresh token reuse detected. UserId: {UserId}. Revoking all sessions.", tokenData.UserId);

                // Revoke all active tokens for this user
                await RevokeUserTokenAsync(tokenData.UserId, ct);

                return Response<TokenResponseDto>.Fail(errorMessage: "Session compromised. Please log in again.", statusCode: 401);
            }

            //Soft fingerprint check
            if (tokenData.CreatedByIp != _requestContext.IpAddress ||
                tokenData.UserAgent != _requestContext.UserAgent ||
                tokenData.DeviceId != _requestContext.DeviceId)
            {
                _logger.LogWarning(
                    "Refresh token fingerprint mismatch for user {Email}. OldIP: {OldIp}, NewIP: {NewIp}"
                    , tokenData.UserEmail
                    , tokenData.CreatedByIp
                    , _requestContext.IpAddress
                );
            }

            // Revoke the current refresh token (rotation)
            await RevokeTokenAsync(tokenData.Id, ct);

            var JwtUserInfo = new JwtUserInfo { Email = tokenData.UserEmail!, UserName = tokenData.UserName!, UserId = tokenData.UserId };

            //Generate JwtToken 
            var accessToken = GenerateJwtToken(JwtUserInfo);
            var refreshToken = await CreateRefreshTokenAsync(tokenData.UserId, false, ct);

            _logger.LogInformation("Tokens rotated successfully. UserId: {UserId}", tokenData.UserId);
            return Response<TokenResponseDto>
                .Success(data: new TokenResponseDto
                {
                    AccessToken = accessToken,
                    RefreshToken = refreshToken,
                    ExpiryTime = DateTimeOffset.UtcNow.AddMinutes(_jwtSettings.DurationInMinutes),
                }, message: "Access token refreshed successfully", statusCode: 200);

        }

        public async Task<Response<object>> Logout(LogoutRequestDto dto,string authenticatedUserId, CancellationToken ct)
        {
            var tokenHash = TokenHasher.Hash(dto.RefreshToken);

            // Fetch the token to check existence
            var tokenData = await _context.RefreshToken
                .Where(x => x.TokenHash == tokenHash)
                .Select(x => new { x.Id, x.UserId, x.Device, x.Revoked })
                .FirstOrDefaultAsync(ct);

            // Case 1: Token doesn't exist at all
            if (tokenData == null)
            {
                _logger.LogWarning("Logout with unknown token. IP: {Ip}", _requestContext.IpAddress);
                return Response<object>.Fail(errorMessage: "Invalid refresh token", statusCode: 401);
            }

            // Case 2: Token exists but belongs to a different user — ownership violation.
            // Return 403 Forbidden, not 404, so the caller knows the token was found
            // but they're not allowed to revoke it.
            if (tokenData.UserId != authenticatedUserId)
            {
                _logger.LogWarning(
                    "Logout ownership violation. AuthenticatedUserId: {AuthUserId}, TokenOwnerUserId: {TokenUserId}, IP: {Ip}",
                    authenticatedUserId, tokenData.UserId, _requestContext.IpAddress);

                return Response<object>.Fail(
                    errorMessage: "You are not authorized to revoke this token",
                    statusCode: 403);
            }

            // Case 3: Token already revoked — idempotent, just return success.
            // Don't error on double-logout (e.g. user taps logout twice).
            if (tokenData.Revoked != null)
            {
                _logger.LogInformation("Logout called on already-revoked token. UserId: {UserId}", authenticatedUserId);
                return Response<object>.Success(data: null, message: "Already logged out", statusCode: 200);
            }

            //Revoke the refresh token 
            await RevokeTokenAsync(tokenData.Id,ct);

            _logger.LogInformation("User logged out successfully. UserId: {UserId}, Device: {Device}",
                authenticatedUserId, tokenData.Device);
            return Response<object>.Success(data: null, message: "Logged out successfully", statusCode: 200);

        }


        /// <summary>
        /// Generates a refresh token and saves it to the refresh tokens table for a particular user device.
        /// </summary>
        /// <param name="UserId"></param>
        /// <param name="revokeExistingDeviceTokens">a flag which indicates whether to revoke the previous device tokens</param>
        /// <param name="ct">Cancellation token</param>
        /// <returns>the generated refresh token</returns>
        private async Task<string> CreateRefreshTokenAsync(string UserId, bool revokeExistingDeviceTokens, CancellationToken ct)
        {
            if (revokeExistingDeviceTokens)
            {
                //Sanitize the previous generated tokens for the device and particular user
                await _context.RefreshToken
                    .Where(x => x.UserId == UserId &&
                            x.DeviceId == _requestContext.DeviceId &&
                            x.Revoked == null)
                    .ExecuteUpdateAsync(setters => setters
                        .SetProperty(x => x.Revoked, DateTimeOffset.UtcNow), ct);
            }

            // Generate raw token
            var rawToken = GenerateRefreshToken();
            var tokenHash = TokenHasher.Hash(rawToken);

            var refreshTokenModel = new RefreshToken()
            {
                Expires = DateTime.UtcNow.AddDays(Convert.ToDouble(_jwtSettings.RefreshTokenExpiryInDays)),
                Created = DateTimeOffset.UtcNow,
                TokenHash = tokenHash,
                UserId = UserId,
                CreatedByIp = _requestContext.IpAddress,
                UserAgent = _requestContext.UserAgent,
                Device = _requestContext.Device,
                DeviceId = _requestContext.DeviceId,
            };

            await _context.RefreshToken.AddAsync(refreshTokenModel, ct);
            await _context.SaveChangesAsync(ct);

            return rawToken;
        }

        /// <summary>
        /// Revokes the refresh token for all the active session irrespective of the Device
        /// </summary>
        /// <param name="UserId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        private async Task RevokeUserTokenAsync(string UserId, CancellationToken ct)
        {
            await _context.RefreshToken.Where(x => x.UserId == UserId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(y => y.Revoked, DateTimeOffset.UtcNow)
                , ct);
        }

        /// <summary>
        /// Revokes the refresh token for a particular device only
        /// </summary>
        /// <param name="TokenId"></param>
        /// <param name="ct"></param>
        /// <returns></returns>
        private async Task RevokeTokenAsync(int TokenId, CancellationToken ct)
        {
            await _context.RefreshToken.Where(x => x.Id == TokenId)
                .ExecuteUpdateAsync(setters => setters
                    .SetProperty(y => y.Revoked, DateTimeOffset.UtcNow)
                    .SetProperty(y => y.LastUsed, DateTimeOffset.UtcNow)
                , ct);
        }

        #region Private Token methods

        private string GenerateJwtToken(JwtUserInfo user)
        {
            var Claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub,user.Email!),
                new Claim(ClaimTypes.Name,user.UserName!),
                new Claim(ClaimTypes.Role,user.Role),
                new Claim("uid",user.UserId),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat,   DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),ClaimValueTypes.Integer64)
            };

            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SecretKey));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);

            var token = new JwtSecurityToken(
                issuer: _jwtSettings.Issuer,
                audience: _jwtSettings.Audience,
                signingCredentials: credentials,
                claims: Claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(_jwtSettings.DurationInMinutes))
            );

            _logger.LogInformation("Jwt token generated for user {email}", user.Email);
            return new JwtSecurityTokenHandler().WriteToken(token);

        }

        private string GenerateRefreshToken()
        {
            var randomNumber = new byte[64];
            using var rng = RandomNumberGenerator.Create();
            rng.GetBytes(randomNumber);
            return Convert.ToBase64String(randomNumber);
        }

        #endregion


    }
}
