using Identity.Api.DTOs;
using Identity.Api.Repository;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using System.Security.Claims;

namespace Identity.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IAuthRepository _authRepository;
        private readonly ILogger<AuthController> _logger;
        public AuthController(IAuthRepository repository, ILogger<AuthController> logger)
        {
            _authRepository = repository;
            _logger = logger;
        }

        /// <summary>
        /// Registers a new user account.
        /// </summary>
        /// <remarks>
        /// Password requirements:
        /// - Minimum 8 characters
        /// - At least one uppercase letter
        /// - At least one lowercase letter
        /// - At least one digit
        /// - At least one special character (@$!%*?&amp;^#-_)
        /// </remarks>
        /// <response code="201">User registered successfully</response>
        /// <response code="409">Email is already registered</response>
        /// <response code="422">Validation errors (e.g. weak password)</response>
        [HttpPost("register")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(Response<RegisterResponseDto>), StatusCodes.Status201Created)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status409Conflict)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status422UnprocessableEntity)]
        [ProducesResponseType(typeof(ValidationProblemDetails), StatusCodes.Status400BadRequest)]
        public async Task<IActionResult> Register([FromBody] RegisterRequestDto dto)
        {
            // Model validation is handled automatically by [ApiController] — if we reach here,
            // all [Required], [EmailAddress], [StringLength] etc. annotations have passed.

            var result = await _authRepository.RegisterUser(dto);

            return result.StatusCode switch
            {
                201 => StatusCode(201, result),
                409 => Conflict(result),
                422 => UnprocessableEntity(result),
                _ => StatusCode(result.StatusCode, result)
            };
        }

        /// <summary>
        /// Authenticates a user and returns access + refresh tokens.
        /// </summary>
        /// <response code="200">Login successful, tokens returned</response>
        /// <response code="401">Invalid credentials</response>
        [HttpPost("login")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(Response<TokenResponseDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> Login([FromBody] LoginRequestDto dto, CancellationToken ct)
        {
            var result = await _authRepository.AuthenticateUser(dto, ct);

            return result.StatusCode switch
            {
                200 => Ok(result),
                401 => Unauthorized(result),
                _ => StatusCode(result.StatusCode, result)
            };
        }

        /// <summary>
        /// Issues a new access token using a valid refresh token (token rotation).
        /// </summary>
        /// <response code="200">New tokens issued</response>
        /// <response code="401">Invalid or reused refresh token — all sessions revoked</response>
        [HttpPost("refresh")]
        [AllowAnonymous]
        [ProducesResponseType(typeof(Response<TokenResponseDto>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status401Unauthorized)]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshRequestDto dto, CancellationToken ct = default)
        {
            var result = await _authRepository.RefreshAccessToken(dto, ct);

            return result.StatusCode switch
            {
                200 => Ok(result),
                401 => Unauthorized(result),
                _ => StatusCode(result.StatusCode, result)
            };
        }

        /// <summary>
        /// Logs out the user by revoking the provided refresh token.
        /// </summary>
        /// <response code="200">Logged out successfully</response>
        /// <response code="401">Invalid refresh token</response>
        /// <summary>
        /// Logs out the authenticated user by revoking their refresh token.
        /// Requires a valid JWT — the token ownership is verified against the
        /// authenticated user's ID before revocation is allowed.
        /// </summary>
        /// <response code="200">Logged out successfully</response>
        /// <response code="401">Missing/invalid JWT or refresh token not found</response>
        /// <response code="403">Refresh token does not belong to the authenticated user</response>
        [HttpPost("logout")]
        [Authorize]                         // ← JWT must be valid to even reach this method
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status200OK)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status401Unauthorized)]
        [ProducesResponseType(typeof(Response<object>), StatusCodes.Status403Forbidden)]
        public async Task<IActionResult> Logout([FromBody] LogoutRequestDto dto, CancellationToken ct)
        {
            // Extract the authenticated user's ID from the JWT "uid" claim set in GenerateJwtToken().
            // If missing the token is malformed — should never happen with a valid JWT but we guard it.
            var authenticatedUserId = User.FindFirstValue("uid");

            if (string.IsNullOrWhiteSpace(authenticatedUserId))
            {
                _logger.LogWarning("Logout attempt with JWT missing 'uid' claim. IP: {Ip}",
                    HttpContext.Connection.RemoteIpAddress);
                return Unauthorized(Response<object>.Fail(
                    errorMessage: "Invalid token: user identity could not be resolved",
                    statusCode: 401));
            }

            // Repository verifies the refresh token belongs to this user before revoking.
            // This prevents user A from logging out user B by submitting B's refresh token.
            var result = await _authRepository.Logout(dto, authenticatedUserId, ct);

            return result.StatusCode switch
            {
                200 => Ok(result),
                401 => Unauthorized(result),
                403 => StatusCode(403, result),
                _ => StatusCode(result.StatusCode, result)
            };

        }
    }
}
