using Identity.Api.DTOs;
using Identity.Api.Models;
using Microsoft.AspNetCore.Identity;

namespace Identity.Api.Repository
{
    public interface IAuthRepository
    {
        /// <summary>
        /// Registers a new user.
        /// - No pre-check for existing email (avoids race condition); relies on Identity's built-in duplicate detection.
        /// - Normalizes email to lowercase before storage.
        /// - Returns a structured error map on validation/identity failures.
        /// - Never leaks whether an email is already registered (returns generic conflict message).
        /// </summary>
        Task<Response<RegisterResponseDto>> RegisterUser(RegisterRequestDto register);
        /// <summary>
        /// Authenticates a user and returns a JWT + refresh token pair.
        /// </summary>
        Task<Response<TokenResponseDto>> AuthenticateUser(LoginRequestDto login,CancellationToken ct);

        /// <summary>
        /// Issues a new access token + refresh token by validating and rotating the current refresh token.
        /// Detects reuse attacks and invalidates all sessions for the user on breach.
        /// </summary>
        Task<Response<TokenResponseDto>> RefreshAccessToken(RefreshRequestDto dto, CancellationToken ct);

        /// <summary>
        /// Revokes the refresh token for the current device session.
        /// Does not validate token ownership against the JWT user here — 
        /// ensure the controller validates the authenticated user before calling.
        /// </summary>
        /// <summary>
        /// Revokes the refresh token for the current session.
        /// Verifies the token belongs to the authenticated user before revoking —
        /// prevents one user from logging out another user's session.
        /// </summary>
        /// <param name="dto">Request containing the refresh token to revoke</param>
        /// <param name="authenticatedUserId">The UserId extracted from the validated JWT in the controller</param>
        /// <param name="ct">Cancellation token</param>
        Task<Response<object>> Logout(LogoutRequestDto dto,string authenticatedUserIdUserId, CancellationToken ct);
    }
}
