using Microsoft.AspNetCore.WebUtilities;
using System.Text.Json;

namespace Catalog.Application.Common.DTO
{
    public record CursorDto
    {
        public DateTimeOffset CreatedAt { get; init; }
        public Guid ProductId { get; init; }

        public string Encode()
        {
            var bytes = JsonSerializer.SerializeToUtf8Bytes(this);
            return WebEncoders.Base64UrlEncode(bytes);
        }

        public static CursorDto? TryDecode(string? cursor)
        {
            if (string.IsNullOrWhiteSpace(cursor))
                return null;

            try
            {
                var bytes = WebEncoders.Base64UrlDecode(cursor);
                return JsonSerializer.Deserialize<CursorDto>(bytes);
            }
            catch
            {
                return null;
            }
        }
    }
}
