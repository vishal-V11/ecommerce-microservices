namespace Identity.Api.Infrastructure
{
    public class RequestContext : IRequestContext
    {

        private readonly IHttpContextAccessor _httpContextAccessor;
        public RequestContext(IHttpContextAccessor httpContextAccessor)
        {
            _httpContextAccessor = httpContextAccessor;
        }
        public string IpAddress =>
            _httpContextAccessor.HttpContext?.Connection?.RemoteIpAddress?.ToString() ?? "unknown";

        public string UserAgent =>
            _httpContextAccessor.HttpContext?.Request?.Headers["User-Agent"].ToString() ?? "unkown";

        public string Device
        {
            get
            {
                var agent = UserAgent.ToLower();

                if (agent.Contains("mobile"))
                    return "Mobile";
                

                if (agent.Contains("tablet"))
                    return "Tablet";

                return "Web";
            }
        }

        public string DeviceId
        {
            get
            {
                var deviceId = _httpContextAccessor.HttpContext?
                    .Request.Headers["X-Device-Id"]
                    .ToString();

                // Validate GUID format
                if (!Guid.TryParse(deviceId, out _))
                    return "unknown";

                return deviceId;
            }
        }
    }
}
