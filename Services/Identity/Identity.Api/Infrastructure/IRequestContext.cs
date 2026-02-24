namespace Identity.Api.Infrastructure
{
    /// <summary>
    /// Provides access to metadata of the current HTTP request.
    /// This abstraction allows repositories and other components to 
    /// retrieve request-specific information (such as client IP address,
    /// browser user-agent and device type) without directly depending on
    /// ASP.NET Core HttpContext.
    /// 
    /// It helps maintain separation of concerns and keeps the data access
    /// layer independent from the web framework.
    /// </summary>
    public interface IRequestContext
    {
        string IpAddress { get; }
        string UserAgent { get; }
        string Device { get; }
        string DeviceId { get; }
    }
}
