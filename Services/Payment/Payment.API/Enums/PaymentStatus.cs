using System.ComponentModel;

namespace Payment.API.Enums
{
    public enum PaymentStatus
    {
        [Description("Pending")]
        Pending,
        [Description("Succeeded")]
        Succeeded,
        [Description("Failed")]
        Failed
    }
}
