namespace Ordering.Domain.ValueObjects
{
    public sealed class DeliveryAddress
    {
        public string FullName { get; }
        public string AddressLine1 { get; }
        public string? AddressLine2 { get; }
        public string City { get; }
        public string State { get; }
        public string Pincode { get; }
        public string PhoneNumber { get; }

        public DeliveryAddress(
        string fullName,
        string addressLine1,
        string? addressLine2,
        string city,
        string state,
        string pincode,
        string phoneNumber)
        {
            FullName = fullName;
            AddressLine1 = addressLine1;
            AddressLine2 = addressLine2;
            City = city;
            State = state;
            Pincode = pincode;
            PhoneNumber = phoneNumber;
        }

        // EF Core requires a parameterless constructor for owned entity hydration
        private DeliveryAddress() { }
    }
}
