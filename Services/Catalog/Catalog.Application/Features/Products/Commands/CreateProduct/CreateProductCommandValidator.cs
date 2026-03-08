using FluentValidation;

namespace Catalog.Application.Features.Products.Commands.CreateProduct
{
    public class CreateProductCommandValidator:AbstractValidator<CreateProductCommand>
    {
        public CreateProductCommandValidator()
        {
            RuleFor(x => x.BrandId)
                .IsInEnum().WithMessage("BrandId should be an enum")
                .NotEmpty().WithMessage("BrandId should not be empty");

            RuleFor(x => x.Price)
                .GreaterThan(0)
                .WithMessage("Price must be greater than zero");
        }
    }
}
