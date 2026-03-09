# Testing Strategy

## Current Baseline

- Build validation:
  - `dotnet build src/Metria.Api/Metria.Api.csproj -c Release`
- Manual smoke validation for integration-critical flows:
  - signup/login
  - google oauth
  - goals/sub-goals CRUD
  - checkout + webhook + subscription status

## Testing Standards (AAA + Moq + Bogus + FluentValidation)

Use these standards as default for new automated tests.

### Test Structure (AAA)

- Arrange:
  - prepare input, mocks, and test data
- Act:
  - execute one behavior under test
- Assert:
  - verify expected result and interactions

Keep one clear assertion objective per test.

### Tooling Guidelines

- `xUnit`: base test framework
- `Moq`: mock dependencies and verify interactions
- `Bogus`: generate deterministic fake data for inputs/entities
- `FluentAssertions`: expressive assertions
- `FluentValidation`:
  - validate command/DTO rules through validator unit tests
  - test valid and invalid payload paths

### Naming Convention

- Method names should follow:
  - `MethodName_ShouldExpectedBehavior_WhenCondition`
- Example:
  - `CreateGoal_ShouldReturnBadRequest_WhenStartDateIsAfterEndDate`

### Minimal Unit Test Pattern

```csharp
[Fact]
public async Task Process_ShouldReturnError_WhenPayloadIsInvalid()
{
    // Arrange
    var faker = new Bogus.Faker("pt_BR");
    var dto = new CreateGoalDto(
        Text: faker.Lorem.Sentence(),
        Period: GoalPeriod.Monthly,
        StartDate: DateTime.UtcNow.AddDays(10),
        EndDate: DateTime.UtcNow.AddDays(1),
        Category: faker.Commerce.Categories(1)[0]);

    var validator = new CreateGoalDtoValidator();

    // Act
    var result = await validator.ValidateAsync(dto);

    // Assert
    result.IsValid.Should().BeFalse();
}
```

## Recommended Regression Checklist

1. `GET /health-check` returns `200`
2. Login issues valid JWT
3. Protected endpoints reject missing/invalid token
4. Goals and sub-goals constraints are enforced
5. Checkout session is created for valid price/plan
6. Webhook updates local subscription state
7. `GET /api/billing/subscription` reflects expected status
8. OAuth callback returns token to frontend callback URL

## Billing-Specific Validation

- Stripe dashboard shows successful webhook deliveries
- Webhook signature validation uses expected `STRIPE_WEBHOOK_SECRET`
- `sync` endpoint can reconcile by checkout session id in failure scenarios

## Suggested Next Steps

- Add endpoint integration tests (auth, goals, billing)
- Add webhook contract tests with Stripe event fixtures
- Add deploy-time smoke script for health and OAuth redirect
