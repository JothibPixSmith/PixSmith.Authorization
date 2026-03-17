namespace AuthServer.Domain.Events;

public abstract record DomainEvent(DateTimeOffset OccurredAt)
{
    protected DomainEvent() : this(DateTimeOffset.UtcNow) { }
}

public sealed record UserCreatedEvent(Guid UserId, string Email) : DomainEvent;
public sealed record UserEmailConfirmedEvent(Guid UserId) : DomainEvent;
public sealed record UserLockedOutEvent(Guid UserId, DateTimeOffset LockoutEnd) : DomainEvent;
public sealed record UserDeactivatedEvent(Guid UserId) : DomainEvent;
public sealed record UserLoggedInEvent(Guid UserId, string IpAddress, string UserAgent) : DomainEvent;
public sealed record UserPasswordChangedEvent(Guid UserId) : DomainEvent;
