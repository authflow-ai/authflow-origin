namespace Rail.Kernel.Time;

/// <summary>UTC everywhere. Injected rather than ambient so ledger and expiry logic is testable.</summary>
public interface IClock
{
    DateTimeOffset UtcNow { get; }
}

public sealed class SystemClock : IClock
{
    public DateTimeOffset UtcNow => DateTimeOffset.UtcNow;
}
