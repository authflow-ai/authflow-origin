namespace Rail.Kernel.Primitives;

/// <summary>
/// The rail's own identifier for a consumer account. Deliberately not a Google <c>sub</c> or any
/// other provider's key: the cross-server consumer identity is the rail's asset, so it has to
/// survive adding or removing login methods.
/// </summary>
public readonly record struct UserId(Guid Value)
{
    public static UserId New() => new(Guid.CreateVersion7());

    public static bool TryParse(string? candidate, out UserId result)
    {
        if (Guid.TryParse(candidate, out var guid) && guid != Guid.Empty)
        {
            result = new UserId(guid);
            return true;
        }

        result = default;
        return false;
    }

    public override string ToString() => Value.ToString("D");
}
