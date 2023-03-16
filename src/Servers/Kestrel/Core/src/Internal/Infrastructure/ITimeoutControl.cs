// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;

internal interface ITimeoutControl
{
    TimeoutReason TimerReason { get; }

    void SetTimeout(long ticks, TimeoutReason timeoutReason);
    void ResetTimeout(long ticks, TimeoutReason timeoutReason);
    void CancelTimeout();

    void Tick(DateTimeOffset now);

    void StartRequestBody(MinDataRate minRate);
    void StopRequestBody();
    void StartTimingRead();
    void StopTimingRead();
    void BytesRead(long count);

    void StartTimingWrite();
    void StopTimingWrite();
    void BytesWrittenToBuffer(MinDataRate minRate, long count);
    long GetResponseDrainDeadline(long ticks, MinDataRate minRate);
}
