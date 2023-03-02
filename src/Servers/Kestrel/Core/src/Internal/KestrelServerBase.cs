// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics;
using System.IO.Pipelines;
using System.Linq;
using Microsoft.AspNetCore.Connections;
using Microsoft.AspNetCore.Hosting.Server;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.Extensions.Primitives;

namespace Microsoft.AspNetCore.Server.Kestrel.Core;

internal abstract class KestrelServerBase : IServer
{
    private readonly ServerAddressesFeature _serverAddresses;

    private readonly SemaphoreSlim _bindSemaphore = new SemaphoreSlim(initialCount: 1);
    private bool _hasStarted;
    private int _stopping;
    private readonly CancellationTokenSource _stopCts = new CancellationTokenSource();
    private readonly TaskCompletionSource _stoppedTcs = new TaskCompletionSource(TaskCreationOptions.RunContinuationsAsynchronously);

    private IDisposable? _configChangedRegistration;

    protected KestrelServerBase(
        IEnumerable<IConnectionListenerFactory> transportFactories,
        IEnumerable<IMultiplexedConnectionListenerFactory> multiplexedFactories,
        ServiceContext serviceContext)
    {
        ArgumentNullException.ThrowIfNull(transportFactories);

        var transportFactoriesList = transportFactories.Reverse().ToList();
        var multiplexedTransportFactoriesList = multiplexedFactories.Reverse().ToList();

        HasTransportFactories = transportFactoriesList.Count > 0;
        HasMultiplexedTransportFactories = multiplexedTransportFactoriesList.Count > 0;

        if (!HasTransportFactories && !HasMultiplexedTransportFactories)
        {
            throw new InvalidOperationException(CoreStrings.TransportNotFound);
        }

        ServiceContext = serviceContext;

        Features = new FeatureCollection();
        _serverAddresses = new ServerAddressesFeature();
        Features.Set<IServerAddressesFeature>(_serverAddresses);

        TransportManager = new TransportManager(transportFactoriesList, multiplexedTransportFactoriesList, ServiceContext);
    }

    protected static ServiceContext CreateServiceContext(IOptions<KestrelServerOptions> options, ILoggerFactory loggerFactory, DiagnosticSource? diagnosticSource)
    {
        ArgumentNullException.ThrowIfNull(options);
        ArgumentNullException.ThrowIfNull(loggerFactory);

        var serverOptions = options.Value ?? new KestrelServerOptions();
        var trace = new KestrelTrace(loggerFactory);
        var connectionManager = new ConnectionManager(
            trace,
            serverOptions.Limits.MaxConcurrentUpgradedConnections);

        var heartbeatManager = new HeartbeatManager(connectionManager);
        var dateHeaderValueManager = new DateHeaderValueManager();

        var heartbeat = new Heartbeat(
            new IHeartbeatHandler[] { dateHeaderValueManager, heartbeatManager },
            new SystemClock(),
            DebuggerWrapper.Singleton,
            trace);

        return new ServiceContext
        {
            Log = trace,
            Scheduler = PipeScheduler.ThreadPool,
            HttpParser = new HttpParser<Http1ParsingHandler>(trace.IsEnabled(LogLevel.Information), serverOptions.DisableHttp1LineFeedTerminators),
            SystemClock = heartbeatManager,
            DateHeaderValueManager = dateHeaderValueManager,
            ConnectionManager = connectionManager,
            Heartbeat = heartbeat,
            ServerOptions = serverOptions,
            DiagnosticSource = diagnosticSource
        };
    }

    public IFeatureCollection Features { get; }

    public KestrelServerOptions Options => ServiceContext.ServerOptions;

    protected ServiceContext ServiceContext { get; }

    protected KestrelTrace Trace => ServiceContext.Log;

    protected AddressBindContext? AddressBindContext { get; set; }

    protected bool HasTransportFactories { get; }
    protected bool HasMultiplexedTransportFactories { get; }

    protected TransportManager TransportManager { get; }

    protected abstract Task OnBind<TContext>(IHttpApplication<TContext> application, ListenOptions options, CancellationToken onBindCancellationToken) where TContext : notnull;

    protected abstract void UseHttps(ListenOptions listenOptions);

    public async Task StartAsync<TContext>(IHttpApplication<TContext> application, CancellationToken cancellationToken) where TContext : notnull
    {
        try
        {
            ValidateOptions();

            if (_hasStarted)
            {
                // The server has already started and/or has not been cleaned up yet
                throw new InvalidOperationException(CoreStrings.ServerAlreadyStarted);
            }
            _hasStarted = true;

            ServiceContext.Heartbeat?.Start();

            AddressBindContext = new AddressBindContext(_serverAddresses, Options, Trace, (options, ct) => OnBind(application, options, ct));

            await BindAsync(cancellationToken).ConfigureAwait(false);
        }
        catch
        {
            // Don't log the error https://github.com/dotnet/aspnetcore/issues/29801
            Dispose();
            throw;
        }

        // Register the options with the event source so it can be logged (if necessary)
        KestrelEventSource.Log.AddServerOptions(Options);
    }

    // Graceful shutdown if possible
    public async Task StopAsync(CancellationToken cancellationToken)
    {
        if (Interlocked.Exchange(ref _stopping, 1) == 1)
        {
            await _stoppedTcs.Task.ConfigureAwait(false);
            return;
        }

        _stopCts.Cancel();

#pragma warning disable CA2016 // Don't use cancellationToken when acquiring the semaphore. Dispose calls this with a pre-canceled token.
        await _bindSemaphore.WaitAsync().ConfigureAwait(false);
#pragma warning restore CA2016

        try
        {
            await TransportManager.StopAsync(cancellationToken).ConfigureAwait(false);
        }
        catch (Exception ex)
        {
            _stoppedTcs.TrySetException(ex);
            throw;
        }
        finally
        {
            ServiceContext.Heartbeat?.Dispose();
            _configChangedRegistration?.Dispose();
            _stopCts.Dispose();
            _bindSemaphore.Release();
        }

        _stoppedTcs.TrySetResult();

        // Remove the options from the event source so we don't have a leak if
        // the server is stopped and started again in the same process.
        KestrelEventSource.Log.RemoveServerOptions(Options);
    }

    // Ungraceful shutdown
    public void Dispose()
    {
        StopAsync(new CancellationToken(canceled: true)).GetAwaiter().GetResult();
    }

    private async Task BindAsync(CancellationToken cancellationToken)
    {
        await _bindSemaphore.WaitAsync(cancellationToken).ConfigureAwait(false);

        try
        {
            if (_stopping == 1)
            {
                throw new InvalidOperationException("Kestrel has already been stopped.");
            }

            IChangeToken? reloadToken = null;

            _serverAddresses.InternalCollection.PreventPublicMutation();

            if (Options.ConfigurationLoader?.ReloadOnChange == true && (!_serverAddresses.PreferHostingUrls || _serverAddresses.InternalCollection.Count == 0))
            {
                reloadToken = Options.ConfigurationLoader.Configuration.GetReloadToken();
            }

            Options.ConfigurationLoader?.Load();

            await AddressBinder.BindAsync(Options.ListenOptions, AddressBindContext!, UseHttps, cancellationToken).ConfigureAwait(false);
            _configChangedRegistration = reloadToken?.RegisterChangeCallback(TriggerRebind, this);

        }
        finally
        {
            _bindSemaphore.Release();
        }
    }

    private static void TriggerRebind(object? state)
    {
        if (state is KestrelServerImpl server)
        {
            _ = server.RebindAsync();
        }
    }

    private async Task RebindAsync()
    {
        // Prevents from interfering with shutdown or other rebinds.
        // All exceptions are caught and logged at the critical level.
        await _bindSemaphore.WaitAsync();

        IChangeToken? reloadToken = null;

        try
        {
            if (_stopping == 1)
            {
                return;
            }

            Debug.Assert(Options.ConfigurationLoader != null, "Rebind can only happen when there is a ConfigurationLoader.");

            reloadToken = Options.ConfigurationLoader.Configuration.GetReloadToken();
            var (endpointsToStop, endpointsToStart) = Options.ConfigurationLoader.Reload();

            Trace.LogDebug("Config reload token fired. Checking for changes...");

            if (endpointsToStop.Count > 0)
            {
                var urlsToStop = endpointsToStop.Select(lo => lo.EndpointConfig!.Url);
                Trace.LogInformation("Config changed. Stopping the following endpoints: '{endpoints}'", string.Join("', '", urlsToStop));

                // 5 is the default value for WebHost's "shutdownTimeoutSeconds", so use that.
                using var timeoutCts = new CancellationTokenSource(TimeSpan.FromSeconds(5));
                using var combinedCts = CancellationTokenSource.CreateLinkedTokenSource(_stopCts.Token, timeoutCts.Token);

                // TODO: It would be nice to start binding to new endpoints immediately and reconfigured endpoints as soon
                // as the unbinding finished for the given endpoint rather than wait for all transports to unbind first.
                var configsToStop = endpointsToStop.Select(lo => lo.EndpointConfig!).ToList();
                await TransportManager.StopEndpointsAsync(configsToStop, combinedCts.Token).ConfigureAwait(false);

                foreach (var listenOption in endpointsToStop)
                {
                    Options.OptionsInUse.Remove(listenOption);
                    _serverAddresses.InternalCollection.Remove(listenOption.GetDisplayName());
                }
            }

            if (endpointsToStart.Count > 0)
            {
                var urlsToStart = endpointsToStart.Select(lo => lo.EndpointConfig!.Url);
                Trace.LogInformation("Config changed. Starting the following endpoints: '{endpoints}'", string.Join("', '", urlsToStart));

                foreach (var listenOption in endpointsToStart)
                {
                    try
                    {
                        await listenOption.BindAsync(AddressBindContext!, _stopCts.Token).ConfigureAwait(false);
                    }
                    catch (Exception ex)
                    {
                        Trace.LogCritical(0, ex, "Unable to bind to '{url}' on config reload.", listenOption.EndpointConfig!.Url);
                    }
                }
            }
        }
        catch (Exception ex)
        {
            Trace.LogCritical(0, ex, "Unable to reload configuration.");
        }
        finally
        {
            _configChangedRegistration = reloadToken?.RegisterChangeCallback(TriggerRebind, this);
            _bindSemaphore.Release();
        }
    }

    private void ValidateOptions()
    {
        if (Options.Limits.MaxRequestBufferSize.HasValue &&
            Options.Limits.MaxRequestBufferSize < Options.Limits.MaxRequestLineSize)
        {
            throw new InvalidOperationException(
                CoreStrings.FormatMaxRequestBufferSmallerThanRequestLineBuffer(Options.Limits.MaxRequestBufferSize.Value, Options.Limits.MaxRequestLineSize));
        }

        if (Options.Limits.MaxRequestBufferSize.HasValue &&
            Options.Limits.MaxRequestBufferSize < Options.Limits.MaxRequestHeadersTotalSize)
        {
            throw new InvalidOperationException(
                CoreStrings.FormatMaxRequestBufferSmallerThanRequestHeaderBuffer(Options.Limits.MaxRequestBufferSize.Value, Options.Limits.MaxRequestHeadersTotalSize));
        }
    }

    protected static ConnectionDelegate EnforceConnectionLimit(ConnectionDelegate innerDelegate, long? connectionLimit, KestrelTrace trace)
    {
        if (!connectionLimit.HasValue)
        {
            return innerDelegate;
        }

        return new ConnectionLimitMiddleware<ConnectionContext>(c => innerDelegate(c), connectionLimit.Value, trace).OnConnectionAsync;
    }

    protected static MultiplexedConnectionDelegate EnforceConnectionLimit(MultiplexedConnectionDelegate innerDelegate, long? connectionLimit, KestrelTrace trace)
    {
        if (!connectionLimit.HasValue)
        {
            return innerDelegate;
        }

        return new ConnectionLimitMiddleware<MultiplexedConnectionContext>(c => innerDelegate(c), connectionLimit.Value, trace).OnConnectionAsync;
    }
}
