// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Net;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Connections;
//using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Hosting.Server.Features;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Server.Kestrel.Core.Internal.Infrastructure;
using Microsoft.Extensions.Logging;

namespace Microsoft.AspNetCore.Server.Kestrel.Core.Internal;

internal sealed class AddressBinder
{
    public static async Task BindAsync(IEnumerable<ListenOptions> listenOptions, AddressBindContext context, CancellationToken cancellationToken)
    {
        var strategy = CreateStrategy(
            listenOptions.ToArray(),
            context.Addresses.ToArray(),
            context.ServerAddressesFeature.PreferHostingUrls);

        // reset options. The actual used options and addresses will be populated
        // by the address binding feature
        context.ServerOptions.OptionsInUse.Clear();
        context.Addresses.Clear();

        await strategy.BindAsync(context, cancellationToken).ConfigureAwait(false);
    }

    private static IStrategy CreateStrategy(ListenOptions[] listenOptions, string[] addresses, bool preferAddresses)
    {
        var hasListenOptions = listenOptions.Length > 0;
        var hasAddresses = addresses.Length > 0;

        if (preferAddresses && hasAddresses)
        {
            if (hasListenOptions)
            {
                return new OverrideWithAddressesStrategy(addresses);
            }

            return new AddressesStrategy(addresses);
        }
        else if (hasListenOptions)
        {
            if (hasAddresses)
            {
                return new OverrideWithEndpointsStrategy(listenOptions, addresses);
            }

            return new EndpointsStrategy(listenOptions);
        }
        else if (hasAddresses)
        {
            // If no endpoints are configured directly using KestrelServerOptions, use those configured via the IServerAddressesFeature.
            return new AddressesStrategy(addresses);
        }
        else
        {
            // "localhost" for both IPv4 and IPv6 can't be represented as an IPEndPoint.
            return new DefaultAddressStrategy();
        }
    }

    /// <summary>
    /// Returns an <see cref="IPEndPoint"/> for the given host an port.
    /// If the host parameter isn't "localhost" or an IP address, use IPAddress.Any.
    /// </summary>
    internal static bool TryCreateIPEndPoint(BindingAddress address, [NotNullWhen(true)] out IPEndPoint? endpoint)
    {
        if (!IPAddress.TryParse(address.Host, out var ip))
        {
            endpoint = null;
            return false;
        }

        endpoint = new IPEndPoint(ip, address.Port);
        return true;
    }

    internal static async Task BindEndpointAsync(ListenOptions endpoint, AddressBindContext context, CancellationToken cancellationToken)
    {
        try
        {
            await context.CreateBinding(endpoint, cancellationToken).ConfigureAwait(false);
        }
        catch (AddressInUseException ex)
        {
            throw new IOException(CoreStrings.FormatEndpointAlreadyInUse(endpoint), ex);
        }

        context.ServerOptions.OptionsInUse.Add(endpoint);
    }

    internal static ListenOptions ParseAddress(string address, out bool https)
    {
        var parsedAddress = BindingAddress.Parse(address);
        https = false;

        if (parsedAddress.Scheme.Equals("https", StringComparison.OrdinalIgnoreCase))
        {
            https = true;
        }
        else if (!parsedAddress.Scheme.Equals("http", StringComparison.OrdinalIgnoreCase))
        {
            throw new InvalidOperationException(CoreStrings.FormatUnsupportedAddressScheme(address));
        }

        if (!string.IsNullOrEmpty(parsedAddress.PathBase))
        {
            throw new InvalidOperationException(CoreStrings.FormatConfigurePathBaseFromMethodCall($"{nameof(IApplicationBuilder)}.UsePathBase()"));
        }

        ListenOptions? options = null;
        if (parsedAddress.IsUnixPipe)
        {
            options = new ListenOptions(parsedAddress.UnixPipePath);
        }
        else if (parsedAddress.IsNamedPipe)
        {
            options = new ListenOptions(new NamedPipeEndPoint(parsedAddress.NamedPipeName));
        }
        else if (string.Equals(parsedAddress.Host, "localhost", StringComparison.OrdinalIgnoreCase))
        {
            // "localhost" for both IPv4 and IPv6 can't be represented as an IPEndPoint.
            options = new LocalhostListenOptions(parsedAddress.Port);
        }
        else if (TryCreateIPEndPoint(parsedAddress, out var endpoint))
        {
            options = new ListenOptions(endpoint);
        }
        else
        {
            // when address is 'http://hostname:port', 'http://*:port', or 'http://+:port'
            options = new AnyIPListenOptions(parsedAddress.Port);
        }

        return options;
    }

    private interface IStrategy
    {
        Task BindAsync(AddressBindContext context, CancellationToken cancellationToken);
    }

    private sealed class DefaultAddressStrategy : IStrategy
    {
        public async Task BindAsync(AddressBindContext context, CancellationToken cancellationToken)
        {
            var httpDefault = ParseAddress(Constants.DefaultServerAddress, out _);
            context.ServerOptions.ApplyEndpointDefaults(httpDefault);
            await httpDefault.BindAsync(context, cancellationToken).ConfigureAwait(false);

            context.Logger.LogDebug(CoreStrings.BindingToDefaultAddress, Constants.DefaultServerAddress);
        }
    }

    private sealed class OverrideWithAddressesStrategy : AddressesStrategy
    {
        public OverrideWithAddressesStrategy(IReadOnlyCollection<string> addresses)
            : base(addresses)
        {
        }

        public override Task BindAsync(AddressBindContext context, CancellationToken cancellationToken)
        {
            var joined = string.Join(", ", _addresses);
            context.Logger.LogInformation(CoreStrings.OverridingWithPreferHostingUrls, nameof(IServerAddressesFeature.PreferHostingUrls), joined);

            return base.BindAsync(context, cancellationToken);
        }
    }

    private sealed class OverrideWithEndpointsStrategy : EndpointsStrategy
    {
        private readonly string[] _originalAddresses;

        public OverrideWithEndpointsStrategy(IReadOnlyCollection<ListenOptions> endpoints, string[] originalAddresses)
            : base(endpoints)
        {
            _originalAddresses = originalAddresses;
        }

        public override Task BindAsync(AddressBindContext context, CancellationToken cancellationToken)
        {
            var joined = string.Join(", ", _originalAddresses);
            context.Logger.LogWarning(CoreStrings.OverridingWithKestrelOptions, joined);

            return base.BindAsync(context, cancellationToken);
        }
    }

    private class EndpointsStrategy : IStrategy
    {
        private readonly IReadOnlyCollection<ListenOptions> _endpoints;

        public EndpointsStrategy(IReadOnlyCollection<ListenOptions> endpoints)
        {
            _endpoints = endpoints;
        }

        public virtual async Task BindAsync(AddressBindContext context, CancellationToken cancellationToken)
        {
            foreach (var endpoint in _endpoints)
            {
                await endpoint.BindAsync(context, cancellationToken).ConfigureAwait(false);
            }
        }
    }

    private class AddressesStrategy : IStrategy
    {
        protected readonly IReadOnlyCollection<string> _addresses;

        public AddressesStrategy(IReadOnlyCollection<string> addresses)
        {
            _addresses = addresses;
        }

        public virtual async Task BindAsync(AddressBindContext context, CancellationToken cancellationToken)
        {
            foreach (var address in _addresses)
            {
                var options = ParseAddress(address, out var https);
                context.ServerOptions.ApplyEndpointDefaults(options);

                if (https && !options.IsTls)
                {
                    //options.UseHttps();
                }

                await options.BindAsync(context, cancellationToken).ConfigureAwait(false);
            }
        }
    }
}
