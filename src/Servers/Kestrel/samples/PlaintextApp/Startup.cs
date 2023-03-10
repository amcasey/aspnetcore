// Licensed to the .NET Foundation under one or more agreements.
// The .NET Foundation licenses this file to you under the MIT license.

using System.Text.Json.Serialization;

var builder = WebApplication.CreateSlimBuilder(args);

//builder.WebHost.UseHttpsConfiguration();
//builder.WebHost.UseQuic(); // Would enable http/3 but not automatically UseHttpsConfiguration

builder.WebHost.ConfigureKestrel((context, options) =>
{
    options.Listen(
        address: System.Net.IPAddress.Any,
        port: 443,
        configure: listenOptions =>
        {
            // Modifying the service collection here throws, so UseHttps probably can't light things up automatically
            listenOptions.Protocols = Microsoft.AspNetCore.Server.Kestrel.Core.HttpProtocols.Http1;
            listenOptions.UseHttps(); // throws without UseHttpsConfiguration
            //listenOptions.UseHttps(@"C:\Users\acasey\AppData\Roaming\ASP.NET\https\PlaintextApp.pfx", "1234"); // Works without or without UseHttpsConfiguration
        });
});

builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.AddContext<AppJsonSerializerContext>();
});

var app = builder.Build();

var todosApi = app.MapGroup("/todos");
todosApi.MapGet("/", () => Todos.AllTodos);

//// Keeping because it is in the template but not actually benchmarked.
//todosApi.MapGet("/{id}", (int id) =>
//    Todos.AllTodos.FirstOrDefault(a => a.Id == id) is { } todo
//        ? Results.Ok(todo)
//        : Results.NotFound());

app.Lifetime.ApplicationStarted.Register(() => Console.WriteLine("Application started. Press Ctrl+C to shut down."));
app.Run();

[JsonSerializable(typeof(Todo[]))]
internal partial class AppJsonSerializerContext : JsonSerializerContext
{

}

public class Todo
{
    public int Id { get; set; }

    public string? Title { get; set; }

    public DateOnly? DueBy { get; set; }

    public bool IsComplete { get; set; }
}

static class Todos
{
    internal static readonly Todo[] AllTodos = new Todo[]
        {
            new Todo() { Id = 0, Title = "Wash the dishes.", DueBy = DateOnly.FromDateTime(DateTime.Now), IsComplete = true },
            new Todo() { Id = 1, Title = "Dry the dishes.", DueBy = DateOnly.FromDateTime(DateTime.Now), IsComplete = true },
            new Todo() { Id = 2, Title = "Turn the dishes over.", DueBy = DateOnly.FromDateTime(DateTime.Now), IsComplete = false },
            new Todo() { Id = 3, Title = "Walk the kangaroo.", DueBy = DateOnly.FromDateTime(DateTime.Now.AddDays(1)), IsComplete = false },
            new Todo() { Id = 4, Title = "Call Grandma.", DueBy = DateOnly.FromDateTime(DateTime.Now.AddDays(1)), IsComplete = false },
        };
}
