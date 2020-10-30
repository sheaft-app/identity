using IdentityServer4;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using System;
using Microsoft.AspNetCore.Authentication.OAuth;
using System.Security.Claims;
using IdentityModel;
using System.Threading.Tasks;
using System.Reflection;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Authentication.Twitter;
using Sheaft.Identity.Data;
using Sheaft.Identity.Models;
using Microsoft.EntityFrameworkCore.Infrastructure;
using IdentityServer4.EntityFramework.DbContexts;
using System.Linq;
using IdentityServer4.EntityFramework.Entities;
using System.Collections.Generic;
using Amazon.SimpleEmail;
using RazorLight;
using Amazon;
using Serilog;
using Serilog.Events;
using NewRelic.LogEnrichers.Serilog;
using Microsoft.IdentityModel.Logging;

namespace Sheaft.Identity
{
    public class DatabaseOptions
    {
        public const string SETTING = "IdentityDatabase";
        public string Url { get; set; }
        public string Name { get; set; }
        public string Server { get; set; }
        public int Port { get; set; }
        public string User { get; set; }
        public string Password { get; set; }
        public string ConnectionString { get => string.Format(Url, Server, Port, Name, User, Password); }
    }
}