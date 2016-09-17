using Microsoft.Owin;
using Owin;

[assembly: OwinStartupAttribute(typeof(OneloginSaml2.Startup))]
namespace OneloginSaml2
{
    public partial class Startup
    {
        public void Configuration(IAppBuilder app)
        {
            ConfigureAuth(app);
        }
    }
}
