using OpenQA.Selenium;
using OpenQA.Selenium.Chrome;
using Reqnroll;

namespace PixSmith.Authorization.UITests.Support;

[Binding]
public sealed class Hooks
{
    private readonly ScenarioContext scenarioContext;

    public Hooks(ScenarioContext scenarioContext) => this.scenarioContext = scenarioContext;

    [BeforeScenario]
    public void StartBrowser()
    {
        var options = new ChromeOptions();
        options.AddArgument("--window-size=1280,900");
        // Dev certs on localhost are self-signed; the real fix is trusting `dotnet dev-certs https`,
        // but that's machine setup, not something a test run should depend on.
        options.AddArgument("--ignore-certificate-errors");

        if (Environment.GetEnvironmentVariable("UITEST_HEADLESS") != "false")
            options.AddArgument("--headless=new");

        var driver = new ChromeDriver(options);
        driver.Manage().Timeouts().ImplicitWait = TimeSpan.FromSeconds(2);
        // Must be set under the IWebDriver key explicitly: Set(driver) would infer the
        // compile-time type ChromeDriver, which Get<IWebDriver>() in step definitions can't find.
        scenarioContext.Set<IWebDriver>(driver);
    }

    [AfterScenario]
    public void StopBrowser()
    {
        if (scenarioContext.TryGetValue(out IWebDriver driver))
        {
            driver.Quit();
            driver.Dispose();
        }
    }
}
