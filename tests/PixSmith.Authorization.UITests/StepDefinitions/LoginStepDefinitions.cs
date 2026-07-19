using OpenQA.Selenium;
using OpenQA.Selenium.Support.UI;
using PixSmith.Authorization.UITests.Support;
using Reqnroll;
using Xunit;

namespace PixSmith.Authorization.UITests.StepDefinitions;

[Binding]
public sealed class LoginStepDefinitions
{
    private readonly ScenarioContext scenarioContext;

    public LoginStepDefinitions(ScenarioContext scenarioContext) => this.scenarioContext = scenarioContext;

    private IWebDriver Driver => scenarioContext.Get<IWebDriver>();

    private WebDriverWait Wait => new(Driver, TimeSpan.FromSeconds(10));

    [Given(@"I am on the login page")]
    public void GivenIAmOnTheLoginPage()
    {
        Driver.Navigate().GoToUrl($"{TestSettings.BaseUrl}/login");
        Wait.Until(d => d.FindElement(By.CssSelector("input[type='email']")));
    }

    [When(@"I sign in with email ""(.*)"" and password ""(.*)""")]
    public void WhenISignInWithEmailAndPassword(string email, string password)
    {
        Driver.FindElement(By.CssSelector("input[type='email']")).SendKeys(email);
        Driver.FindElement(By.CssSelector("input[type='password']")).SendKeys(password);
        Driver.FindElement(By.CssSelector("button[type='submit']")).Click();
    }

    [When(@"I follow the ""(.*)"" link")]
    public void WhenIFollowTheLink(string linkText)
    {
        Driver.FindElement(By.LinkText(linkText)).Click();
    }

    [Then(@"I should see a sign-in error message")]
    public void ThenIShouldSeeASignInErrorMessage()
    {
        var error = Wait.Until(d => d.FindElement(By.CssSelector(".text-red-700")));
        Assert.False(string.IsNullOrWhiteSpace(error.Text));
    }

    [Then(@"I should be on the registration page")]
    public void ThenIShouldBeOnTheRegistrationPage()
    {
        Wait.Until(d => d.Url.Contains("/register", StringComparison.OrdinalIgnoreCase));
    }
}
