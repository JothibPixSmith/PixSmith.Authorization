Feature: Login
    As a registered user
    I want to sign in with my email and password
    So that I can access my account

Scenario: Rejecting invalid credentials
    Given I am on the login page
    When I sign in with email "nobody@example.com" and password "WrongPassword1!"
    Then I should see a sign-in error message

Scenario: Navigating to the registration page
    Given I am on the login page
    When I follow the "Create one" link
    Then I should be on the registration page
