# Azure AD email checks

Using Microsofts Graph API to get all users of a given tenant and pull out last time they changed their password.

## Features
### Graph API Query
	•	Uses the Microsoft Graph API endpoint /users to fetch user details.
	•	Include filters, such as lastPasswordChangeDateTime, to check password age.
### CSV Export
	•	Export user data to a CSV file using Go’s encoding/csv library.
### OAuth2 Authentication
	•	The app uses the clientcredentials.Config to authenticate and generate an access token for API calls.

	Usage:  ./azusers  [options]
	Options:
	  -f filename  Output filename, defaults to AzureAD_Users.csv
	  -h           Print help message
	  -e           Exclude users with accountEnabled set to false
	  -p           Set password expiration period in days (if > 0, expiration date is computed)

## Pre-requisite
You will need an Entra App created in the Microsoft Entra Admin Center.
1. App Registration:
	•	Register your app in the Azure Portal under Azure Active Directory > App Registrations.
	•	Assign the AuditLog.Read.All, Directory.Read.All, User.Export.All, User.Read.All required permissions to your app.
	•	Use the app’s client ID, client secret, and tenant ID in the Go script main directory in a file called .env.

## todo
- add option to email the output file out to a given email address
