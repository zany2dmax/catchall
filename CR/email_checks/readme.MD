# Azure AD email checks

Using Microsofts Graph API to get all users of a given tenant and pull out last time they changed their password.

	Usage:  ./azusers  [options]
	Options:
	  -f filename  Output filename, defaults to AzureAD_Users.csv
	  -h           Print help message
	  -e           Exclude users with accountEnabled set to false

## todo
- add flag to ignore disable users
- add option to email the output file out to a given email address
- add a flag to input # of days since password change and only output those greater than
