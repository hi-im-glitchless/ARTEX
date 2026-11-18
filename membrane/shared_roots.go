package membrane

import "strings"

// sharedTenantRoots are multi-tenant SaaS and cloud roots: a client's host
// under one (acme.okta.com) is the client's tenant, but the root itself
// (okta.com) belongs to every tenant. Such a root is never a client root,
// even when an operator declares a host under it; only the tenant label is
// aliased. Roots that the public suffix list already treats as suffixes
// (github.io, herokuapp.com...) make the tenant host its own registrable
// root; they are listed for the hosts the list does not cover.
var sharedTenantRoots = map[string]bool{
	"okta.com": true, "oktapreview.com": true, "auth0.com": true, "zendesk.com": true,
	"service-now.com": true, "salesforce.com": true, "force.com": true, "my.salesforce.com": true,
	"atlassian.net": true, "myshopify.com": true, "sharepoint.com": true, "onmicrosoft.com": true,
	"azurewebsites.net": true, "cloudapp.net": true, "cloudfront.net": true, "amazonaws.com": true,
	"herokuapp.com": true, "vercel.app": true, "netlify.app": true, "appspot.com": true,
	"firebaseapp.com": true, "web.app": true, "github.io": true, "gitlab.io": true,
	"wordpress.com": true, "wixsite.com": true, "squarespace.com": true, "freshdesk.com": true,
	"hubspot.com": true, "zoom.us": true, "slack.com": true,
}

// IsSharedTenantRoot reports whether root (a registrable domain) is a
// multi-tenant SaaS/cloud root that must never become a client root.
func IsSharedTenantRoot(root string) bool {
	return sharedTenantRoots[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")]
}
