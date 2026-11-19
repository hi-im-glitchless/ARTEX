package membrane

import (
	"strings"

	"golang.org/x/net/publicsuffix"
)

// sharedTenantRoots are multi-tenant SaaS and cloud roots: a client's host
// under one (acme.okta.com) is the client's tenant, but the root itself
// (okta.com) belongs to every tenant. Such a root is never a client root,
// even when an operator declares a host under it; only the tenant label is
// aliased, and a stored entry under one is quarantined (see indexEntry).
//
// Every entry is the registrable root (eTLD+1) of its tenants' hosts
// (TestSharedTenantRootsAreRegistrable). Platforms the public suffix list
// already lists as suffixes (github.io, herokuapp.com, myshopify.com,
// azurewebsites.net, cloudfront.net, vercel.app, netlify.app, appspot.com,
// web.app, pages.dev, workers.dev, ngrok.io, blob.core.windows.net,
// my.salesforce.com...) are deliberately absent: there the tenant host is
// its own registrable root (acme.github.io), so derivation under its alias
// stays inside the tenant.
var sharedTenantRoots = map[string]bool{
	// identity
	"okta.com": true, "oktapreview.com": true, "okta-emea.com": true, "auth0.com": true,
	// SaaS
	"zendesk.com": true, "service-now.com": true, "salesforce.com": true, "force.com": true,
	"atlassian.net": true, "sharepoint.com": true, "onmicrosoft.com": true, "wordpress.com": true,
	"squarespace.com": true, "freshdesk.com": true, "freshservice.com": true, "hubspot.com": true,
	"zoom.us": true, "slack.com": true, "workday.com": true, "myworkday.com": true, "box.com": true,
	"webex.com": true, "zohosites.com": true, "typeform.com": true, "surveymonkey.com": true,
	"docusign.net": true, "sentry.io": true,
	// cloud hosting whose tenant hosts share the root
	"amazonaws.com": true, "windows.net": true, "googleusercontent.com": true,
}

// IsSharedTenantRoot reports whether root (a registrable domain) is a
// multi-tenant SaaS/cloud root that must never become a client root.
func IsSharedTenantRoot(root string) bool {
	return sharedTenantRoots[strings.TrimSuffix(strings.ToLower(strings.TrimSpace(root)), ".")]
}

// underSharedRoot reports whether host's registrable root is a shared
// multi-tenant root.
func underSharedRoot(host string) bool {
	r, err := publicsuffix.EffectiveTLDPlusOne(strings.TrimSuffix(strings.ToLower(host), "."))
	return err == nil && IsSharedTenantRoot(r)
}
