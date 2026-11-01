package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// SKELETON: this provider is a scaffold and does not talk to an ARACHNE API. See README.md.

// Ensure the implementation satisfies the framework interface at compile time.
var _ provider.Provider = (*arachneProvider)(nil)

// arachneProvider is the skeleton provider. The client it would hold is deliberately absent.
type arachneProvider struct {
	version string
}

// arachneProviderModel is the provider configuration block.
type arachneProviderModel struct {
	Endpoint types.String `tfsdk:"endpoint"`
	APIKey   types.String `tfsdk:"api_key"`
}

// New returns the provider constructor the server calls.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &arachneProvider{version: version}
	}
}

// Metadata sets the provider type name ("arachne") and its version.
func (p *arachneProvider) Metadata(
	_ context.Context,
	_ provider.MetadataRequest,
	resp *provider.MetadataResponse,
) {
	resp.TypeName = "arachne"
	resp.Version = p.version
}

// Schema declares the provider configuration: the control-plane endpoint and an API key.
func (p *arachneProvider) Schema(
	_ context.Context,
	_ provider.SchemaRequest,
	resp *provider.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		// SKELETON: descriptions are the intended contract, not a shipped one.
		Description: "SKELETON provider for ARACHNE (not functional; see README.md).",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "ARACHNE control-plane base URL. Falls back to ARACHNE_API_URL.",
			},
			"api_key": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "ARACHNE API key (scanner role or above). Falls back to ARACHNE_API_KEY.",
			},
		},
	}
}

// Configure would build an ARACHNE API client. SKELETON: it validates nothing and stores
// nothing; every data source and resource therefore refuses to run.
func (p *arachneProvider) Configure(
	ctx context.Context,
	req provider.ConfigureRequest,
	resp *provider.ConfigureResponse,
) {
	var config arachneProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// SKELETON: the endpoint/key resolution below is the intended shape. A real provider
	// would build a client here and put it on resp.DataSourceData / resp.ResourceData.
	_ = config.Endpoint
	_ = config.APIKey
	resp.DataSourceData = nil
	resp.ResourceData = nil
}

// DataSources registers the skeleton data sources.
func (p *arachneProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		NewFindingsDataSource,
	}
}

// Resources registers the skeleton resources.
func (p *arachneProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		NewTenantResource,
	}
}
