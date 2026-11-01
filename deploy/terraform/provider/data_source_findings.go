package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// SKELETON: arachne_findings reads a scan's findings from the ARACHNE API. Read is stubbed.

var (
	_ datasource.DataSource              = (*findingsDataSource)(nil)
	_ datasource.DataSourceWithConfigure = (*findingsDataSource)(nil)
)

// findingsDataSource is the data source implementation.
type findingsDataSource struct{}

// findingsDataSourceModel is the configuration + result shape.
type findingsDataSourceModel struct {
	ScanID    types.String   `tfsdk:"scan_id"`
	Threshold types.String   `tfsdk:"threshold"`
	Findings  []findingModel `tfsdk:"findings"`
}

// findingModel is one finding row (a subset of the report schema).
type findingModel struct {
	ID       types.String `tfsdk:"id"`
	CheckID  types.String `tfsdk:"check_id"`
	Title    types.String `tfsdk:"title"`
	Severity types.String `tfsdk:"severity"`
	Asset    types.String `tfsdk:"asset"`
}

// NewFindingsDataSource is the constructor the provider registers.
func NewFindingsDataSource() datasource.DataSource {
	return &findingsDataSource{}
}

// Metadata sets the data source name used in Terraform ("arachne_findings").
func (d *findingsDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_findings"
}

// Schema declares the data source's attributes.
func (d *findingsDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "SKELETON: read ARACHNE findings for a scan (not functional).",
		Attributes: map[string]schema.Attribute{
			"scan_id": schema.StringAttribute{
				Required:    true,
				Description: "The scan to read findings from.",
			},
			"threshold": schema.StringAttribute{
				Optional:    true,
				Description: "Only return findings at or above this severity.",
			},
			"findings": schema.ListNestedAttribute{
				Computed:    true,
				Description: "The matching findings.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"id":       schema.StringAttribute{Computed: true},
						"check_id": schema.StringAttribute{Computed: true},
						"title":    schema.StringAttribute{Computed: true},
						"severity": schema.StringAttribute{Computed: true},
						"asset":    schema.StringAttribute{Computed: true},
					},
				},
			},
		},
	}
}

// Configure would receive the provider's API client. SKELETON: nothing is stored.
func (d *findingsDataSource) Configure(
	_ context.Context,
	_ datasource.ConfigureRequest,
	_ *datasource.ConfigureResponse,
) {
	// SKELETON: req.ProviderData is nil (the provider builds no client).
}

// Read would call the API. SKELETON: it returns a diagnostic instead of any findings.
func (d *findingsDataSource) Read(
	_ context.Context,
	_ datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	resp.Diagnostics.Append(diag.NewErrorDiagnostic(
		"arachne_findings is a skeleton",
		"the ARACHNE Terraform provider is a scaffold and does not call the API; see "+
			"deploy/terraform/provider/README.md",
	))
}
