package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

// SKELETON: arachne_tenant manages an ARACHNE project/tenant. All CRUD is stubbed.

var (
	_ resource.Resource              = (*tenantResource)(nil)
	_ resource.ResourceWithConfigure = (*tenantResource)(nil)
)

// tenantResource is the resource implementation.
type tenantResource struct{}

// tenantResourceModel is the resource's state/config shape.
type tenantResourceModel struct {
	ID            types.String `tfsdk:"id"`
	Slug          types.String `tfsdk:"slug"`
	Name          types.String `tfsdk:"name"`
	RetentionDays types.Int64  `tfsdk:"retention_days"`
}

// NewTenantResource is the constructor the provider registers.
func NewTenantResource() resource.Resource {
	return &tenantResource{}
}

// Metadata sets the resource name used in Terraform ("arachne_tenant").
func (r *tenantResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_tenant"
}

// Schema declares the resource's attributes.
func (r *tenantResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		Description: "SKELETON: manage an ARACHNE tenant/project (not functional).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Server-assigned identifier.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"slug": schema.StringAttribute{
				Required:      true,
				Description:   "URL-safe tenant identifier (unique).",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable tenant name.",
			},
			"retention_days": schema.Int64Attribute{
				Optional:    true,
				Description: "Evidence/finding retention in days (0 keeps forever).",
			},
		},
	}
}

// Configure would receive the provider's API client. SKELETON: nothing is stored.
func (r *tenantResource) Configure(
	_ context.Context,
	_ resource.ConfigureRequest,
	_ *resource.ConfigureResponse,
) {
	// SKELETON: req.ProviderData is nil (the provider builds no client).
}

// Create would POST the tenant. SKELETON: returns a diagnostic.
func (r *tenantResource) Create(
	_ context.Context,
	_ resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	resp.Diagnostics.Append(skeletonDiagnostic())
}

// Read would GET the tenant. SKELETON: returns a diagnostic.
func (r *tenantResource) Read(
	_ context.Context,
	_ resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	resp.Diagnostics.Append(skeletonDiagnostic())
}

// Update would PATCH the tenant. SKELETON: returns a diagnostic.
func (r *tenantResource) Update(
	_ context.Context,
	_ resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	resp.Diagnostics.Append(skeletonDiagnostic())
}

// Delete would DELETE the tenant. SKELETON: returns a diagnostic.
func (r *tenantResource) Delete(
	_ context.Context,
	_ resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	resp.Diagnostics.Append(skeletonDiagnostic())
}

func skeletonDiagnostic() diag.Diagnostic {
	return diag.NewErrorDiagnostic(
		"arachne_tenant is a skeleton",
		"the ARACHNE Terraform provider is a scaffold and does not call the API; see "+
			"deploy/terraform/provider/README.md",
	)
}
