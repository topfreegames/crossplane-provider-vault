package role

import (
	"encoding/json"

	"github.com/topfreegames/crossplane-provider-vault/apis/aws/v1alpha1"
)

// Note: these values comes from https://registry.terraform.io/providers/hashicorp/vault/latest/docs/resources/aws_secret_backend_role

// CrossplaneToVault is a transport object to send to vault. The reason we are using it, its because vault only accepts values as snake_case
type CrossplaneToVault struct {

	// RoleName - Role Name
	// +required
	RoleName string `json:"role_name"`

	// Backend - (Required) The path the AWS secret backend is mounted at, with no leading or trailing /s.
	// +required
	Backend string `json:"backend"`

	// CredentialType - (Required) Specifies the type of credential to be used when retrieving credentials from the role. Must be one of iam_user, assumed_role, or federation_token.
	// https://www.vaultproject.io/docs/secrets/aws
	// +required
	CredentialType string `json:"credential_type"`

	// IamRolesArn - (Optional) Specifies the ARNs of the AWS roles this Vault role is allowed to assume. Required when credential_type is assumed_role and prohibited otherwise.
	// +optional
	IamRolesArn []string `json:"role_arns,omitempty"`

	// PoliciesArn - (Optional) Specifies a list of AWS managed policy ARNs. The behavior depends on the credential type. With iam_user, the policies will be attached to IAM users when they are requested. With assumed_role and federation_token, the policy ARNs will act as a filter on what the credentials can do, similar to policy_document. When credential_type is iam_user or federation_token, at least one of policy_document or policy_arns must be specified.
	// +optional
	PoliciesArn []string `json:"policy_arns,omitempty"`

	// PolicyDocument - (Optional) The IAM policy document for the role. The behavior depends on the credential type. With iam_user, the policy document will be attached to the IAM user generated and augment the permissions the IAM user has. With assumed_role and federation_token, the policy document will act as a filter on what the credentials can do, similar to policy_arns.
	// +optional
	PolicyDocument string `json:"policy_document,omitempty"`

	// IamGroups - (Optional) A list of IAM group names. IAM users generated against this vault role will be added to these IAM Groups. For a credential type of assumed_role or federation_token, the policies sent to the corresponding AWS call (sts:AssumeRole or sts:GetFederation) will be the policies from each group in iam_groups combined with the policy_document and policy_arns parameters.
	// +optional
	IamGroups []string `json:"iam_groups,omitempty"`

	// UserPath - (Optional) The path for the user name. Valid only when credential_type is iam_user. Default is /.
	// +optional
	UserPath string `json:"user_path,omitempty"`

	// PermissionBoundaryArn - (Optional) The ARN of the AWS Permissions Boundary to attach to IAM users created in the role. Valid only when credential_type is iam_user. If not specified, then no permissions boundary policy will be attached.
	// +optional
	PermissionBoundaryArn string `json:"permissions_boundary_arn,omitempty"`

	// DefaultStsTTL -  (Optional) The default TTL in seconds for STS credentials. When a TTL is not specified when STS credentials are requested, and a default TTL is specified on the role, then this default TTL will be used. Valid only when credential_type is one of assumed_role or federation_token.
	// +optional
	DefaultStsTTL int `json:"default_sts_ttl,omitempty"`

	// MaxStsTTL - (Optional) The max allowed TTL in seconds for STS credentials (credentials TTL are capped to max_sts_ttl). Valid only when credential_type is one of assumed_role or federation_token.
	// +optional
	MaxStsTTL int `json:"max_sts_ttl,omitempty"`
}

// croosplaneToVaultFunc
func crossplaneToVaultFunc(role *v1alpha1.Role) (map[string]interface{}, error) {

	crossplane := &CrossplaneToVault{
		RoleName:              role.Name,
		Backend:               role.Spec.ForProvider.Backend,
		CredentialType:        role.Spec.ForProvider.CredentialType,
		IamRolesArn:           role.Spec.ForProvider.IamRolesArn,
		PoliciesArn:           role.Spec.ForProvider.PoliciesArn,
		PolicyDocument:        role.Spec.ForProvider.PolicyDocument,
		IamGroups:             role.Spec.ForProvider.IamGroups,
		UserPath:              role.Spec.ForProvider.UserPath,
		PermissionBoundaryArn: role.Spec.ForProvider.PermissionBoundaryArn,
		DefaultStsTTL:         role.Spec.ForProvider.DefaultStsTTL,
		MaxStsTTL:             role.Spec.ForProvider.MaxStsTTL,
	}

	return decodeData(crossplane)

}

func decodeData(role *CrossplaneToVault) (map[string]interface{}, error) {
	d := map[string]interface{}{}
	jsonObj, _ := json.Marshal(role)
	json.Unmarshal(jsonObj, &d)
	return d, nil
}
