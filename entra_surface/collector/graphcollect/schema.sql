CREATE TABLE "AZmanagementGroups" (
	id TEXT NOT NULL, 
	name TEXT, 
	type TEXT, 
	display_name TEXT, 
	tenant_id TEXT, 
	details TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "AZresources" (
	id TEXT NOT NULL, 
	name TEXT, 
	type TEXT, 
	type_display_name TEXT, 
	resource_group TEXT, 
	location_display_name TEXT, 
	subscription_display_name TEXT, 
	kind TEXT, 
	location TEXT, 
	subscription_id TEXT, 
	tags TEXT, 
	extended_location TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(subscription_id) REFERENCES "AZsubscriptions" (id)
);
CREATE TABLE "AZroleAssignments" (
	id TEXT NOT NULL, 
	name TEXT, 
	type TEXT, 
	scope TEXT, 
	role_definition_id TEXT, 
	principal_id TEXT, 
	principal_type TEXT, 
	description TEXT, 
	condition TEXT, 
	condition_version TEXT, 
	created_on DATETIME, 
	delegated_managed_identity_resource_id TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(role_definition_id) REFERENCES "AZroleDefinitions" (id)
);
CREATE TABLE "AZroleDefinitions" (
	id TEXT NOT NULL, 
	name TEXT, 
	type TEXT, 
	role_name TEXT, 
	description TEXT, 
	role_type TEXT, 
	created_on DATETIME, 
	permissions TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "AZroleEligibilityScheduleInstances" (
	id TEXT NOT NULL, 
	name TEXT, 
	type TEXT, 
	role_definition_id TEXT, 
	principal_id TEXT, 
	principal_type TEXT, 
	scope TEXT, 
	role_eligibility_schedule_id TEXT, 
	status TEXT, 
	start_date_time DATETIME, 
	end_date_time DATETIME, 
	member_type TEXT, 
	condition TEXT, 
	condition_version TEXT, 
	created_on DATETIME, 
	expanded_properties TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY(role_definition_id) REFERENCES "AZroleDefinitions" (id)
);
CREATE TABLE "AZsubscriptions" (
	id TEXT NOT NULL, 
	subscription_id TEXT, 
	display_name TEXT, 
	state TEXT, 
	subscription_policies TEXT, 
	authorization_source TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "AdministrativeUnits" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"displayName" TEXT, 
	description TEXT, 
	"isMemberManagementRestricted" BOOLEAN, 
	"membershipRule" TEXT, 
	"membershipRuleProcessingState" TEXT, 
	"membershipType" TEXT, 
	visibility TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "AppRoleAssignments" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"creationTimestamp" DATETIME, 
	id TEXT, 
	"principalDisplayName" TEXT, 
	"principalId" TEXT, 
	"principalType" TEXT, 
	"resourceDisplayName" TEXT, 
	"resourceId" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "ApplicationRefs" (
	"appCategory" TEXT, 
	"appContextId" TEXT, 
	"appData" TEXT, 
	"appId" TEXT NOT NULL, 
	"appRoles" TEXT, 
	"availableToOtherTenants" BOOLEAN, 
	certification TEXT, 
	"displayName" TEXT, 
	"errorUrl" TEXT, 
	homepage TEXT, 
	"identifierUris" TEXT, 
	"knownClientApplications" TEXT, 
	"logoutUrl" TEXT, 
	"logoUrl" TEXT, 
	"mainLogo" TEXT, 
	"oauth2Permissions" TEXT, 
	"publisherDomain" TEXT, 
	"publisherName" TEXT, 
	"publicClient" BOOLEAN, 
	"replyUrls" TEXT, 
	"requiredResourceAccess" TEXT, 
	"samlMetadataUrl" TEXT, 
	"supportsConvergence" BOOLEAN, 
	"verifiedPublisher" TEXT, 
	PRIMARY KEY ("appId")
);
CREATE TABLE "Applications" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"addIns" TEXT, 
	"allowActAsForAllClients" BOOLEAN, 
	"allowPassthroughUsers" BOOLEAN, 
	"appBranding" TEXT, 
	"appCategory" TEXT, 
	"appData" TEXT, 
	"appId" TEXT, 
	"applicationTemplateId" TEXT, 
	"appMetadata" TEXT, 
	"appRoles" TEXT, 
	"availableToOtherTenants" BOOLEAN, 
	certification TEXT, 
	"disabledByMicrosoftStatus" TEXT, 
	"displayName" TEXT, 
	"encryptedMsiApplicationSecret" TEXT, 
	"errorUrl" TEXT, 
	"groupMembershipClaims" TEXT, 
	homepage TEXT, 
	"identifierUris" TEXT, 
	"informationalUrls" TEXT, 
	"isDeviceOnlyAuthSupported" BOOLEAN, 
	"keyCredentials" TEXT, 
	"knownClientApplications" TEXT, 
	logo TEXT, 
	"logoUrl" TEXT, 
	"logoutUrl" TEXT, 
	"mainLogo" TEXT, 
	"oauth2AllowIdTokenImplicitFlow" BOOLEAN, 
	"oauth2AllowImplicitFlow" BOOLEAN, 
	"oauth2AllowUrlPathMatching" BOOLEAN, 
	"oauth2Permissions" TEXT, 
	"oauth2RequirePostResponse" BOOLEAN, 
	"optionalClaims" TEXT, 
	"parentalControlSettings" TEXT, 
	"passwordCredentials" TEXT, 
	"publicClient" BOOLEAN, 
	"publisherDomain" TEXT, 
	"recordConsentConditions" TEXT, 
	"replyUrls" TEXT, 
	"requiredResourceAccess" TEXT, 
	"samlMetadataUrl" TEXT, 
	"supportsConvergence" BOOLEAN, 
	"tokenEncryptionKeyId" TEXT, 
	"trustedCertificateSubjects" TEXT, 
	"verifiedPublisher" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "AuthorizationPolicys" (
	id TEXT NOT NULL, 
	"allowInvitesFrom" TEXT, 
	"allowedToSignUpEmailBasedSubscriptions" BOOLEAN, 
	"allowedToUseSSPR" BOOLEAN, 
	"allowEmailVerifiedUsersToJoinOrganization" BOOLEAN, 
	"blockMsolPowerShell" BOOLEAN, 
	"defaultUserRolePermissions" TEXT, 
	"displayName" TEXT, 
	description TEXT, 
	"enabledPreviewFeatures" TEXT, 
	"guestUserRoleId" TEXT, 
	"permissionGrantPolicyIdsAssignedToDefaultUserRole" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "Contacts" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	city TEXT, 
	"cloudAudioConferencingProviderInfo" TEXT, 
	"cloudMSRtcIsSipEnabled" BOOLEAN, 
	"cloudMSRtcOwnerUrn" TEXT, 
	"cloudMSRtcPolicyAssignments" TEXT, 
	"cloudMSRtcPool" TEXT, 
	"cloudMSRtcServiceAttributes" TEXT, 
	"cloudRtcUserPolicies" TEXT, 
	"cloudSipLine" TEXT, 
	"companyName" TEXT, 
	country TEXT, 
	department TEXT, 
	"dirSyncEnabled" BOOLEAN, 
	"displayName" TEXT, 
	"facsimileTelephoneNumber" TEXT, 
	"givenName" TEXT, 
	"jobTitle" TEXT, 
	"lastDirSyncTime" DATETIME, 
	mail TEXT, 
	"mailNickname" TEXT, 
	mobile TEXT, 
	"onPremisesObjectIdentifier" TEXT, 
	"physicalDeliveryOfficeName" TEXT, 
	"postalCode" TEXT, 
	"provisioningErrors" TEXT, 
	"proxyAddresses" TEXT, 
	"sipProxyAddress" TEXT, 
	state TEXT, 
	"streetAddress" TEXT, 
	surname TEXT, 
	"telephoneNumber" TEXT, 
	"thumbnailPhoto" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "Devices" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"accountEnabled" BOOLEAN, 
	"alternativeSecurityIds" TEXT, 
	"approximateLastLogonTimestamp" DATETIME, 
	"bitLockerKey" TEXT, 
	capabilities TEXT, 
	"complianceExpiryTime" DATETIME, 
	"compliantApplications" TEXT, 
	"compliantAppsManagementAppId" TEXT, 
	"deviceCategory" TEXT, 
	"deviceId" TEXT, 
	"deviceKey" TEXT, 
	"deviceManufacturer" TEXT, 
	"deviceManagementAppId" TEXT, 
	"deviceMetadata" TEXT, 
	"deviceModel" TEXT, 
	"deviceObjectVersion" BIGINT, 
	"deviceOSType" TEXT, 
	"deviceOSVersion" TEXT, 
	"deviceOwnership" TEXT, 
	"devicePhysicalIds" TEXT, 
	"deviceSystemMetadata" TEXT, 
	"deviceTrustType" TEXT, 
	"dirSyncEnabled" BOOLEAN, 
	"displayName" TEXT, 
	"domainName" TEXT, 
	"enrollmentProfileName" TEXT, 
	"enrollmentType" TEXT, 
	"exchangeActiveSyncId" TEXT, 
	"externalSourceName" TEXT, 
	hostnames TEXT, 
	"isCompliant" BOOLEAN, 
	"isManaged" BOOLEAN, 
	"isRooted" BOOLEAN, 
	"keyCredentials" TEXT, 
	"lastDirSyncTime" DATETIME, 
	"localCredentials" TEXT, 
	"managementType" TEXT, 
	"onPremisesSecurityIdentifier" TEXT, 
	"organizationalUnit" TEXT, 
	"profileType" TEXT, 
	reserved1 TEXT, 
	"sourceType" TEXT, 
	"systemLabels" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "DirectoryRoles" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"cloudSecurityIdentifier" TEXT, 
	description TEXT, 
	"displayName" TEXT, 
	"isSystem" BOOLEAN, 
	"roleDisabled" BOOLEAN, 
	"roleTemplateId" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "DirectorySettings" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	"templateId" TEXT, 
	"values" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "EligibleRoleAssignments" (
	id TEXT NOT NULL, 
	"principalId" TEXT, 
	"resourceScopes" TEXT, 
	"roleDefinitionId" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "RoleDefinitions" ("objectId")
);
CREATE TABLE "ExtensionPropertys" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"appDisplayName" TEXT, 
	name TEXT, 
	"dataType" TEXT, 
	"isSyncedFromOnPremises" BOOLEAN, 
	"targetObjects" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "Groups" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"appMetadata" TEXT, 
	classification TEXT, 
	"cloudSecurityIdentifier" TEXT, 
	"createdDateTime" DATETIME, 
	"createdByAppId" TEXT, 
	description TEXT, 
	"dirSyncEnabled" BOOLEAN, 
	"displayName" TEXT, 
	"exchangeResources" TEXT, 
	"expirationDateTime" DATETIME, 
	"externalGroupIds" TEXT, 
	"externalGroupProviderId" TEXT, 
	"externalGroupState" TEXT, 
	"creationOptions" TEXT, 
	"groupTypes" TEXT, 
	"infoCatalogs" TEXT, 
	"isAssignableToRole" BOOLEAN, 
	"isMembershipRuleLocked" BOOLEAN, 
	"isPublic" BOOLEAN, 
	"lastDirSyncTime" DATETIME, 
	"licenseAssignment" TEXT, 
	mail TEXT, 
	"mailNickname" TEXT, 
	"mailEnabled" BOOLEAN, 
	"membershipRule" TEXT, 
	"membershipRuleProcessingState" TEXT, 
	"membershipTypes" TEXT, 
	"onPremisesSecurityIdentifier" TEXT, 
	"preferredDataLocation" TEXT, 
	"preferredLanguage" TEXT, 
	"primarySMTPAddress" TEXT, 
	"provisioningErrors" TEXT, 
	"proxyAddresses" TEXT, 
	"renewedDateTime" DATETIME, 
	"resourceBehaviorOptions" TEXT, 
	"resourceProvisioningOptions" TEXT, 
	"securityEnabled" BOOLEAN, 
	"sharepointResources" TEXT, 
	"targetAddress" TEXT, 
	theme TEXT, 
	visibility TEXT, 
	"wellKnownObject" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "IGaccessPackageAssignmentPolicys" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	description TEXT, 
	"allowedTargetScope" TEXT, 
	"specificAllowedTargets" TEXT, 
	expiration TEXT, 
	"countOfUsersIncludedInPolicy" BIGINT, 
	"activeAssignmentCount" BIGINT, 
	"createdDateTime" DATETIME, 
	"createdByString" TEXT, 
	"accessPackageAssignmentRequestorSettings" TEXT, 
	"automaticRequestSettings" TEXT, 
	"lastModifiedByString" TEXT, 
	"approvalSettings" TEXT, 
	"lastModifiedDateTime" DATETIME, 
	"reviewSettings" TEXT, 
	questions TEXT, 
	"notificationSettings" TEXT, 
	"accessPackageNotificationSettings" TEXT, 
	"verifiableCredentialSettings" TEXT, 
	"createdBy" TEXT, 
	"modifiedBy" TEXT, 
	"isDenyPolicy" BOOLEAN, 
	"canExtend" BOOLEAN, 
	"durationInDays" BIGINT, 
	"expirationDateTime" DATETIME, 
	"isCustomAssignmentScheduleAllowed" BOOLEAN, 
	"policyAssignmentType" TEXT, 
	"requestorSettings" TEXT, 
	"accessReviewSettings" TEXT, 
	"assignmentReviewSettings" TEXT, 
	"requestApprovalSettings" TEXT, 
	"accessPackageId" TEXT, 
	"modifiedDateTime" DATETIME, 
	PRIMARY KEY (id), 
	FOREIGN KEY("accessPackageId") REFERENCES "IGaccessPackages" (id)
);
CREATE TABLE "IGaccessPackageAssignmentRequests" (
	id TEXT NOT NULL, 
	"requestType" TEXT, 
	schedule TEXT, 
	answers TEXT, 
	"requestState" TEXT, 
	state TEXT, 
	"requestStatus" TEXT, 
	status TEXT, 
	"createdDateTime" DATETIME, 
	"modifiedDateTime" DATETIME, 
	"completedDate" DATETIME, 
	justification TEXT, 
	"isValidationOnly" BOOLEAN, 
	history TEXT, 
	parameters TEXT, 
	"customProperties" TEXT, 
	"referenceId" TEXT, 
	"verifiedCredentialsData" TEXT, 
	"customExtensionHandlerInstances" TEXT, 
	"customExtensionCalloutInstances" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageAssignmentResourceRoles" (
	id TEXT NOT NULL, 
	"originId" TEXT, 
	"originSystem" TEXT, 
	status TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageAssignments" (
	id TEXT NOT NULL, 
	"catalogId" TEXT, 
	"accessPackageId" TEXT, 
	"assignmentPolicyId" TEXT, 
	"targetId" TEXT, 
	schedule TEXT, 
	"assignmentStatus" TEXT, 
	"assignmentState" TEXT, 
	state TEXT, 
	status TEXT, 
	"isExtended" BOOLEAN, 
	"expiredDateTime" DATETIME, 
	"createdDateTime" DATETIME, 
	"modifiedDateTime" DATETIME, 
	history TEXT, 
	"customExtensionHandlerInstances" TEXT, 
	"customExtensionCalloutInstances" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("accessPackageId") REFERENCES "IGaccessPackages" (id), 
	FOREIGN KEY("assignmentPolicyId") REFERENCES "IGaccessPackageAssignmentPolicys" (id)
);
CREATE TABLE "IGaccessPackageCatalogs" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	"uniqueName" TEXT, 
	description TEXT, 
	"catalogType" TEXT, 
	"catalogStatus" TEXT, 
	state TEXT, 
	"isExternallyVisible" BOOLEAN, 
	"createdBy" TEXT, 
	"createdByString" TEXT, 
	"createdDateTime" DATETIME, 
	"modifiedBy" TEXT, 
	"lastModifiedByString" TEXT, 
	"modifiedDateTime" DATETIME, 
	"lastModifiedDateTime" DATETIME, 
	"serviceManagementReference" TEXT, 
	"privilegeLevel" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageResourceRequests" (
	id TEXT NOT NULL, 
	"requestType" TEXT, 
	"requestState" TEXT, 
	state TEXT, 
	"requestStatus" TEXT, 
	"createdBy" TEXT, 
	"createdByString" TEXT, 
	"createdDateTime" DATETIME, 
	"catalogId" TEXT, 
	"executeImmediately" BOOLEAN, 
	justification TEXT, 
	"expirationDateTime" DATETIME, 
	history TEXT, 
	answers TEXT, 
	parameters TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageResourceRoleScopes" (
	id TEXT NOT NULL, 
	"createdBy" TEXT, 
	"createdByString" TEXT, 
	"createdDateTime" DATETIME, 
	"modifiedBy" TEXT, 
	"modifiedDateTime" DATETIME, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageResourceRoles" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	description TEXT, 
	"roleType" TEXT, 
	"originSystem" TEXT, 
	"originId" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageResourceScopes" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	description TEXT, 
	"originId" TEXT, 
	"originSystem" TEXT, 
	"roleOriginId" TEXT, 
	"isRootScope" BOOLEAN, 
	url TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageResources" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	description TEXT, 
	url TEXT, 
	"resourceType" TEXT, 
	"originId" TEXT, 
	"originSystem" TEXT, 
	"isPendingOnboarding" BOOLEAN, 
	"addedBy" TEXT, 
	"addedOn" DATETIME, 
	attributes TEXT, 
	"createdBy" TEXT, 
	"createdByString" TEXT, 
	"createdDateTime" DATETIME, 
	PRIMARY KEY (id)
);
CREATE TABLE "IGaccessPackageSubjects" (
	"connectedOrganizationId" TEXT, 
	id TEXT NOT NULL, 
	"objectId" TEXT NOT NULL, 
	"altSecId" TEXT, 
	"displayName" TEXT, 
	"principalName" TEXT, 
	email TEXT, 
	"onPremisesSecurityIdentifier" TEXT, 
	type TEXT, 
	"subjectType" TEXT, 
	"subjectLifecycle" TEXT, 
	"cleanupScheduledDateTime" DATETIME, 
	"createdDateTime" DATETIME, 
	PRIMARY KEY (id, "objectId")
);
CREATE TABLE "IGaccessPackages" (
	id TEXT NOT NULL, 
	"catalogId" TEXT, 
	"displayName" TEXT, 
	"uniqueName" TEXT, 
	description TEXT, 
	"isHidden" BOOLEAN, 
	"isRoleScopesVisible" BOOLEAN, 
	"createdBy" TEXT, 
	"createdByString" TEXT, 
	"createdDateTime" DATETIME, 
	"modifiedBy" TEXT, 
	"lastModifiedByString" TEXT, 
	"modifiedDateTime" DATETIME, 
	"lastModifiedDateTime" DATETIME, 
	"lastCriticalModificationDateTime" DATETIME, 
	"lastSuccessfulChangeEvaluationDateTime" DATETIME, 
	PRIMARY KEY (id)
);
CREATE TABLE "OAuth2PermissionGrants" (
	"clientId" TEXT, 
	"consentType" TEXT, 
	"expiryTime" DATETIME, 
	"objectId" TEXT NOT NULL, 
	"principalId" TEXT, 
	"resourceId" TEXT, 
	scope TEXT, 
	"startTime" DATETIME, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "PIMgovernanceAlerts" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"alertName" TEXT, 
	"alertDescription" TEXT, 
	"numberOfAffectedItems" BIGINT, 
	"additionalData" TEXT, 
	"lastModifiedDateTime" DATETIME, 
	"lastScannedDateTime" DATETIME, 
	"severityLevel" TEXT, 
	"alertType" TEXT, 
	"securityImpact" TEXT, 
	"mitigationSteps" TEXT, 
	"howToPrevent" TEXT, 
	"isDisabled" BOOLEAN, 
	"isActive" BOOLEAN, 
	"isResolvable" BOOLEAN, 
	"isConfigurable" BOOLEAN, 
	status TEXT, 
	settings TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id)
);
CREATE TABLE "PIMgovernanceResources" (
	id TEXT NOT NULL, 
	"externalId" TEXT, 
	type TEXT, 
	"displayName" TEXT, 
	status TEXT, 
	"onboardDateTime" DATETIME, 
	"registeredDateTime" DATETIME, 
	"managedAt" TEXT, 
	"registeredRoot" TEXT, 
	"originTenantId" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "PIMgovernanceRoleAssignmentRequests" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"roleDefinitionId" TEXT, 
	"subjectId" TEXT, 
	"scopedResourceId" TEXT, 
	"linkedEligibleRoleAssignmentId" TEXT, 
	type TEXT, 
	"assignmentState" TEXT, 
	"requestedDateTime" DATETIME, 
	"roleAssignmentStartDateTime" DATETIME, 
	"roleAssignmentEndDateTime" DATETIME, 
	reason TEXT, 
	status TEXT, 
	schedule TEXT, 
	"PIMmetadata" TEXT, 
	"ticketNumber" TEXT, 
	"ticketSystem" TEXT, 
	condition TEXT, 
	"conditionVersion" TEXT, 
	"conditionDescription" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "PIMgovernanceRoleDefinitions" (id)
);
CREATE TABLE "PIMgovernanceRoleAssignments" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"roleDefinitionId" TEXT, 
	"subjectId" TEXT, 
	"scopedResourceId" TEXT, 
	"linkedEligibleRoleAssignmentId" TEXT, 
	"externalId" TEXT, 
	"isPermanent" BOOLEAN, 
	"startDateTime" DATETIME, 
	"endDateTime" DATETIME, 
	"memberType" TEXT, 
	"assignmentState" TEXT, 
	status TEXT, 
	condition TEXT, 
	"conditionVersion" TEXT, 
	"conditionDescription" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "PIMgovernanceRoleDefinitions" (id)
);
CREATE TABLE "PIMgovernanceRoleDefinitions" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"externalId" TEXT, 
	"templateId" TEXT, 
	"displayName" TEXT, 
	type TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id)
);
CREATE TABLE "PIMgovernanceRoleSettingV2s" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"roleDefinitionId" TEXT, 
	"isDefault" BOOLEAN, 
	"lastUpdatedDateTime" DATETIME, 
	"lastUpdatedBy" TEXT, 
	"lifeCycleManagement" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "PIMgovernanceRoleDefinitions" (id)
);
CREATE TABLE "PIMgovernanceRoleSettings" (
	id TEXT NOT NULL, 
	"resourceId" TEXT, 
	"roleDefinitionId" TEXT, 
	"isDefault" BOOLEAN, 
	"lastUpdatedDateTime" DATETIME, 
	"lastUpdatedBy" TEXT, 
	"adminEligibleSettings" TEXT, 
	"adminMemberSettings" TEXT, 
	"userEligibleSettings" TEXT, 
	"userMemberSettings" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("resourceId") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "PIMgovernanceRoleDefinitions" (id)
);
CREATE TABLE "PIMprivilegedAccesss" (
	id TEXT NOT NULL, 
	"displayName" TEXT, 
	PRIMARY KEY (id)
);
CREATE TABLE "Policys" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"displayName" TEXT, 
	"keyCredentials" TEXT, 
	"policyType" BIGINT, 
	"policyDetail" TEXT, 
	"policyIdentifier" TEXT, 
	"tenantDefaultPolicy" BIGINT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "RoleAssignments" (
	id TEXT NOT NULL, 
	"principalId" TEXT, 
	"resourceScopes" TEXT, 
	"roleDefinitionId" TEXT, 
	PRIMARY KEY (id), 
	FOREIGN KEY("roleDefinitionId") REFERENCES "RoleDefinitions" ("objectId")
);
CREATE TABLE "RoleDefinitions" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	description TEXT, 
	"displayName" TEXT, 
	"isBuiltIn" BOOLEAN, 
	"isEnabled" BOOLEAN, 
	"resourceScopes" TEXT, 
	"rolePermissions" TEXT, 
	"templateId" TEXT, 
	version TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "ServicePrincipals" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"accountEnabled" BOOLEAN, 
	"addIns" TEXT, 
	"alternativeNames" TEXT, 
	"appBranding" TEXT, 
	"appCategory" TEXT, 
	"appData" TEXT, 
	"appDisplayName" TEXT, 
	"appId" TEXT, 
	"applicationTemplateId" TEXT, 
	"appMetadata" TEXT, 
	"appOwnerTenantId" TEXT, 
	"appRoleAssignmentRequired" BOOLEAN, 
	"appRoles" TEXT, 
	"authenticationPolicy" TEXT, 
	"disabledByMicrosoftStatus" TEXT, 
	"displayName" TEXT, 
	"errorUrl" TEXT, 
	homepage TEXT, 
	"informationalUrls" TEXT, 
	"keyCredentials" TEXT, 
	"logoutUrl" TEXT, 
	"managedIdentityResourceId" TEXT, 
	"microsoftFirstParty" BOOLEAN, 
	"notificationEmailAddresses" TEXT, 
	"oauth2Permissions" TEXT, 
	"passwordCredentials" TEXT, 
	"preferredSingleSignOnMode" TEXT, 
	"preferredTokenSigningKeyEndDateTime" DATETIME, 
	"preferredTokenSigningKeyThumbprint" TEXT, 
	"publisherName" TEXT, 
	"replyUrls" TEXT, 
	"samlMetadataUrl" TEXT, 
	"samlSingleSignOnSettings" TEXT, 
	"servicePrincipalNames" TEXT, 
	tags TEXT, 
	"tokenEncryptionKeyId" TEXT, 
	"servicePrincipalType" TEXT, 
	"useCustomTokenSigningKey" BOOLEAN, 
	"verifiedPublisher" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "TenantDetails" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"assignedPlans" TEXT, 
	"authorizedServiceInstance" TEXT, 
	city TEXT, 
	"cloudRtcUserPolicies" TEXT, 
	"companyLastDirSyncTime" DATETIME, 
	"companyTags" TEXT, 
	"compassEnabled" BOOLEAN, 
	country TEXT, 
	"countryLetterCode" TEXT, 
	"dirSyncEnabled" BOOLEAN, 
	"displayName" TEXT, 
	"isMultipleDataLocationsForServicesEnabled" BOOLEAN, 
	"marketingNotificationEmails" TEXT, 
	"postalCode" TEXT, 
	"preferredLanguage" TEXT, 
	"privacyProfile" TEXT, 
	"provisionedPlans" TEXT, 
	"provisioningErrors" TEXT, 
	"releaseTrack" TEXT, 
	"replicationScope" TEXT, 
	"securityComplianceNotificationMails" TEXT, 
	"securityComplianceNotificationPhones" TEXT, 
	"selfServePasswordResetPolicy" TEXT, 
	state TEXT, 
	street TEXT, 
	"technicalNotificationMails" TEXT, 
	"telephoneNumber" TEXT, 
	"tenantType" TEXT, 
	"createdDateTime" DATETIME, 
	"verifiedDomains" TEXT, 
	"windowsCredentialsEncryptionCertificate" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE "Users" (
	"objectType" TEXT, 
	"objectId" TEXT NOT NULL, 
	"deletionTimestamp" DATETIME, 
	"acceptedAs" TEXT, 
	"acceptedOn" DATETIME, 
	"accountEnabled" BOOLEAN, 
	"ageGroup" TEXT, 
	"alternativeSecurityIds" TEXT, 
	"signInNames" TEXT, 
	"signInNamesInfo" TEXT, 
	"appMetadata" TEXT, 
	"assignedLicenses" TEXT, 
	"assignedPlans" TEXT, 
	city TEXT, 
	"cloudAudioConferencingProviderInfo" TEXT, 
	"cloudMSExchRecipientDisplayType" BIGINT, 
	"cloudMSRtcIsSipEnabled" BOOLEAN, 
	"cloudMSRtcOwnerUrn" TEXT, 
	"cloudMSRtcPolicyAssignments" TEXT, 
	"cloudMSRtcPool" TEXT, 
	"cloudMSRtcServiceAttributes" TEXT, 
	"cloudRtcUserPolicies" TEXT, 
	"cloudSecurityIdentifier" TEXT, 
	"cloudSipLine" TEXT, 
	"cloudSipProxyAddress" TEXT, 
	"companyName" TEXT, 
	"consentProvidedForMinor" TEXT, 
	country TEXT, 
	"createdDateTime" DATETIME, 
	"creationType" TEXT, 
	department TEXT, 
	"dirSyncEnabled" BOOLEAN, 
	"displayName" TEXT, 
	"employeeId" TEXT, 
	"employeeHireDate" DATETIME, 
	"employeeOrgData" TEXT, 
	"employeeType" TEXT, 
	"extensionAttribute1" TEXT, 
	"extensionAttribute2" TEXT, 
	"extensionAttribute3" TEXT, 
	"extensionAttribute4" TEXT, 
	"extensionAttribute5" TEXT, 
	"extensionAttribute6" TEXT, 
	"extensionAttribute7" TEXT, 
	"extensionAttribute8" TEXT, 
	"extensionAttribute9" TEXT, 
	"extensionAttribute10" TEXT, 
	"extensionAttribute11" TEXT, 
	"extensionAttribute12" TEXT, 
	"extensionAttribute13" TEXT, 
	"extensionAttribute14" TEXT, 
	"extensionAttribute15" TEXT, 
	"facsimileTelephoneNumber" TEXT, 
	"givenName" TEXT, 
	"hasOnPremisesShadow" BOOLEAN, 
	"immutableId" TEXT, 
	"infoCatalogs" TEXT, 
	"invitedAsMail" TEXT, 
	"invitedOn" DATETIME, 
	"inviteReplyUrl" TEXT, 
	"inviteResources" TEXT, 
	"inviteTicket" TEXT, 
	"isCompromised" BOOLEAN, 
	"isResourceAccount" BOOLEAN, 
	"jobTitle" TEXT, 
	"jrnlProxyAddress" TEXT, 
	"lastDirSyncTime" DATETIME, 
	"lastPasswordChangeDateTime" DATETIME, 
	"legalAgeGroupClassification" TEXT, 
	mail TEXT, 
	"mailNickname" TEXT, 
	mobile TEXT, 
	"msExchRecipientTypeDetails" BIGINT, 
	"msExchRemoteRecipientType" BIGINT, 
	"msExchMailboxGuid" TEXT, 
	"netId" TEXT, 
	"onPremisesDistinguishedName" TEXT, 
	"onPremisesObjectIdentifier" TEXT, 
	"onPremisesPasswordChangeTimestamp" DATETIME, 
	"onPremisesSecurityIdentifier" TEXT, 
	"onPremisesUserPrincipalName" TEXT, 
	"otherMails" TEXT, 
	"originTenantInfo" TEXT, 
	"passwordPolicies" TEXT, 
	"passwordProfile" TEXT, 
	"physicalDeliveryOfficeName" TEXT, 
	"postalCode" TEXT, 
	"preferredDataLocation" TEXT, 
	"preferredLanguage" TEXT, 
	"primarySMTPAddress" TEXT, 
	"provisionedPlans" TEXT, 
	"provisioningErrors" TEXT, 
	"proxyAddresses" TEXT, 
	"refreshTokensValidFromDateTime" DATETIME, 
	"releaseTrack" TEXT, 
	"searchableDeviceKey" TEXT, 
	"selfServePasswordResetData" TEXT, 
	"shadowAlias" TEXT, 
	"shadowDisplayName" TEXT, 
	"shadowLegacyExchangeDN" TEXT, 
	"shadowMail" TEXT, 
	"shadowMobile" TEXT, 
	"shadowOtherMobile" TEXT, 
	"shadowProxyAddresses" TEXT, 
	"shadowTargetAddress" TEXT, 
	"shadowUserPrincipalName" TEXT, 
	"showInAddressList" BOOLEAN, 
	"sipProxyAddress" TEXT, 
	"smtpAddresses" TEXT, 
	state TEXT, 
	"streetAddress" TEXT, 
	surname TEXT, 
	"telephoneNumber" TEXT, 
	"thumbnailPhoto" TEXT, 
	"usageLocation" TEXT, 
	"userPrincipalName" TEXT, 
	"userState" TEXT, 
	"userStateChangedOn" DATETIME, 
	"userType" TEXT, 
	"strongAuthenticationDetail" TEXT, 
	"windowsInformationProtectionKey" TEXT, 
	PRIMARY KEY ("objectId")
);
CREATE TABLE lnk_application_owner_serviceprincipal (
	"Application" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("Application") REFERENCES "Applications" ("objectId"), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_application_owner_user (
	"Application" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Application") REFERENCES "Applications" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_au_member_device (
	"AdministrativeUnit" TEXT, 
	"Device" TEXT, 
	FOREIGN KEY("AdministrativeUnit") REFERENCES "AdministrativeUnits" ("objectId"), 
	FOREIGN KEY("Device") REFERENCES "Devices" ("objectId")
);
CREATE TABLE lnk_au_member_group (
	"AdministrativeUnit" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("AdministrativeUnit") REFERENCES "AdministrativeUnits" ("objectId"), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_au_member_user (
	"AdministrativeUnit" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("AdministrativeUnit") REFERENCES "AdministrativeUnits" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_eligible_group (
	"AZroleEligibilityScheduleInstance" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("AZroleEligibilityScheduleInstance") REFERENCES "AZroleEligibilityScheduleInstances" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_eligible_serviceprincipal (
	"AZroleEligibilityScheduleInstance" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("AZroleEligibilityScheduleInstance") REFERENCES "AZroleEligibilityScheduleInstances" (id), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_eligible_user (
	"AZroleEligibilityScheduleInstance" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("AZroleEligibilityScheduleInstance") REFERENCES "AZroleEligibilityScheduleInstances" (id), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_group (
	"AZroleAssignment" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("AZroleAssignment") REFERENCES "AZroleAssignments" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_serviceprincipal (
	"AZroleAssignment" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("AZroleAssignment") REFERENCES "AZroleAssignments" (id), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_az_roleassignment_user (
	"AZroleAssignment" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("AZroleAssignment") REFERENCES "AZroleAssignments" (id), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_device_owner (
	"Device" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Device") REFERENCES "Devices" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_group_member_contact (
	"Group" TEXT, 
	"Contact" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("Contact") REFERENCES "Contacts" ("objectId")
);
CREATE TABLE lnk_group_member_device (
	"Group" TEXT, 
	"Device" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("Device") REFERENCES "Devices" ("objectId")
);
CREATE TABLE lnk_group_member_group (
	"Group" TEXT, 
	"childGroup" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("childGroup") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_group_member_serviceprincipal (
	"Group" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_group_member_user (
	"Group" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_group_owner_serviceprincipal (
	"Group" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_group_owner_user (
	"Group" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_ig_ap (
	"IGaccessPackageCatalog" TEXT, 
	"IGaccessPackage" TEXT, 
	FOREIGN KEY("IGaccessPackageCatalog") REFERENCES "IGaccessPackageCatalogs" (id), 
	FOREIGN KEY("IGaccessPackage") REFERENCES "IGaccessPackages" (id)
);
CREATE TABLE lnk_ig_ap_assignment_policy_inscope_group (
	"IGaccessPackageAssignmentPolicy" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignmentPolicy") REFERENCES "IGaccessPackageAssignmentPolicys" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_ig_ap_assignment_policy_inscope_serviceprincipal (
	"IGaccessPackageAssignmentPolicy" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignmentPolicy") REFERENCES "IGaccessPackageAssignmentPolicys" (id), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_ig_ap_assignment_policy_inscope_user (
	"IGaccessPackageAssignmentPolicy" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignmentPolicy") REFERENCES "IGaccessPackageAssignmentPolicys" (id), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_ig_ap_assignment_request (
	"IGaccessPackage" TEXT, 
	"IGaccessPackageAssignmentRequest" TEXT, 
	FOREIGN KEY("IGaccessPackage") REFERENCES "IGaccessPackages" (id), 
	FOREIGN KEY("IGaccessPackageAssignmentRequest") REFERENCES "IGaccessPackageAssignmentRequests" (id)
);
CREATE TABLE lnk_ig_ap_assignment_request_requestor (
	"IGaccessPackageAssignmentRequest" TEXT, 
	"IGaccessPackageSubject" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignmentRequest") REFERENCES "IGaccessPackageAssignmentRequests" (id), 
	FOREIGN KEY("IGaccessPackageSubject") REFERENCES "IGaccessPackageSubjects" (id)
);
CREATE TABLE lnk_ig_ap_assignment_request_target (
	"IGaccessPackageAssignmentRequest" TEXT, 
	"IGaccessPackageSubject" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignmentRequest") REFERENCES "IGaccessPackageAssignmentRequests" (id), 
	FOREIGN KEY("IGaccessPackageSubject") REFERENCES "IGaccessPackageSubjects" (id)
);
CREATE TABLE lnk_ig_ap_assignment_resource_role (
	"IGaccessPackageAssignment" TEXT, 
	"IGaccessPackageAssignmentResourceRole" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignment") REFERENCES "IGaccessPackageAssignments" (id), 
	FOREIGN KEY("IGaccessPackageAssignmentResourceRole") REFERENCES "IGaccessPackageAssignmentResourceRoles" (id)
);
CREATE TABLE lnk_ig_ap_assignment_target (
	"IGaccessPackageAssignment" TEXT, 
	"IGaccessPackageSubject" TEXT, 
	FOREIGN KEY("IGaccessPackageAssignment") REFERENCES "IGaccessPackageAssignments" (id), 
	FOREIGN KEY("IGaccessPackageSubject") REFERENCES "IGaccessPackageSubjects" (id)
);
CREATE TABLE lnk_ig_ap_resource_request (
	"IGaccessPackageResource" TEXT, 
	"IGaccessPackageResourceRequest" TEXT, 
	FOREIGN KEY("IGaccessPackageResource") REFERENCES "IGaccessPackageResources" (id), 
	FOREIGN KEY("IGaccessPackageResourceRequest") REFERENCES "IGaccessPackageResourceRequests" (id)
);
CREATE TABLE lnk_ig_ap_rr (
	"IGaccessPackageResource" TEXT, 
	"IGaccessPackageResourceRole" TEXT, 
	FOREIGN KEY("IGaccessPackageResource") REFERENCES "IGaccessPackageResources" (id), 
	FOREIGN KEY("IGaccessPackageResourceRole") REFERENCES "IGaccessPackageResourceRoles" (id)
);
CREATE TABLE lnk_ig_ap_rr_scope (
	"IGaccessPackage" TEXT, 
	"IGaccessPackageResourceRoleScope" TEXT, 
	FOREIGN KEY("IGaccessPackage") REFERENCES "IGaccessPackages" (id), 
	FOREIGN KEY("IGaccessPackageResourceRoleScope") REFERENCES "IGaccessPackageResourceRoleScopes" (id)
);
CREATE TABLE lnk_ig_ap_rrs_role (
	"IGaccessPackageResourceRoleScope" TEXT, 
	"IGaccessPackageResourceRole" TEXT, 
	FOREIGN KEY("IGaccessPackageResourceRoleScope") REFERENCES "IGaccessPackageResourceRoleScopes" (id), 
	FOREIGN KEY("IGaccessPackageResourceRole") REFERENCES "IGaccessPackageResourceRoles" (id)
);
CREATE TABLE lnk_ig_ap_rrs_scope (
	"IGaccessPackageResourceRoleScope" TEXT, 
	"IGaccessPackageResourceScope" TEXT, 
	FOREIGN KEY("IGaccessPackageResourceRoleScope") REFERENCES "IGaccessPackageResourceRoleScopes" (id), 
	FOREIGN KEY("IGaccessPackageResourceScope") REFERENCES "IGaccessPackageResourceScopes" (id)
);
CREATE TABLE lnk_ig_cg_resource (
	"IGaccessPackageCatalog" TEXT, 
	"IGaccessPackageResource" TEXT, 
	FOREIGN KEY("IGaccessPackageCatalog") REFERENCES "IGaccessPackageCatalogs" (id), 
	FOREIGN KEY("IGaccessPackageResource") REFERENCES "IGaccessPackageResources" (id)
);
CREATE TABLE lnk_pim_resource (
	"PIMprivilegedAccess" TEXT, 
	"PIMgovernanceResource" TEXT, 
	FOREIGN KEY("PIMprivilegedAccess") REFERENCES "PIMprivilegedAccesss" (id), 
	FOREIGN KEY("PIMgovernanceResource") REFERENCES "PIMgovernanceResources" (id)
);
CREATE TABLE lnk_pim_resource_aadgroup (
	"PIMgovernanceResource" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("PIMgovernanceResource") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_pim_resource_rolealerts (
	"PIMgovernanceResource" TEXT, 
	"PIMgovernanceAlert" TEXT, 
	FOREIGN KEY("PIMgovernanceResource") REFERENCES "PIMgovernanceResources" (id), 
	FOREIGN KEY("PIMgovernanceAlert") REFERENCES "PIMgovernanceAlerts" (id)
);
CREATE TABLE lnk_pim_roleassignment_subjectgroup (
	"PIMgovernanceRoleAssignment" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignment") REFERENCES "PIMgovernanceRoleAssignments" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_pim_roleassignment_subjectserviceprincipal (
	"PIMgovernanceRoleAssignment" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignment") REFERENCES "PIMgovernanceRoleAssignments" (id), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_pim_roleassignment_subjectuser (
	"PIMgovernanceRoleAssignment" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignment") REFERENCES "PIMgovernanceRoleAssignments" (id), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_pim_roleassignmentrequest_subjectgroup (
	"PIMgovernanceRoleAssignmentRequest" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignmentRequest") REFERENCES "PIMgovernanceRoleAssignmentRequests" (id), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_pim_roleassignmentrequest_subjectserviceprincipal (
	"PIMgovernanceRoleAssignmentRequest" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignmentRequest") REFERENCES "PIMgovernanceRoleAssignmentRequests" (id), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_pim_roleassignmentrequest_subjectuser (
	"PIMgovernanceRoleAssignmentRequest" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("PIMgovernanceRoleAssignmentRequest") REFERENCES "PIMgovernanceRoleAssignmentRequests" (id), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_policy_user_exclude (
	"Policy" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Policy") REFERENCES "Policys" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_policy_user_include (
	"Policy" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("Policy") REFERENCES "Policys" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_policy_user_include_allusers (
	"Policy" TEXT, 
	FOREIGN KEY("Policy") REFERENCES "Policys" ("objectId")
);
CREATE TABLE lnk_role_member_group (
	"DirectoryRole" TEXT, 
	"Group" TEXT, 
	FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"), 
	FOREIGN KEY("Group") REFERENCES "Groups" ("objectId")
);
CREATE TABLE lnk_role_member_serviceprincipal (
	"DirectoryRole" TEXT, 
	"ServicePrincipal" TEXT, 
	FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"), 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_role_member_user (
	"DirectoryRole" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("DirectoryRole") REFERENCES "DirectoryRoles" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
CREATE TABLE lnk_serviceprincipal_owner_serviceprincipal (
	"ServicePrincipal" TEXT, 
	"childServicePrincipal" TEXT, 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId"), 
	FOREIGN KEY("childServicePrincipal") REFERENCES "ServicePrincipals" ("objectId")
);
CREATE TABLE lnk_serviceprincipal_owner_user (
	"ServicePrincipal" TEXT, 
	"User" TEXT, 
	FOREIGN KEY("ServicePrincipal") REFERENCES "ServicePrincipals" ("objectId"), 
	FOREIGN KEY("User") REFERENCES "Users" ("objectId")
);
