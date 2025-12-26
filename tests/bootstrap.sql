-- Logto Bootstrap SQL for Integration Tests
-- Creates an M2M application directly in the database after Logto has seeded the schema.
-- This solves the "catch-22" problem: we need M2M credentials to call Logto API,
-- but we can't create M2M apps without API access.

-- M2M Application for Integration Tests
INSERT INTO applications (tenant_id, id, name, description, type, secret, oidc_client_metadata, custom_client_metadata, custom_data, is_third_party, created_at)
VALUES (
  'default',
  '{{.M2MAppID}}',
  'Integration Test M2M',
  'M2M application for logto-go integration tests',
  'MachineToMachine',
  '{{.M2MAppSecret}}',
  '{"redirectUris":[],"postLogoutRedirectUris":[]}',
  '{"idTokenTtl":3600,"refreshTokenTtlInDays":14,"rotateRefreshToken":true}',
  '{}',
  false,
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- M2M Application Secret (for newer Logto versions that use separate secrets table)
INSERT INTO application_secrets (tenant_id, application_id, name, value, created_at)
SELECT
  'default',
  '{{.M2MAppID}}',
  'Default',
  '{{.M2MAppSecret}}',
  NOW()
WHERE EXISTS (SELECT 1 FROM applications WHERE id = '{{.M2MAppID}}')
ON CONFLICT (tenant_id, application_id, name) DO NOTHING;

-- Link M2M app to Management API access role
INSERT INTO applications_roles (tenant_id, id, application_id, role_id)
SELECT
  'default',
  'test-m2m-mgmt-role',
  '{{.M2MAppID}}',
  r.id
FROM roles r
WHERE r.tenant_id = 'default'
  AND r.name = 'Logto Management API access'
  AND r.type = 'MachineToMachine'
ON CONFLICT (id) DO NOTHING;

-- API Resource for testing token exchange (impersonation)
-- The indicator is the audience URI used in token requests
INSERT INTO resources (tenant_id, id, name, indicator, is_default, access_token_ttl)
SELECT
  'default',
  'test-api-resource',
  'Test API Resource',
  'https://test-api.example.com',
  false,
  3600
WHERE NOT EXISTS (SELECT 1 FROM resources WHERE tenant_id = 'default' AND id = 'test-api-resource');

-- Traditional Web App for token exchange (impersonation tests)
-- Token exchange requires a client app (Traditional/SPA), not M2M
INSERT INTO applications (tenant_id, id, name, description, type, secret, oidc_client_metadata, custom_client_metadata, custom_data, is_third_party, created_at)
VALUES (
  'default',
  'test-web-app',
  'Integration Test Web App',
  'Traditional Web App for impersonation token exchange tests',
  'Traditional',
  'test-web-secret-12345',
  '{"redirectUris":["http://localhost:3000/callback"],"postLogoutRedirectUris":[]}',
  '{"idTokenTtl":3600,"refreshTokenTtlInDays":14,"rotateRefreshToken":true}',
  '{}',
  false,
  NOW()
) ON CONFLICT (id) DO NOTHING;

-- Application secret for web app (for newer Logto versions)
INSERT INTO application_secrets (tenant_id, application_id, name, value, created_at)
SELECT
  'default',
  'test-web-app',
  'Default',
  'test-web-secret-12345',
  NOW()
WHERE EXISTS (SELECT 1 FROM applications WHERE id = 'test-web-app')
ON CONFLICT (tenant_id, application_id, name) DO NOTHING;

-- HTTP Email Connector for sending invitation emails
-- The endpoint is configured via template parameter from the test httptest.Server
INSERT INTO connectors (tenant_id, id, connector_id, config, metadata, sync_profile, created_at)
SELECT
  'default',
  'test-http-email',
  'http-email',
  ('{"endpoint": "' || '{{.EmailEndpoint}}' || '"}')::jsonb,
  '{"target": "http-email", "name": {"en": "Test HTTP Email"}}'::jsonb,
  false,
  NOW()
WHERE NOT EXISTS (SELECT 1 FROM connectors WHERE tenant_id = 'default' AND id = 'test-http-email');

-- Test organization for M2M org tokens
INSERT INTO organizations (tenant_id, id, name, description, created_at)
SELECT
  'default',
  'test-org',
  'Test Organization',
  'Organization for integration tests',
  NOW()
WHERE NOT EXISTS (SELECT 1 FROM organizations WHERE tenant_id = 'default' AND id = 'test-org');

-- Organization role for M2M apps (type MUST be 'MachineToMachine')
INSERT INTO organization_roles (tenant_id, id, name, description, type)
SELECT
  'default',
  'test-m2m-org-role',
  'Test M2M Role',
  'M2M role for test organization',
  'MachineToMachine'
WHERE NOT EXISTS (SELECT 1 FROM organization_roles WHERE tenant_id = 'default' AND id = 'test-m2m-org-role');

-- Add M2M app to organization
-- Table has check constraint requiring application type = 'MachineToMachine'
INSERT INTO organization_application_relations (tenant_id, organization_id, application_id)
SELECT 'default', 'test-org', '{{.M2MAppID}}'
WHERE NOT EXISTS (
  SELECT 1 FROM organization_application_relations
  WHERE tenant_id = 'default' AND organization_id = 'test-org' AND application_id = '{{.M2MAppID}}'
);

-- Assign role to M2M app in organization
-- Table has check constraint requiring role type = 'MachineToMachine'
INSERT INTO organization_role_application_relations (tenant_id, organization_id, organization_role_id, application_id)
SELECT 'default', 'test-org', 'test-m2m-org-role', '{{.M2MAppID}}'
WHERE NOT EXISTS (
  SELECT 1 FROM organization_role_application_relations
  WHERE tenant_id = 'default' AND organization_id = 'test-org'
    AND organization_role_id = 'test-m2m-org-role' AND application_id = '{{.M2MAppID}}'
);
