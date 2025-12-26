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
