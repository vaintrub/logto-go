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
