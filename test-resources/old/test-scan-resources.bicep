targetScope = 'subscription'

// ── Parameters ────────────────────────────────────────────────────────────────
@description('Location for all resources')
param location string = 'uksouth'

// ── Resource Groups ────────────────────────────────────────────────────────────
resource rg1 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'rg-test-tobedeleted-1'
  location: location
  tags: { environment: 'test', purpose: 'tobedeleted' }
}

resource rg2 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'rg-test-tobedeleted-2'
  location: location
  tags: { environment: 'test', purpose: 'tobedeleted' }
}

resource rg3 'Microsoft.Resources/resourceGroups@2023-07-01' = {
  name: 'rg-test-tobedeleted-3'
  location: location
  tags: { environment: 'test', purpose: 'tobedeleted' }
}

// ── RG1: Storage + NSG (tests Storage and Networking sections) ─────────────────
module rg1Resources 'test-scan-resources-rg1.bicep' = {
  name: 'rg1Resources'
  scope: rg1
  params: { location: location }
}

// ── RG2: Key Vault + App Service (tests KeyVault and Compute sections) ─────────
module rg2Resources 'test-scan-resources-rg2.bicep' = {
  name: 'rg2Resources'
  scope: rg2
  params: { location: location }
}

// ── RG3: Virtual Network + Public IP (tests Networking section) ────────────────
module rg3Resources 'test-scan-resources-rg3.bicep' = {
  name: 'rg3Resources'
  scope: rg3
  params: { location: location }
}

// ── Policy: Deny public blob access (tests Policy section) ────────────────────
resource denyPublicBlobPolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'test-deny-public-blob'
  properties: {
    displayName: '[TEST] Deny Public Blob Access on Storage Accounts'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/4fa4b6c0-31ca-4c0d-b10d-24b96f62a751'
    enforcementMode: 'DoNotEnforce'
    description: 'Test policy assignment — to be deleted with test resources'
  }
}

resource requireHttpsStoragePolicy 'Microsoft.Authorization/policyAssignments@2023-04-01' = {
  name: 'test-require-https-storage'
  properties: {
    displayName: '[TEST] Require HTTPS on Storage Accounts'
    policyDefinitionId: '/providers/Microsoft.Authorization/policyDefinitions/404c3081-a854-4457-ae30-26a93ef643f9'
    enforcementMode: 'DoNotEnforce'
    description: 'Test policy assignment — to be deleted with test resources'
  }
}
