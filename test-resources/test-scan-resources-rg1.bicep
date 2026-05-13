// RG1 (tobedeleted1) — IAM, Networking, Storage, Compute, KeyVault, Monitor, SQL
// All intentional misconfigs (open NSG, public blob, no HTTPS, no purge protection) are deliberate to generate findings.
param location string
param sqlLocation string
param suffix string
param adminUsername string
@secure()
param adminPassword string

// ── Managed Identity ──────────────────────────────────────────────────────────
resource identity 'Microsoft.ManagedIdentity/userAssignedIdentities@2023-01-31' = {
  name: 'id-rg1-${suffix}'
  location: location
}

// ── NSG ───────────────────────────────────────────────────────────────────────
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-rg1-${suffix}'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Internet'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '22'
          description: 'INTENTIONAL FINDING: SSH open to internet'
        }
      }
      {
        name: 'Allow-RDP-Internet'
        properties: {
          priority: 110
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '3389'
          description: 'INTENTIONAL FINDING: RDP open to internet'
        }
      }
      {
        name: 'Allow-HTTP-Inbound'
        properties: {
          priority: 120
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '80'
          description: 'INTENTIONAL FINDING: unencrypted HTTP'
        }
      }
      {
        name: 'Allow-HTTPS-Inbound'
        properties: {
          priority: 130
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '443'
        }
      }
    ]
  }
}

// ── Route Table ───────────────────────────────────────────────────────────────
resource routeTable 'Microsoft.Network/routeTables@2023-11-01' = {
  name: 'rt-rg1-${suffix}'
  location: location
  properties: {
    routes: [
      {
        name: 'default-internet'
        properties: {
          addressPrefix: '0.0.0.0/0'
          nextHopType: 'Internet'
        }
      }
    ]
  }
}

// ── Virtual Network ───────────────────────────────────────────────────────────
resource vnet 'Microsoft.Network/virtualNetworks@2023-11-01' = {
  name: 'vnet-rg1-${suffix}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.0.0.0/16']
    }
    subnets: [
      {
        name: 'subnet-vms'
        properties: {
          addressPrefix: '10.0.1.0/24'
          networkSecurityGroup: { id: nsg.id }
          routeTable: { id: routeTable.id }
        }
      }
      {
        name: 'subnet-apps'
        properties: {
          addressPrefix: '10.0.2.0/24'
        }
      }
    ]
  }
}

// ── Public IPs ────────────────────────────────────────────────────────────────
resource pip1 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'pip-vm1-${suffix}'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource pip2 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'pip-vm2-${suffix}'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

// ── NICs ──────────────────────────────────────────────────────────────────────
resource nic1 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'nic-vm1-${suffix}'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: pip1.id }
          subnet: { id: '${vnet.id}/subnets/subnet-vms' }
        }
      }
    ]
  }
}

resource nic2 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'nic-vm2-${suffix}'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: pip2.id }
          subnet: { id: '${vnet.id}/subnets/subnet-vms' }
        }
      }
    ]
  }
}

// ── VMs removed — subscription has 0 quota for Standard_B family (SubscriptionIsOverQuotaForSku).
// Request an increase at: Azure Portal → Subscriptions → Usage + quotas → Standard BS Family vCPUs → Request increase
// The NICs and PIPs above remain as unattached resources (valid Azure resources, appear in networking audit).

// ── Log Analytics Workspace ───────────────────────────────────────────────────
resource logWorkspace 'Microsoft.OperationalInsights/workspaces@2022-10-01' = {
  name: 'log-rg1-${suffix}'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
  }
}

// ── Storage Account (with intentional findings) ────────────────────────────────
resource storageAccount 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st1${suffix}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
  }
}

resource blobService 'Microsoft.Storage/storageAccounts/blobServices@2023-05-01' = {
  parent: storageAccount
  name: 'default'
}

resource publicContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'public-data'
  properties: { publicAccess: 'Blob' }
}

resource privateContainer 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-05-01' = {
  parent: blobService
  name: 'private-data'
  properties: { publicAccess: 'None' }
}

// ── Key Vault (standard, no purge protection — intentional finding) ────────────
resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: 'kv-rg1-${suffix}'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    enablePurgeProtection: true
    accessPolicies: []
    networkAcls: {
      defaultAction: 'Allow'
      bypass: 'AzureServices'
    }
  }
}

resource kvSecret 'Microsoft.KeyVault/vaults/secrets@2023-07-01' = {
  parent: keyVault
  name: 'db-connection-string'
  properties: {
    value: 'test-secret-connection-string-value'
  }
}

resource kvKey 'Microsoft.KeyVault/vaults/keys@2023-07-01' = {
  parent: keyVault
  name: 'encryption-key'
  properties: {
    kty: 'RSA'
    keySize: 2048
  }
}

// ── Key Vault Diagnostic Setting → Log Analytics ───────────────────────────────
resource kvDiag 'Microsoft.Insights/diagnosticSettings@2021-05-01-preview' = {
  scope: keyVault
  name: 'kv-diag-${suffix}'
  properties: {
    workspaceId: logWorkspace.id
    logs: [
      {
        categoryGroup: 'allLogs'
        enabled: true
      }
    ]
    metrics: [
      {
        category: 'AllMetrics'
        enabled: true
      }
    ]
  }
}

// ── SQL Server + Database (Basic 2 GB — cheapest) ─────────────────────────────
resource sqlServer 'Microsoft.Sql/servers@2021-11-01' = {
  name: 'sql-rg1-${suffix}'
  location: sqlLocation
  properties: {
    administratorLogin: adminUsername
    administratorLoginPassword: adminPassword
    version: '12.0'
  }
}

// Intentional finding: firewall allows all IPs
resource sqlFwAll 'Microsoft.Sql/servers/firewallRules@2021-11-01' = {
  parent: sqlServer
  name: 'AllowAllIPs'
  properties: {
    startIpAddress: '0.0.0.0'
    endIpAddress: '255.255.255.255'
  }
}

resource sqlDatabase 'Microsoft.Sql/servers/databases@2021-11-01' = {
  parent: sqlServer
  name: 'db-rg1'
  location: sqlLocation
  sku: {
    name: 'Basic'
    tier: 'Basic'
  }
  properties: {
    maxSizeBytes: 2147483648
  }
}

// ── App Service Plans / Function App removed — subscription quota blocks Basic (B1) and Dynamic (Y1) tiers.
// To add them back: request quota increase in Azure Portal → Subscriptions → Usage + quotas.
// Look for "Basic VMs" (App Service B1) and "Dynamic VMs" (Consumption/Y1 Functions) and request > 0.

// Keeping a standalone storage account (was for Function App — now just another storage resource for the audit).
resource funcStorage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'stf${suffix}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    supportsHttpsTrafficOnly: true
  }
}
