// RG2 (tobedeleted2) — Compute (VM + VMSS + ACI), Cosmos DB, ACR, App Service, Networking
// All intentional misconfigs are deliberate to generate findings for the audit tool.
param location string
param suffix string
param adminUsername string
@secure()
param adminPassword string

// ── NSG (with overly permissive rules) ───────────────────────────────────────
resource nsg 'Microsoft.Network/networkSecurityGroups@2023-11-01' = {
  name: 'nsg-rg2-${suffix}'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-All-Inbound'
        properties: {
          priority: 100
          protocol: '*'
          access: 'Allow'
          direction: 'Inbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: '*'
          destinationPortRange: '*'
          description: 'INTENTIONAL FINDING: all inbound traffic allowed'
        }
      }
      {
        name: 'Allow-HTTP-Outbound'
        properties: {
          priority: 100
          protocol: 'Tcp'
          access: 'Allow'
          direction: 'Outbound'
          sourceAddressPrefix: '*'
          sourcePortRange: '*'
          destinationAddressPrefix: 'Internet'
          destinationPortRange: '80'
          description: 'INTENTIONAL FINDING: unencrypted HTTP outbound'
        }
      }
    ]
  }
}

// ── Route Table ───────────────────────────────────────────────────────────────
resource routeTable 'Microsoft.Network/routeTables@2023-11-01' = {
  name: 'rt-rg2-${suffix}'
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
  name: 'vnet-rg2-${suffix}'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.1.0.0/16']
    }
    subnets: [
      {
        name: 'subnet-main'
        properties: {
          addressPrefix: '10.1.1.0/24'
          networkSecurityGroup: { id: nsg.id }
          routeTable: { id: routeTable.id }
        }
      }
      {
        name: 'subnet-vmss'
        properties: {
          addressPrefix: '10.1.2.0/24'
          networkSecurityGroup: { id: nsg.id }
        }
      }
    ]
  }
}

// ── Public IP ─────────────────────────────────────────────────────────────────
resource pip 'Microsoft.Network/publicIPAddresses@2023-11-01' = {
  name: 'pip-rg2-${suffix}'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

// ── NIC ───────────────────────────────────────────────────────────────────────
resource nic 'Microsoft.Network/networkInterfaces@2023-11-01' = {
  name: 'nic-rg2-${suffix}'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          privateIPAllocationMethod: 'Dynamic'
          publicIPAddress: { id: pip.id }
          subnet: { id: '${vnet.id}/subnets/subnet-main' }
        }
      }
    ]
  }
}

// ── VMs and VMSS removed — subscription has 0 quota for Standard_B family (SubscriptionIsOverQuotaForSku).
// Request an increase at: Azure Portal → Subscriptions → Usage + quotas → Standard BS Family vCPUs → Request increase
// The NIC and PIP above remain as unattached resources (valid, appear in networking audit).

// ── Storage Account ───────────────────────────────────────────────────────────
resource storage 'Microsoft.Storage/storageAccounts@2023-05-01' = {
  name: 'st2${suffix}'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    accessTier: 'Hot'
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
  }
}

// ── Cosmos DB (NoSQL API, Serverless — cheapest) ──────────────────────────────
resource cosmosAccount 'Microsoft.DocumentDB/databaseAccounts@2023-11-15' = {
  name: 'cosmos-rg2-${suffix}'
  location: location
  kind: 'GlobalDocumentDB'
  properties: {
    databaseAccountOfferType: 'Standard'
    consistencyPolicy: {
      defaultConsistencyLevel: 'Session'
    }
    locations: [
      {
        locationName: location
        failoverPriority: 0
        isZoneRedundant: false
      }
    ]
    capabilities: [
      {
        name: 'EnableServerless'
      }
    ]
    enableFreeTier: false
    publicNetworkAccess: 'Enabled'
    networkAclBypass: 'None'
  }
}

resource cosmosDb 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases@2023-11-15' = {
  parent: cosmosAccount
  name: 'testdb'
  properties: {
    resource: { id: 'testdb' }
  }
}

resource cosmosContainer 'Microsoft.DocumentDB/databaseAccounts/sqlDatabases/containers@2023-11-15' = {
  parent: cosmosDb
  name: 'testcontainer'
  properties: {
    resource: {
      id: 'testcontainer'
      partitionKey: {
        paths: ['/id']
        kind: 'Hash'
      }
    }
  }
}

// ── Container Registry (Basic — cheapest, admin user enabled = finding) ────────
resource acr 'Microsoft.ContainerRegistry/registries@2023-07-01' = {
  name: 'acr${suffix}rg2'
  location: location
  sku: { name: 'Basic' }
  properties: {
    adminUserEnabled: true
    publicNetworkAccess: 'Enabled'
  }
}

// ── App Service Plan removed — subscription quota blocks Basic (B1) tier ("Basic VMs" quota = 0).

// ── Azure Container Instance (nginx, 1 vCPU / 1 GB — cheapest) ───────────────
resource aci 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: 'aci-rg2-${suffix}'
  location: location
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    containers: [
      {
        name: 'nginx'
        properties: {
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld'
          resources: {
            requests: {
              cpu: 1
              memoryInGB: 1
            }
          }
          ports: [
            { port: 80, protocol: 'TCP' }
          ]
        }
      }
    ]
    ipAddress: {
      type: 'Public'
      ports: [
        { port: 80, protocol: 'TCP' }
      ]
    }
  }
}
