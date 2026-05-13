// ============================================================
//  Test resources — covers all 7 audit sections
//  RG: tobedeletedaftertest
//  Deploy: az deployment group create \
//            --resource-group tobedeletedaftertest \
//            --template-file main.bicep \
//            --parameters adminPassword='YourP@ssw0rd123!'
//  Deploy: az deployment group create --resource-group tobedeletedaftertest --template-file main.bicep --parameters adminPassword='YourP@ssw0rd123!'
// ============================================================
//az group create --name tobedeletedaftertest --location eastus
targetScope = 'resourceGroup'

param location string = resourceGroup().location
param prefix   string = 'aztest'

@secure()
param adminPassword string ='defaultP@ssw0rd123!'
param adminUsername string = 'azureadmin'

var suffix     = uniqueString(resourceGroup().id)
var shortSuf   = substring(suffix, 0, 6)
var lbName     = '${prefix}-lb'

// ── NETWORKING ───────────────────────────────────────────────────────────────

resource nsg 'Microsoft.Network/networkSecurityGroups@2023-05-01' = {
  name: '${prefix}-nsg'
  location: location
  properties: {
    securityRules: [
      {
        name: 'Allow-SSH-Any'
        properties: {
          priority: 100
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '22'
          sourceAddressPrefix: '*'           // intentionally open — will appear as finding
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'Allow-RDP-Any'
        properties: {
          priority: 110
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '3389'
          sourceAddressPrefix: '*'           // intentionally open — will appear as finding
          destinationAddressPrefix: '*'
        }
      }
      {
        name: 'Allow-HTTP-Inbound'
        properties: {
          priority: 120
          direction: 'Inbound'
          access: 'Allow'
          protocol: 'Tcp'
          sourcePortRange: '*'
          destinationPortRange: '80'
          sourceAddressPrefix: '*'
          destinationAddressPrefix: '*'
        }
      }
    ]
  }
}

resource vnet 'Microsoft.Network/virtualNetworks@2023-05-01' = {
  name: '${prefix}-vnet'
  location: location
  properties: {
    addressSpace: {
      addressPrefixes: ['10.10.0.0/16']
    }
    subnets: [
      {
        name: 'default'
        properties: {
          addressPrefix: '10.10.1.0/24'
          networkSecurityGroup: { id: nsg.id }
        }
      }
      {
        name: 'AppGatewaySubnet'
        properties: {
          addressPrefix: '10.10.2.0/24'
        }
      }
    ]
  }
}

resource vmPip 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${prefix}-vm-pip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource lbPip 'Microsoft.Network/publicIPAddresses@2023-05-01' = {
  name: '${prefix}-lb-pip'
  location: location
  sku: { name: 'Standard' }
  properties: { publicIPAllocationMethod: 'Static' }
}

resource lb 'Microsoft.Network/loadBalancers@2023-05-01' = {
  name: lbName
  location: location
  sku: { name: 'Standard' }
  properties: {
    frontendIPConfigurations: [
      {
        name: 'frontend'
        properties: { publicIPAddress: { id: lbPip.id } }
      }
    ]
    backendAddressPools: [{ name: 'backendPool' }]
    probes: [
      {
        name: 'httpProbe'
        properties: {
          protocol: 'Http'
          port: 80
          requestPath: '/'
          intervalInSeconds: 15
          numberOfProbes: 2
        }
      }
    ]
    loadBalancingRules: [
      {
        name: 'HTTPRule'
        properties: {
          frontendIPConfiguration: {
            id: resourceId('Microsoft.Network/loadBalancers/frontendIPConfigurations', lbName, 'frontend')
          }
          backendAddressPool: {
            id: resourceId('Microsoft.Network/loadBalancers/backendAddressPools', lbName, 'backendPool')
          }
          probe: {
            id: resourceId('Microsoft.Network/loadBalancers/probes', lbName, 'httpProbe')
          }
          protocol: 'Tcp'
          frontendPort: 80
          backendPort: 80
          idleTimeoutInMinutes: 4
        }
      }
    ]
  }
}

// ── STORAGE ──────────────────────────────────────────────────────────────────

// Insecure account — surfaces findings (public blob, TLS 1.0, HTTP allowed)
resource storageInsecure 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'ins${shortSuf}sa'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: true
    minimumTlsVersion: 'TLS1_0'
    supportsHttpsTrafficOnly: false
    allowSharedKeyAccess: true
  }
}

resource blobInsecure 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageInsecure
  name: 'default'
}

resource containerPublic 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobInsecure
  name: 'public-files'
  properties: { publicAccess: 'Blob' }
}

resource containerPrivate 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobInsecure
  name: 'private-files'
  properties: { publicAccess: 'None' }
}

// Secure account — should pass checks
resource storageSecure 'Microsoft.Storage/storageAccounts@2023-01-01' = {
  name: 'sec${shortSuf}sa'
  location: location
  sku: { name: 'Standard_LRS' }
  kind: 'StorageV2'
  properties: {
    allowBlobPublicAccess: false
    minimumTlsVersion: 'TLS1_2'
    supportsHttpsTrafficOnly: true
    allowSharedKeyAccess: false
  }
}

resource blobSecure 'Microsoft.Storage/storageAccounts/blobServices@2023-01-01' = {
  parent: storageSecure
  name: 'default'
  properties: {
    deleteRetentionPolicy: { enabled: true, days: 7 }
  }
}

resource containerSecure 'Microsoft.Storage/storageAccounts/blobServices/containers@2023-01-01' = {
  parent: blobSecure
  name: 'secure-files'
  properties: { publicAccess: 'None' }
}

// ── KEY VAULT ────────────────────────────────────────────────────────────────

resource keyVault 'Microsoft.KeyVault/vaults@2023-07-01' = {
  name: '${prefix}-kv-${shortSuf}'
  location: location
  properties: {
    sku: { family: 'A', name: 'standard' }
    tenantId: subscription().tenantId
    enableSoftDelete: true
    softDeleteRetentionInDays: 7
    // enablePurgeProtection omitted — defaults to false (will appear as finding)
    enableRbacAuthorization: false        // using access policies
    accessPolicies: []                    // empty — will appear as finding
    networkAcls: {
      defaultAction: 'Allow'             // allows all — will appear as finding
      bypass: 'AzureServices'
    }
  }
}

// ── COMPUTE ──────────────────────────────────────────────────────────────────
// Note: App Service Plan quota is 0 on this subscription — web app omitted.
// The audit tool discovers web apps from real customer subscriptions.

// VM NIC
resource nic 'Microsoft.Network/networkInterfaces@2023-05-01' = {
  name: '${prefix}-vm-nic'
  location: location
  properties: {
    ipConfigurations: [
      {
        name: 'ipconfig1'
        properties: {
          subnet: { id: '${vnet.id}/subnets/default' }
          publicIPAddress: { id: vmPip.id }
          privateIPAllocationMethod: 'Dynamic'
        }
      }
    ]
    networkSecurityGroup: { id: nsg.id }
  }
}

// Linux VM (Standard_B1s — cheapest general-purpose size)
resource vm 'Microsoft.Compute/virtualMachines@2023-09-01' = {
  name: '${prefix}-vm'
  location: location
  properties: {
    hardwareProfile: { vmSize: 'Standard_B1s' }
    osProfile: {
      computerName: 'aztestvm'
      adminUsername: adminUsername
      adminPassword: adminPassword
      linuxConfiguration: { disablePasswordAuthentication: false }
    }
    storageProfile: {
      imageReference: {
        publisher: 'Canonical'
        offer: '0001-com-ubuntu-server-focal'
        sku: '20_04-lts-gen2'
        version: 'latest'
      }
      osDisk: {
        createOption: 'FromImage'
        managedDisk: { storageAccountType: 'Standard_LRS' }
        deleteOption: 'Delete'
      }
    }
    networkProfile: {
      networkInterfaces: [{ id: nic.id }]
    }
  }
}

// Container Instance (nginx, public IP)
resource containerGroup 'Microsoft.ContainerInstance/containerGroups@2023-05-01' = {
  name: '${prefix}-aci'
  location: location
  properties: {
    osType: 'Linux'
    restartPolicy: 'Always'
    ipAddress: {
      type: 'Public'
      ports: [{ port: 80, protocol: 'TCP' }]
    }
    containers: [
      {
        name: 'nginx'
        properties: {
          image: 'mcr.microsoft.com/azuredocs/aci-helloworld'
          ports: [{ port: 80, protocol: 'TCP' }]
          resources: {
            requests: { cpu: 1, memoryInGB: 1 }
          }
        }
      }
    ]
  }
}

// ── MONITOR ──────────────────────────────────────────────────────────────────

resource logAnalytics 'Microsoft.OperationalInsights/workspaces@2023-09-01' = {
  name: '${prefix}-law'
  location: location
  properties: {
    sku: { name: 'PerGB2018' }
    retentionInDays: 30
    publicNetworkAccessForIngestion: 'Enabled'
    publicNetworkAccessForQuery: 'Enabled'
  }
}

resource actionGroup 'Microsoft.Insights/actionGroups@2023-01-01' = {
  name: '${prefix}-alerts-ag'
  location: 'global'
  properties: {
    groupShortName: 'aztestag'
    enabled: true
    emailReceivers: [
      {
        name: 'AdminEmail'
        emailAddress: 'admin@example.com'
        useCommonAlertSchema: true
      }
    ]
  }
}

resource activityAlert 'Microsoft.Insights/activityLogAlerts@2020-10-01' = {
  name: '${prefix}-activity-alert'
  location: 'global'
  properties: {
    enabled: true
    scopes: [resourceGroup().id]
    condition: {
      allOf: [
        { field: 'category', equals: 'Security' }
        { field: 'level',    equals: 'Critical'  }
      ]
    }
    actions: {
      actionGroups: [{ actionGroupId: actionGroup.id }]
    }
  }
}

resource metricAlert 'Microsoft.Insights/metricAlerts@2018-03-01' = {
  name: '${prefix}-storage-metric-alert'
  location: 'global'
  properties: {
    enabled: true
    severity: 2
    evaluationFrequency: 'PT5M'
    windowSize: 'PT15M'
    scopes: [storageInsecure.id]
    criteria: {
      'odata.type': 'Microsoft.Azure.Monitor.SingleResourceMultipleMetricCriteria'
      allOf: [
        {
          name: 'HighTransactions'
          metricName: 'Transactions'
          operator: 'GreaterThan'
          threshold: 1000
          timeAggregation: 'Total'
          criterionType: 'StaticThresholdCriterion'
        }
      ]
    }
    autoMitigate: true
    actions: [{ actionGroupId: actionGroup.id }]
  }
}

// ── IAM — Custom Role ─────────────────────────────────────────────────────────

resource customRole 'Microsoft.Authorization/roleDefinitions@2022-04-01' = {
  name: guid(resourceGroup().id, '${prefix}-custom-role')
  properties: {
    roleName: '${prefix} Test Reader Plus'
    description: 'Test custom role — read access with extra storage permissions'
    type: 'CustomRole'
    assignableScopes: [resourceGroup().id]
    permissions: [
      {
        actions: [
          '*/read'
          'Microsoft.Storage/storageAccounts/blobServices/containers/delete'
          'Microsoft.Storage/storageAccounts/listKeys/action'
        ]
        notActions: []
        dataActions: []
        notDataActions: []
      }
    ]
  }
}

// ── OUTPUTS ───────────────────────────────────────────────────────────────────

output vmPublicIp    string = vmPip.properties.ipAddress
output keyVaultName  string = keyVault.name
output aciIp         string = containerGroup.properties.ipAddress.ip
