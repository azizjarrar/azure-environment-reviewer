targetScope = 'resourceGroup'
param location string = resourceGroup().location

resource appPlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'test-asp-f1'
  location: location
  sku: { name: 'F1', tier: 'Free' }
  properties: {}
}

resource webApp 'Microsoft.Web/sites@2022-09-01' = {
  name: 'test-webapp-${uniqueString(resourceGroup().id)}'
  location: location
  properties: {
    serverFarmId: appPlan.id
    httpsOnly: false
    clientCertEnabled: false
    siteConfig: {
      minTlsVersion: '1.0'
      ftpsState: 'AllAllowed'
      http20Enabled: false
    }
  }
}
