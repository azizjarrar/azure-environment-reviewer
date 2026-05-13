targetScope = 'resourceGroup'
param location string = resourceGroup().location

resource appPlan 'Microsoft.Web/serverfarms@2022-09-01' = {
  name: 'test-asp-simple'
  location: location
  sku: { name: 'F1', tier: 'Free' }
  properties: {}
}
