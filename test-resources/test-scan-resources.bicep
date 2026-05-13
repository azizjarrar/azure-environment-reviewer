// Subscription-scope entry point.
// Deploy: az deployment sub create --location eastus --template-file test-scan-resources.bicep --parameters adminPassword='P@ssw0rd1234!'
// Destroy:  az group delete --name tobedeleted1 --yes --no-wait && az group delete --name tobedeleted2 --yes --no-wait
targetScope = 'subscription'

@description('Azure region for all resources')
param location string = 'eastus'

@description('Region for SQL Server — eastus has provisioning restrictions on some subscriptions')
param sqlLocation string = 'eastus2'

@description('Admin username for VMs and SQL')
param adminUsername string = 'azureadmin'

@description('Admin password — must meet Azure complexity rules (upper, lower, digit, special, 12+ chars)')
@secure()
param adminPassword string

// 6-char suffix derived from subscription ID — keeps resource names globally unique and consistent
var suffix = take(uniqueString(subscription().subscriptionId), 6)

resource rg1 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'tobedeleted1'
  location: location
}

resource rg2 'Microsoft.Resources/resourceGroups@2022-09-01' = {
  name: 'tobedeleted2'
  location: location
}

module rg1Deploy 'test-scan-resources-rg1.bicep' = {
  name: 'rg1-deploy'
  scope: rg1
  params: {
    location: location
    sqlLocation: sqlLocation
    suffix: suffix
    adminUsername: adminUsername
    adminPassword: adminPassword
  }
}

module rg2Deploy 'test-scan-resources-rg2.bicep' = {
  name: 'rg2-deploy'
  scope: rg2
  params: {
    location: location
    suffix: suffix
    adminUsername: adminUsername
    adminPassword: adminPassword
  }
}
