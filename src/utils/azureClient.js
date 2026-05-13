const { ClientSecretCredential } = require('@azure/identity');
const { SubscriptionClient } = require('@azure/arm-subscriptions');
const { ResourceManagementClient } = require('@azure/arm-resources');
const { NetworkManagementClient } = require('@azure/arm-network');
const { ComputeManagementClient } = require('@azure/arm-compute');
const { StorageManagementClient } = require('@azure/arm-storage');
const { SecurityCenter } = require('@azure/arm-security');
const { MonitorClient } = require('@azure/arm-monitor');
const { KeyVaultManagementClient } = require('@azure/arm-keyvault');
const { AuthorizationManagementClient } = require('@azure/arm-authorization');
const { WebSiteManagementClient } = require('@azure/arm-appservice');
const { ContainerInstanceManagementClient } = require('@azure/arm-containerinstance');
const { ContainerAppsAPIClient } = require('@azure/arm-appcontainers');
const { ContainerServiceClient } = require('@azure/arm-containerservice');
const { SqlManagementClient } = require('@azure/arm-sql');
const { ContainerRegistryManagementClient } = require('@azure/arm-containerregistry');
const { PolicyClient } = require('@azure/arm-policy');

/**
 * Creates an Azure AD credential object from Service Principal fields (tenantId, clientId, clientSecret).
 * This is the identity token source used by every SDK client.
 * 
 * @param {Object} creds - { tenantId, clientId, clientSecret }
 * @returns {ClientSecretCredential}
 */
function buildCredential({ tenantId, clientId, clientSecret }) {
  return new ClientSecretCredential(tenantId, clientId, clientSecret);
}

/**
 * Instantiates all required Azure ARM SDK clients scoped to the given subscription.
 * 
 * @param {Object} creds - Service Principal and Subscription details.
 * @returns {Object} - An object containing all initialized SDK clients.
 */
function buildClients(creds) {
  const credential = buildCredential(creds);
  const { subscriptionId } = creds;

  return {
    credential,
    subscriptions:     new SubscriptionClient(credential),
    resources:         new ResourceManagementClient(credential, subscriptionId),
    network:           new NetworkManagementClient(credential, subscriptionId),
    compute:           new ComputeManagementClient(credential, subscriptionId),
    storage:           new StorageManagementClient(credential, subscriptionId),
    security:          new SecurityCenter(credential, subscriptionId),
    monitor:           new MonitorClient(credential, subscriptionId),
    keyvault:          new KeyVaultManagementClient(credential, subscriptionId),
    authorization:     new AuthorizationManagementClient(credential, subscriptionId),
    web:               new WebSiteManagementClient(credential, subscriptionId),
    containerInstance: new ContainerInstanceManagementClient(credential, subscriptionId),
    containerApps:     new ContainerAppsAPIClient(credential, subscriptionId),
    aks:               new ContainerServiceClient(credential, subscriptionId),
    sql:               new SqlManagementClient(credential, subscriptionId),
    containerRegistry: new ContainerRegistryManagementClient(credential, subscriptionId),
    policy:            new PolicyClient(credential, subscriptionId),
  };
}

/**
 * Validates that the Service Principal credentials can successfully authenticate with Azure.
 * 
 * @param {Object} creds - Service Principal details.
 * @returns {Promise<boolean>} - True if authentication is successful.
 * @throws {Error} - If authentication fails.
 */
async function validateCredentials(creds) {
  const { credential } = buildClients(creds);
  const token = await credential.getToken('https://management.azure.com/.default');
  if (!token || !token.token) throw new Error('Could not acquire access token — check credentials.');
  return true;
}

module.exports = { buildClients, validateCredentials };
