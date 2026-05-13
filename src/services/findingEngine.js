'use strict';

/**
 * Executes deterministic security checks against collected Azure resource data.
 * This engine focuses on quantitative, rule-based findings that can be reliably
 * identified without LLM reasoning.
 * 
 * @param {Object} results - The raw audit data collected by the reviewEngine.
 * @returns {Array} - A collection of finding objects with ID, severity, and recommendations.
 */
function analyze(results) {
  const findings = [];

  // ── IAM / RBAC ─────────────────────────────────────────────────────────────
  // Identity is the primary security perimeter in Azure. We check for excessive
  // privileges, legacy admin accounts, and custom role hygiene.
  if (results.iam) {
    const iam = results.iam;

    // IAM-001: Excessive Owner assignments
    const owners = iam.filter(r => r.type === 'RoleAssignment' && r.roleName === 'Owner');
    if (owners.length > 2) {
      findings.push({
        id: 'IAM-001', category: 'IAM / RBAC', severity: 'High',
        title: 'Excessive Owner role assignments',
        description: `Found ${owners.length} Owner assignments. Best practice allows a maximum of 2-3 emergency accounts with Owner.`,
        affected: owners.map(o => ({ principalId: o.principalId, principalType: o.principalType, scope: o.scope })),
        recommendation: 'Reduce Owners to 2-3. Use Contributor for daily tasks. Enable PIM for remaining Owners.',
      });
    }

    // IAM-002: Guest users with elevated roles
    const guestElevated = iam.filter(r =>
      r.type === 'RoleAssignment' &&
      r.principalType === 'Guest' &&
      ['Owner', 'Contributor', 'User Access Administrator'].includes(r.roleName)
    );
    if (guestElevated.length > 0) {
      findings.push({
        id: 'IAM-002', category: 'IAM / RBAC', severity: 'Critical',
        title: 'Guest users with highly privileged roles',
        description: `${guestElevated.length} external guest user(s) have Owner, Contributor, or User Access Administrator roles. External parties should follow least privilege.`,
        affected: guestElevated.map(r => ({ principalId: r.principalId, roleName: r.roleName, scope: r.scope })),
        recommendation: 'Revoke high-privilege roles from guest accounts. Assign purpose-specific built-in roles scoped to the minimum required resource.',
      });
    }

    // IAM-003: Service Principals with Owner at subscription scope
    const spOwners = iam.filter(r =>
      r.type === 'RoleAssignment' &&
      r.principalType === 'ServicePrincipal' &&
      r.roleName === 'Owner' &&
      r.scope && r.scope.split('/').filter(Boolean).length <= 2
    );
    if (spOwners.length > 0) {
      findings.push({
        id: 'IAM-003', category: 'IAM / RBAC', severity: 'High',
        title: 'Service Principals with Owner role at subscription scope',
        description: `${spOwners.length} Service Principal(s) have Owner at the subscription level. Compromised SP credentials grant an attacker full subscription control.`,
        affected: spOwners.map(r => ({ principalId: r.principalId, scope: r.scope })),
        recommendation: 'Replace Owner with the most specific built-in role needed. Scope assignments to the minimum required resource group.',
      });
    }

    // IAM-004: Classic administrators still present
    const classicAdmins = iam.filter(r => r.type === 'ClassicAdministrator');
    if (classicAdmins.length > 0) {
      findings.push({
        id: 'IAM-004', category: 'IAM / RBAC', severity: 'Medium',
        title: 'Legacy Classic Administrator accounts present',
        description: `${classicAdmins.length} Classic Administrator account(s) detected. The Co-Administrator role is deprecated and bypasses modern RBAC controls and Conditional Access.`,
        affected: classicAdmins.map(c => ({ name: c.name, email: c.emailAddress, role: c.role })),
        recommendation: 'Remove all Classic Administrator assignments. Migrate to Azure RBAC roles.',
      });
    }

    // IAM-005: Custom roles with wildcard actions
    const wildcardRoles = iam.filter(r =>
      r.type === 'CustomRoleDefinition' && Array.isArray(r.actions) && r.actions.includes('*')
    );
    if (wildcardRoles.length > 0) {
      findings.push({
        id: 'IAM-005', category: 'IAM / RBAC', severity: 'High',
        title: 'Custom roles with wildcard (*) permissions',
        description: `${wildcardRoles.length} custom role(s) grant all actions ('*'), effectively equivalent to Owner. Custom roles should enumerate only required actions.`,
        affected: wildcardRoles.map(r => r.name),
        recommendation: 'Refactor custom roles to explicit action lists. Remove the wildcard and enumerate only required Microsoft.*/operations.',
      });
    }

    // IAM-006: No PIM active or eligible assignments (high-privilege roles not time-bound)
    const pimActive   = iam.filter(r => r.type === 'PIMActiveAssignment');
    const pimEligible = iam.filter(r => r.type === 'PIMEligibleAssignment');
    if (pimActive.length === 0 && pimEligible.length === 0 && owners.length > 0) {
      findings.push({
        id: 'IAM-006', category: 'IAM / RBAC', severity: 'Medium',
        title: 'Privileged Identity Management (PIM) not in use',
        description: 'No PIM active or eligible role assignments found, but high-privilege roles exist. PIM enforces just-in-time access, approval workflows, and time-bounded activation for privileged roles.',
        affected: ['subscription-wide'],
        recommendation: 'Enable Azure AD Privileged Identity Management. Migrate Owner, Contributor, and User Access Administrator assignments to PIM-eligible assignments requiring justification and approval.',
      });
    }
  }

  // ── Networking ─────────────────────────────────────────────────────────────
  if (results.networking) {
    const net = results.networking;

    // NET-001: Management/open ports accessible from internet
    const openRules = [];
    net.filter(r => r.type === 'NetworkSecurityGroup').forEach(nsg => {
      (nsg.rules || []).forEach(rule => {
        const openSrc = ['*', '0.0.0.0/0', 'Internet'].includes(rule.sourceAddressPrefix);
        if (rule.access === 'Allow' && rule.direction === 'Inbound' && openSrc) {
          const port = parseInt(rule.destinationPortRange, 10);
          const dangerousPorts = [22, 23, 3389, 5985, 5986, 1433, 3306, 5432, 6379, 27017];
          if (rule.destinationPortRange === '*' || dangerousPorts.includes(port)) {
            openRules.push(`${nsg.name}: rule "${rule.name}" port ${rule.destinationPortRange} from Internet (priority ${rule.priority})`);
          }
        }
      });
    });
    if (openRules.length > 0) {
      findings.push({
        id: 'NET-001', category: 'Networking', severity: 'Critical',
        title: 'NSG rules allow internet access to sensitive ports',
        description: 'One or more NSGs allow inbound traffic from the internet to management or database ports, creating a broad attack surface.',
        affected: openRules,
        recommendation: 'Restrict source to specific trusted IP ranges. Use Azure Bastion for RDP/SSH. Place databases in private subnets only.',
      });
    }

    // NET-002: Subnets without NSG
    const exemptSubnets = new Set(['AzureBastionSubnet', 'GatewaySubnet', 'AzureFirewallSubnet', 'AzureFirewallManagementSubnet', 'RouteServerSubnet']);
    const subnetsNoNsg = [];
    net.filter(r => r.type === 'VirtualNetwork').forEach(vnet => {
      (vnet.subnets || []).forEach(s => {
        if (!s.nsgId && !exemptSubnets.has(s.name)) {
          subnetsNoNsg.push(`${vnet.name} → ${s.name} (${s.addressPrefix})`);
        }
      });
    });
    if (subnetsNoNsg.length > 0) {
      findings.push({
        id: 'NET-002', category: 'Networking', severity: 'Medium',
        title: 'Subnets without Network Security Group',
        description: `${subnetsNoNsg.length} subnet(s) have no NSG, leaving resources without layer-4 traffic filtering.`,
        affected: subnetsNoNsg,
        recommendation: 'Attach an NSG to every workload subnet. Enforce via Azure Policy "Subnets should have a Network Security Group".',
      });
    }

    // NET-003: NICs with IP forwarding enabled
    const ipForwardNics = net.filter(r => r.type === 'NetworkInterface' && r.enableIpForwarding === true);
    if (ipForwardNics.length > 0) {
      findings.push({
        id: 'NET-003', category: 'Networking', severity: 'Medium',
        title: 'Network Interfaces with IP forwarding enabled',
        description: `${ipForwardNics.length} NIC(s) have IP forwarding enabled. Unless the NIC is on a network virtual appliance, this introduces routing risks.`,
        affected: ipForwardNics.map(n => n.name),
        recommendation: 'Disable IP forwarding on NICs not acting as NVAs. Review routing tables for unexpected paths.',
      });
    }

    // NET-004: Application Gateways without WAF in Prevention mode
    const unsafeGateways = net.filter(r =>
      r.type === 'ApplicationGateway' && (!r.wafEnabled || r.wafMode === 'Detection')
    );
    if (unsafeGateways.length > 0) {
      findings.push({
        id: 'NET-004', category: 'Networking', severity: 'High',
        title: 'Application Gateways without WAF in Prevention mode',
        description: `${unsafeGateways.length} Application Gateway(s) have WAF disabled or in Detection-only mode. Detection mode logs but does not block attacks.`,
        affected: unsafeGateways.map(g => `${g.name} (WAF: ${g.wafEnabled ? 'Detection' : 'Disabled'})`),
        recommendation: 'Enable WAF and switch to Prevention mode. Use OWASP 3.2 ruleset as a minimum baseline.',
      });
    }

    // NET-005: NSG flow logs disabled
    const flowLogMap = {};
    net.filter(r => r.type === 'NSGFlowLog').forEach(fl => {
      const nsgName = (fl.targetNsgId || '').split('/').pop();
      if (nsgName) flowLogMap[nsgName] = fl;
    });
    const nsgsNoFlowLog = net.filter(r => r.type === 'NetworkSecurityGroup').filter(nsg => {
      const fl = flowLogMap[nsg.name];
      return !fl || fl.enabled === false;
    });
    if (nsgsNoFlowLog.length > 0) {
      findings.push({
        id: 'NET-005', category: 'Networking', severity: 'Medium',
        title: 'NSGs without enabled flow logs',
        description: `${nsgsNoFlowLog.length} NSG(s) lack enabled flow logs, reducing network visibility for incident investigation.`,
        affected: nsgsNoFlowLog.map(n => n.name),
        recommendation: 'Enable NSG flow logs v2 for all NSGs. Configure Traffic Analytics for real-time visibility.',
      });
    }

    // NET-006-pre: WAF policies in Detection mode
    const detectionWafs = net.filter(r =>
      r.type === 'WAFPolicy' && (r.policyMode === 'Detection' || r.policyState !== 'Enabled')
    );
    if (detectionWafs.length > 0) {
      findings.push({
        id: 'NET-006a', category: 'Networking', severity: 'High',
        title: 'WAF policies not in Prevention mode',
        description: `${detectionWafs.length} WAF policy(ies) are disabled or in Detection mode. Detection mode logs attacks but does not block them.`,
        affected: detectionWafs.map(w => `${w.name} (mode: ${w.policyMode || 'unknown'}, state: ${w.policyState || 'unknown'})`),
        recommendation: 'Set WAF policy mode to Prevention. Test in Detection mode first, then switch. Use OWASP 3.2 managed rule sets as baseline.',
      });
    }

    // NET-006-pre: Firewall policies with IDPS not in Deny mode
    const weakFirewallPolicies = net.filter(r =>
      r.type === 'FirewallPolicy' && r.idpsMode && r.idpsMode !== 'Deny'
    );
    if (weakFirewallPolicies.length > 0) {
      findings.push({
        id: 'NET-006b', category: 'Networking', severity: 'High',
        title: 'Azure Firewall IDPS not set to Deny mode',
        description: `${weakFirewallPolicies.length} Firewall policy(ies) have IDPS in Alert mode instead of Deny. Alert mode detects but does not block intrusion attempts.`,
        affected: weakFirewallPolicies.map(f => `${f.name} (IDPS: ${f.idpsMode})`),
        recommendation: 'Set IDPS mode to Deny in the Firewall Policy. This requires Azure Firewall Premium SKU.',
      });
    }

    // NET-006: VNets without DDoS Protection
    const noDdos = net.filter(r => r.type === 'VirtualNetwork' && !r.ddosProtection);
    const hasDdosPlan = net.some(r => r.type === 'DDoSProtectionPlan');
    if (noDdos.length > 0 && !hasDdosPlan) {
      findings.push({
        id: 'NET-006', category: 'Networking', severity: 'Medium',
        title: 'Virtual Networks without DDoS Protection Plan',
        description: `${noDdos.length} VNet(s) do not have a DDoS Protection Plan attached. Basic DDoS protection is included but does not provide adaptive tuning or attack analytics.`,
        affected: noDdos.map(v => v.name),
        recommendation: 'Consider Azure DDoS Network Protection for production VNets with public-facing services.',
      });
    }
  }

  // ── Storage ────────────────────────────────────────────────────────────────
  if (results.storage) {
    const storage = results.storage.filter(r => r.type === 'StorageAccount');

    // STG-001: Public blob access or open network default action
    const publicStorage = storage.filter(s => s.allowBlobPublicAccess === true || s.networkDefaultAction === 'Allow');
    if (publicStorage.length > 0) {
      findings.push({
        id: 'STG-001', category: 'Storage', severity: 'High',
        title: 'Storage accounts with public or unrestricted network access',
        description: `${publicStorage.length} storage account(s) allow public blob access or are accessible from any IP.`,
        affected: publicStorage.map(s => s.name),
        recommendation: 'Set allowBlobPublicAccess=false and networkDefaultAction=Deny. Add VNet/IP rules for required access.',
      });
    }

    // STG-002: HTTPS not enforced
    const noHttps = storage.filter(s => !s.enableHttpsTrafficOnly);
    if (noHttps.length > 0) {
      findings.push({
        id: 'STG-002', category: 'Storage', severity: 'High',
        title: 'Storage accounts allowing unencrypted HTTP transfers',
        description: `${noHttps.length} storage account(s) do not enforce HTTPS-only, allowing cleartext data transmission.`,
        affected: noHttps.map(s => s.name),
        recommendation: 'Enable "Secure transfer required" on all storage accounts. Enforce via Azure Policy.',
      });
    }

    // STG-003: TLS version below 1.2
    const oldTls = storage.filter(s => s.minimumTlsVersion && s.minimumTlsVersion !== 'TLS1_2');
    if (oldTls.length > 0) {
      findings.push({
        id: 'STG-003', category: 'Storage', severity: 'Medium',
        title: 'Storage accounts accepting TLS below version 1.2',
        description: `${oldTls.length} storage account(s) accept TLS 1.0/1.1, which have known protocol vulnerabilities.`,
        affected: oldTls.map(s => `${s.name} (min TLS: ${s.minimumTlsVersion})`),
        recommendation: 'Set minimumTlsVersion=TLS1_2 on all storage accounts.',
      });
    }

    // STG-004: Shared key access allowed
    const sharedKey = storage.filter(s => s.allowSharedKeyAccess === true);
    if (sharedKey.length > 0) {
      findings.push({
        id: 'STG-004', category: 'Storage', severity: 'Medium',
        title: 'Storage accounts allowing shared key (account key) authentication',
        description: `${sharedKey.length} storage account(s) allow storage account key authentication. Account keys grant unrestricted access and cannot be scoped.`,
        affected: sharedKey.map(s => s.name),
        recommendation: 'Disable shared key access and use Azure AD (Entra ID) RBAC authentication with Managed Identities.',
      });
    }

    // STG-005: Blob soft delete disabled
    const noSoftDelete = storage.filter(s => s.blobSoftDeleteEnabled === false);
    if (noSoftDelete.length > 0) {
      findings.push({
        id: 'STG-005', category: 'Storage', severity: 'Medium',
        title: 'Storage accounts without blob soft delete',
        description: `${noSoftDelete.length} storage account(s) lack blob soft delete. Deleted blobs cannot be recovered without soft delete.`,
        affected: noSoftDelete.map(s => s.name),
        recommendation: 'Enable blob soft delete with at least 7-day (recommended 30-day) retention.',
      });
    }

    // STG-006-pre: Accounts with no lifecycle policy
    const noLifecycle = storage.filter(s => s.lifecyclePolicy === null);
    if (noLifecycle.length > 0) {
      findings.push({
        id: 'STG-006a', category: 'Storage', severity: 'Low',
        title: 'Storage accounts without lifecycle management policies',
        description: `${noLifecycle.length} storage account(s) have no lifecycle policy configured. Without lifecycle rules, data accumulates indefinitely with no automated tiering or deletion.`,
        affected: noLifecycle.map(s => s.name),
        recommendation: 'Configure lifecycle management policies to tier infrequently accessed data to Cool/Archive and delete expired data. This also supports data retention compliance.',
      });
    }

    // STG-006-pre: SFTP users with password authentication
    const sftpPasswordUsers = [];
    storage.forEach(sa => {
      (sa.localUsers || []).filter(u => u.hasSshPassword).forEach(u => {
        sftpPasswordUsers.push(`${sa.name}/${u.name}`);
      });
    });
    if (sftpPasswordUsers.length > 0) {
      findings.push({
        id: 'STG-006b', category: 'Storage', severity: 'Medium',
        title: 'SFTP local users with password authentication enabled',
        description: `${sftpPasswordUsers.length} SFTP local user(s) have SSH password authentication enabled. SSH key authentication is significantly more secure.`,
        affected: sftpPasswordUsers,
        recommendation: 'Disable SSH password authentication for SFTP local users. Require SSH key-based authentication only.',
      });
    }

    // STG-006: Blob containers with public access
    const publicContainers = [];
    storage.forEach(sa => {
      (sa.containers || []).filter(c => c.publicAccess && c.publicAccess !== 'None').forEach(c => {
        publicContainers.push(`${sa.name}/${c.name} (${c.publicAccess})`);
      });
    });
    if (publicContainers.length > 0) {
      findings.push({
        id: 'STG-006', category: 'Storage', severity: 'Critical',
        title: 'Blob containers with public access enabled',
        description: `${publicContainers.length} blob container(s) are publicly accessible without authentication.`,
        affected: publicContainers,
        recommendation: 'Set public access to None. Use SAS tokens or private endpoints for authorized external sharing.',
      });
    }
  }

  // ── Key Vault ──────────────────────────────────────────────────────────────
  if (results.keyVault) {
    const kvData = results.keyVault.filter(v => v.type === 'KeyVault');

    // KV-001: Purge protection disabled
    const noPurge = kvData.filter(v => !v.purgeProtectionEnabled);
    if (noPurge.length > 0) {
      findings.push({
        id: 'KV-001', category: 'Key Vault', severity: 'Medium',
        title: 'Key Vaults without purge protection',
        description: `${noPurge.length} Key Vault(s) lack purge protection, allowing permanent deletion during the soft-delete window.`,
        affected: noPurge.map(v => v.name),
        recommendation: 'Enable purge protection on all production Key Vaults.',
      });
    }

    // KV-002: Vaults open to all networks
    const openVaults = kvData.filter(v => v.networkDefaultAction === 'Allow');
    if (openVaults.length > 0) {
      findings.push({
        id: 'KV-002', category: 'Key Vault', severity: 'High',
        title: 'Key Vaults accessible from all networks',
        description: `${openVaults.length} Key Vault(s) have networkDefaultAction=Allow, exposing them to any internet source.`,
        affected: openVaults.map(v => v.name),
        recommendation: 'Set networkDefaultAction=Deny. Use private endpoints or VNet service endpoints for access.',
      });
    }

    // KV-003: Secrets without expiry
    const secretsNoExpiry = [];
    kvData.forEach(v => {
      (v.secrets || []).filter(s => s.enabled && !s.expiresOn).forEach(s => {
        secretsNoExpiry.push(`${v.name}/${s.name}`);
      });
    });
    if (secretsNoExpiry.length > 0) {
      findings.push({
        id: 'KV-003', category: 'Key Vault', severity: 'Medium',
        title: 'Secrets without expiry dates',
        description: `${secretsNoExpiry.length} secret(s) have no expiry date. Non-expiring secrets remain valid indefinitely if compromised.`,
        affected: secretsNoExpiry,
        recommendation: 'Set expiry dates on all secrets and implement automated rotation policies.',
      });
    }

    // KV-004: Certificates expiring within 90 days or no expiry
    const certIssues = [];
    const now = Date.now();
    const ninetyDays = 90 * 24 * 60 * 60 * 1000;
    kvData.forEach(v => {
      (v.certificates || []).filter(c => c.enabled).forEach(c => {
        if (!c.expiresOn) {
          certIssues.push(`${v.name}/${c.name} (no expiry set)`);
        } else {
          const msLeft = new Date(c.expiresOn).getTime() - now;
          if (msLeft < ninetyDays) {
            const daysLeft = Math.ceil(msLeft / (24 * 60 * 60 * 1000));
            certIssues.push(`${v.name}/${c.name} (expires in ${daysLeft} days)`);
          }
        }
      });
    });
    if (certIssues.length > 0) {
      findings.push({
        id: 'KV-004', category: 'Key Vault', severity: 'High',
        title: 'Certificates expiring within 90 days or without expiry dates',
        description: `${certIssues.length} certificate(s) are near expiry or unmanaged. Expired certs cause service outages.`,
        affected: certIssues,
        recommendation: 'Configure auto-renewal in Key Vault. Set Azure Monitor alerts for certs expiring within 60 days.',
      });
    }

    // KV-005: Vaults not using RBAC authorization
    const noRbac = kvData.filter(v => !v.enableRbacAuthorization);
    if (noRbac.length > 0) {
      findings.push({
        id: 'KV-005', category: 'Key Vault', severity: 'Low',
        title: 'Key Vaults using legacy Access Policies instead of RBAC',
        description: `${noRbac.length} Key Vault(s) use Access Policies which are less granular than Azure RBAC and cannot be audited via IAM Access Reviews.`,
        affected: noRbac.map(v => v.name),
        recommendation: 'Migrate to Azure RBAC authorization mode. This enables fine-grained roles (Key Vault Secrets User, Key Vault Reader) and Entra ID Privileged Identity Management.',
      });
    }
  }

  // ── Compute ────────────────────────────────────────────────────────────────
  if (results.compute) {
    const compute = results.compute;

    // CMP-001: VMs without disk encryption
    const unencryptedVms = compute.filter(c => c.type === 'VirtualMachine' && !c.diskEncryptionExtension);
    if (unencryptedVms.length > 0) {
      findings.push({
        id: 'CMP-001', category: 'Compute', severity: 'High',
        title: 'Virtual Machines without disk encryption',
        description: `${unencryptedVms.length} VM(s) lack Azure Disk Encryption. Unencrypted disks can be read if detached.`,
        affected: unencryptedVms.map(v => v.name),
        recommendation: 'Enable Azure Disk Encryption using a Key Vault key. Use Customer Managed Keys for regulatory compliance.',
      });
    }

    // CMP-002: AKS clusters with public API server
    const publicAks = compute.filter(c => c.type === 'AKSCluster' && c.apiServerPublicAccess === true);
    if (publicAks.length > 0) {
      findings.push({
        id: 'CMP-002', category: 'Compute', severity: 'High',
        title: 'AKS clusters with publicly accessible Kubernetes API server',
        description: `${publicAks.length} AKS cluster(s) expose the Kubernetes API server to the internet, enabling unauthenticated probing.`,
        affected: publicAks.map(c => `${c.name} (K8s ${c.kubernetesVersion})`),
        recommendation: 'Enable private cluster mode or configure authorized IP ranges to restrict API server access.',
      });
    }

    // CMP-003: App Services / Function Apps without auth
    const noAuth = compute.filter(c =>
      (c.type === 'AppService' || c.type === 'FunctionApp') && c.authEnabled === false
    );
    if (noAuth.length > 0) {
      findings.push({
        id: 'CMP-003', category: 'Compute', severity: 'Medium',
        title: 'App Services and Function Apps without authentication',
        description: `${noAuth.length} App Service(s)/Function App(s) have authentication disabled, making them accessible without identity verification.`,
        affected: noAuth.map(c => `${c.name} (${c.type})`),
        recommendation: 'Enable App Service Authentication (Easy Auth) with Azure AD/Entra ID as the identity provider.',
      });
    }

    // CMP-004: App Services not enforcing HTTPS
    const noHttpsApps = compute.filter(c =>
      (c.type === 'AppService' || c.type === 'FunctionApp') && c.httpsOnly === false
    );
    if (noHttpsApps.length > 0) {
      findings.push({
        id: 'CMP-004', category: 'Compute', severity: 'High',
        title: 'App Services / Function Apps not enforcing HTTPS',
        description: `${noHttpsApps.length} App Service(s) allow HTTP traffic, transmitting data in cleartext.`,
        affected: noHttpsApps.map(c => c.name),
        recommendation: 'Enable HTTPS-only mode and set minimum TLS version to 1.2 on all App Services.',
      });
    }

    // CMP-005: Container Registries with admin user enabled
    const acrAdmin = compute.filter(c => c.type === 'ContainerRegistry' && c.adminUserEnabled === true);
    if (acrAdmin.length > 0) {
      findings.push({
        id: 'CMP-005', category: 'Compute', severity: 'Medium',
        title: 'Container Registries with admin user account enabled',
        description: `${acrAdmin.length} ACR(s) have the admin user enabled. Admin passwords cannot be scoped to specific repos and are difficult to audit.`,
        affected: acrAdmin.map(c => c.name),
        recommendation: 'Disable admin user. Authenticate with Azure AD RBAC using AcrPull/AcrPush roles and Managed Identities.',
      });
    }

    // CMP-006: SQL Servers with allow-all-Azure-services firewall rule
    const sqlAllAzure = [];
    compute.filter(c => c.type === 'SQLServer').forEach(srv => {
      if ((srv.firewallRules || []).some(r => r.allowAllAzureServices)) {
        sqlAllAzure.push(srv.name);
      }
    });
    if (sqlAllAzure.length > 0) {
      findings.push({
        id: 'CMP-006', category: 'Compute', severity: 'High',
        title: 'SQL Servers with "Allow all Azure services" firewall rule',
        description: `${sqlAllAzure.length} SQL Server(s) have the 0.0.0.0 firewall rule, allowing any Azure-hosted service from any subscription to connect.`,
        affected: sqlAllAzure,
        recommendation: 'Remove the allow-all-Azure firewall rule. Use private endpoints or specific VNet service endpoints instead.',
      });
    }

    // CMP-007: SQL databases without TDE
    const noTde = [];
    compute.filter(c => c.type === 'SQLServer').forEach(srv => {
      (srv.databases || []).filter(db => db.tdeEnabled === false).forEach(db => {
        noTde.push(`${srv.name}/${db.name}`);
      });
    });
    if (noTde.length > 0) {
      findings.push({
        id: 'CMP-007', category: 'Compute', severity: 'High',
        title: 'SQL Databases without Transparent Data Encryption',
        description: `${noTde.length} SQL Database(s) lack TDE. Unencrypted data-at-rest violates multiple compliance frameworks.`,
        affected: noTde,
        recommendation: 'Enable TDE on all SQL databases. Use Customer Managed Keys for PCI-DSS or HIPAA compliance.',
      });
    }

    // CMP-008: SQL Servers without Azure AD admin configured
    const noAdAdmin = compute.filter(c => c.type === 'SQLServer' && c.adAdminConfigured === false);
    if (noAdAdmin.length > 0) {
      findings.push({
        id: 'CMP-008', category: 'Compute', severity: 'Medium',
        title: 'SQL Servers without Azure AD administrator',
        description: `${noAdAdmin.length} SQL Server(s) have no Azure AD admin, limiting authentication to SQL credentials which cannot use MFA or Conditional Access.`,
        affected: noAdAdmin.map(c => c.name),
        recommendation: 'Configure an Azure AD administrator for each SQL Server to enable MFA and Conditional Access on database access.',
      });
    }

    // CMP-009-pre: Snapshots with public network access
    const publicSnapshots = compute.filter(c =>
      c.type === 'Snapshot' && c.publicNetworkAccess === 'Enabled'
    );
    if (publicSnapshots.length > 0) {
      findings.push({
        id: 'CMP-009a', category: 'Compute', severity: 'High',
        title: 'Disk snapshots with public network access enabled',
        description: `${publicSnapshots.length} snapshot(s) have public network access enabled. Snapshots can be exported by anyone with Contributor access via a public URL, bypassing private endpoint controls.`,
        affected: publicSnapshots.map(s => s.name),
        recommendation: 'Set publicNetworkAccess=Disabled on all snapshots. Use DiskAccess resources with private endpoints for any required export operations.',
      });
    }

    // CMP-009-pre: SQL threat detection not enabled
    const noThreatDetect = compute.filter(c =>
      c.type === 'SQLServer' && c.threatDetectionEnabled === false
    );
    if (noThreatDetect.length > 0) {
      findings.push({
        id: 'CMP-009b', category: 'Compute', severity: 'High',
        title: 'SQL Servers without threat detection enabled',
        description: `${noThreatDetect.length} SQL Server(s) have threat detection (Microsoft Defender for SQL) disabled. Without threat detection, SQL injection, brute-force, and anomalous query attacks go undetected.`,
        affected: noThreatDetect.map(c => c.name),
        recommendation: 'Enable Microsoft Defender for SQL (serverSecurityAlertPolicies) on all SQL Servers. Configure alert email addresses.',
      });
    }

    // CMP-009-pre: SQL servers not enforcing AAD-only authentication
    const noAadOnly = compute.filter(c =>
      c.type === 'SQLServer' && c.aadOnlyAuthEnabled === false
    );
    if (noAadOnly.length > 0) {
      findings.push({
        id: 'CMP-009c', category: 'Compute', severity: 'Medium',
        title: 'SQL Servers allowing SQL password authentication',
        description: `${noAadOnly.length} SQL Server(s) do not enforce Azure AD-only authentication. SQL password auth cannot leverage MFA, Conditional Access, or Entra ID identity governance.`,
        affected: noAadOnly.map(c => c.name),
        recommendation: 'Enable Azure AD-only authentication on all SQL Servers. This disables SQL login auth entirely, requiring Azure AD for all connections.',
      });
    }

    // CMP-009-pre: SQL TDE using Service Managed Key instead of Customer Managed Key
    const smkTde = compute.filter(c =>
      c.type === 'SQLServer' && c.tdeKeyType === 'ServiceManaged'
    );
    if (smkTde.length > 0) {
      findings.push({
        id: 'CMP-009d', category: 'Compute', severity: 'Low',
        title: 'SQL Servers using Service Managed Key for TDE encryption',
        description: `${smkTde.length} SQL Server(s) use Microsoft-managed keys (Service Managed Key) for TDE. Customer Managed Keys (CMK) give the organization full control and the ability to revoke access instantly.`,
        affected: smkTde.map(c => c.name),
        recommendation: 'Configure TDE with Customer Managed Key stored in Azure Key Vault. This is required for PCI-DSS, HIPAA, and some ISO 27001 implementations.',
      });
    }

    // CMP-009-pre: SQL databases with short backup retention
    const shortBackup = [];
    compute.filter(c => c.type === 'SQLServer').forEach(srv => {
      (srv.databases || []).filter(db => db.backupRetentionDays !== null && db.backupRetentionDays < 7).forEach(db => {
        shortBackup.push(`${srv.name}/${db.name} (${db.backupRetentionDays} days)`);
      });
    });
    if (shortBackup.length > 0) {
      findings.push({
        id: 'CMP-009e', category: 'Compute', severity: 'Medium',
        title: 'SQL databases with backup retention below 7 days',
        description: `${shortBackup.length} SQL database(s) have point-in-time restore retention below 7 days. Short retention limits recovery options after ransomware or accidental data corruption.`,
        affected: shortBackup,
        recommendation: 'Increase short-term backup retention to at least 7 days (35 days for production). Configure long-term retention policies for compliance.',
      });
    }

    // CMP-009: Managed disks with public network access
    const publicDisks = compute.filter(c =>
      c.type === 'ManagedDisk' && c.publicNetworkAccess === 'Enabled' && c.diskState !== 'Attached'
    );
    if (publicDisks.length > 0) {
      findings.push({
        id: 'CMP-009', category: 'Compute', severity: 'Medium',
        title: 'Unattached managed disks with public network access enabled',
        description: `${publicDisks.length} unattached managed disk(s) have public network access enabled. Unattached disks with public access can be exported without a VM.`,
        affected: publicDisks.map(d => d.name),
        recommendation: 'Disable public network access on managed disks. Use private endpoints for disk export operations.',
      });
    }
  }

  // ── Security Center ────────────────────────────────────────────────────────
  if (results.securityCenter) {
    const sc = results.securityCenter;

    // SEC-001: Unhealthy recommendations
    const unhealthy = sc.filter(r => r.type === 'SecurityRecommendation' && r.status !== 'Healthy');
    if (unhealthy.length > 0) {
      findings.push({
        id: 'SEC-001', category: 'Security Center', severity: 'Medium',
        title: 'Active Microsoft Defender for Cloud recommendations',
        description: `${unhealthy.length} active unhealthy recommendation(s) detected in Microsoft Defender for Cloud.`,
        affected: unhealthy.slice(0, 10).map(r => r.name),
        recommendation: 'Prioritize and remediate findings in Defender for Cloud portal, starting with High severity items.',
      });
    }

    // SEC-002: Defender plans on Free tier
    const freeDefender = sc.filter(r => r.type === 'DefenderPlan' && r.pricingTier === 'Free');
    if (freeDefender.length > 0) {
      findings.push({
        id: 'SEC-002', category: 'Security Center', severity: 'High',
        title: 'Microsoft Defender workload protection plans not enabled',
        description: `${freeDefender.length} Defender plan(s) are on Free tier, providing only basic posture management without advanced threat detection.`,
        affected: freeDefender.map(p => p.name),
        recommendation: 'Enable Defender for Servers, SQL, Storage, and Key Vault as a minimum baseline.',
      });
    }

    // SEC-002b: JIT VM access not configured (management ports always open)
    const jitPolicies = sc.filter(r => r.type === 'JITNetworkAccessPolicy');
    if (jitPolicies.length === 0) {
      findings.push({
        id: 'SEC-002b', category: 'Security Center', severity: 'High',
        title: 'Just-In-Time VM access not configured',
        description: 'No JIT Network Access Policies are configured. Without JIT, management ports (RDP/SSH) must be permanently open in NSG rules. JIT provides time-bounded, approved access on demand.',
        affected: ['subscription-wide'],
        recommendation: 'Enable JIT VM access in Defender for Cloud for all VMs with public management ports. This requires Defender for Servers Plan 2.',
      });
    }

    // SEC-002c: Auto-provisioning of security agents disabled
    const agentOff = sc.filter(r =>
      r.type === 'AutoProvisioningSetting' && r.autoProvision === 'Off'
    );
    if (agentOff.length > 0) {
      findings.push({
        id: 'SEC-002c', category: 'Security Center', severity: 'Medium',
        title: 'Defender for Cloud auto-provisioning agents disabled',
        description: `${agentOff.length} auto-provisioning setting(s) are disabled. Without auto-provisioning, monitoring agents may not be deployed to new VMs, creating security visibility gaps.`,
        affected: agentOff.map(a => a.name),
        recommendation: 'Enable auto-provisioning for the Log Analytics agent (MMA/AMA) and Defender for Endpoint in Defender for Cloud settings.',
      });
    }

    // SEC-002d: Active alert suppression rules
    const activeSuppression = sc.filter(r =>
      r.type === 'AlertSuppressionRule' && r.state === 'Enabled'
    );
    if (activeSuppression.length > 0) {
      findings.push({
        id: 'SEC-002d', category: 'Security Center', severity: 'Medium',
        title: 'Active alert suppression rules silencing security alerts',
        description: `${activeSuppression.length} active alert suppression rule(s) are silencing specific alert types. Suppression rules can hide legitimate threats if overly broad or if the original reason for suppression is no longer valid.`,
        affected: activeSuppression.map(r => `${r.name} (alertType: ${r.alertType}, reason: ${r.reason})`),
        recommendation: 'Review all active suppression rules. Ensure each has a current business justification, is scoped as narrowly as possible, and has an expiration date.',
      });
    }

    // SEC-003: No security contact configured
    const contacts = sc.filter(r => r.type === 'SecurityContact' && r.email);
    if (contacts.length === 0) {
      findings.push({
        id: 'SEC-003', category: 'Security Center', severity: 'Medium',
        title: 'No security contact email configured in Defender for Cloud',
        description: 'No security contact is configured. Microsoft cannot notify the organization about security alerts or incidents.',
        affected: ['subscription-wide'],
        recommendation: 'Configure a security contact email in Defender for Cloud settings. Enable alert notifications for all severity levels.',
      });
    }
  }

  // ── Monitor / Logging ──────────────────────────────────────────────────────
  if (results.monitor) {
    const mon = results.monitor;

    // MON-001: Log Analytics workspaces with low retention
    const lowRetention = mon.filter(r =>
      r.type === 'LogAnalyticsWorkspace' && r.retentionDays !== null && r.retentionDays < 90
    );
    if (lowRetention.length > 0) {
      findings.push({
        id: 'MON-001', category: 'Monitor / Logging', severity: 'Medium',
        title: 'Log Analytics workspaces with retention below 90 days',
        description: `${lowRetention.length} workspace(s) retain data for under 90 days. CIS, ISO 27001, and NIST require 90-day online retention minimum.`,
        affected: lowRetention.map(w => `${w.name} (${w.retentionDays} days)`),
        recommendation: 'Increase retention to 90+ days. Archive to Storage Account for 1-year retention at reduced cost.',
      });
    }

    // MON-002: No activity log alerts configured
    const activeAlerts = mon.filter(r => r.type === 'ActivityLogAlert' && r.enabled);
    if (activeAlerts.length === 0) {
      findings.push({
        id: 'MON-002', category: 'Monitor / Logging', severity: 'High',
        title: 'No activity log alerts configured',
        description: 'No active activity log alerts were found. Without alerts on critical operations, security incidents may go undetected.',
        affected: ['subscription-wide'],
        recommendation: 'Create alerts for: Create/Update/Delete Policy Assignment, NSG changes, Key Vault deletion, and role assignment changes.',
      });
    }

    // MON-003-pre: No scheduled query rules (no log-based detection/SIEM alerting)
    const sqRules = mon.filter(r => r.type === 'ScheduledQueryRule' && r.enabled);
    if (sqRules.length === 0) {
      findings.push({
        id: 'MON-003a', category: 'Monitor / Logging', severity: 'Medium',
        title: 'No scheduled query rules (log-based detection) configured',
        description: 'No enabled scheduled query rules found. Scheduled query rules enable SIEM-style detection by running Log Analytics queries on a schedule and alerting on matches. Without them, threats in log data go undetected until manually reviewed.',
        affected: ['subscription-wide'],
        recommendation: 'Create scheduled query rules for: failed login bursts, privilege escalation events, large data exports from storage, impossible travel, and service health degradation.',
      });
    }

    // MON-003-pre: No data collection rules (agent monitoring not configured)
    const dcrules = mon.filter(r => r.type === 'DataCollectionRule');
    if (dcrules.length === 0) {
      findings.push({
        id: 'MON-003b', category: 'Monitor / Logging', severity: 'Low',
        title: 'No data collection rules configured',
        description: 'No Data Collection Rules (DCRs) found. DCRs are the modern mechanism for collecting logs and metrics from Azure resources and VMs via the Azure Monitor Agent. Without DCRs, monitoring relies on legacy MMA agents or no agent-based collection.',
        affected: ['subscription-wide'],
        recommendation: 'Create DCRs to collect Windows Event Logs, Syslog, and performance counters from VMs. Associate DCRs with all production VMs using Azure Monitor Agent.',
      });
    }

    // MON-003: No subscription-level diagnostic settings
    const subDiag = mon.filter(r => r.type === 'DiagnosticSetting' && r.resourceScope === 'subscription');
    if (subDiag.length === 0) {
      findings.push({
        id: 'MON-003', category: 'Monitor / Logging', severity: 'High',
        title: 'No subscription-level diagnostic settings',
        description: 'The Azure Activity Log is not exported to a Log Analytics workspace or Storage Account, making audit trails unavailable beyond the 90-day portal view.',
        affected: ['subscription activity log'],
        recommendation: 'Create a diagnostic setting to export all Activity Log categories to a Log Analytics workspace. This is a CIS Azure Benchmark requirement.',
      });
    }
  }

  // ── Azure Policy ───────────────────────────────────────────────────────────
  if (results.policy) {
    const pol = results.policy;

    // POL-001: No policy assignments at subscription scope
    const subAssignments = pol.filter(r =>
      r.type === 'PolicyAssignment' &&
      r.scope && r.scope.split('/').filter(Boolean).length <= 2
    );
    if (subAssignments.length === 0) {
      findings.push({
        id: 'POL-001', category: 'Azure Policy', severity: 'High',
        title: 'No Azure Policy assignments at subscription scope',
        description: 'No policy assignments at the subscription level. Resource configurations are ungoverned and can drift from security baselines.',
        affected: ['subscription-wide'],
        recommendation: 'Assign the Azure Security Benchmark or CIS Microsoft Azure Foundations Benchmark initiative at subscription scope.',
      });
    }

    // POL-002: Policies in DoNotEnforce mode
    const auditOnly = pol.filter(r => r.type === 'PolicyAssignment' && r.enforcementMode === 'DoNotEnforce');
    if (auditOnly.length > 0) {
      findings.push({
        id: 'POL-002', category: 'Azure Policy', severity: 'Medium',
        title: 'Policy assignments in DoNotEnforce (audit-only) mode',
        description: `${auditOnly.length} policy assignment(s) are in DoNotEnforce mode. These generate compliance reports but do NOT block non-compliant resource deployments.`,
        affected: auditOnly.map(p => p.displayName || p.name),
        recommendation: 'Transition critical security policies to Enforce mode after validating impact in a test environment.',
      });
    }
  }

  return findings;
}

module.exports = { analyze };
