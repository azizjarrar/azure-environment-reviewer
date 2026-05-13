const SECTIONS = [
  { key: 'iam',            label: 'IAM / RBAC' },
  { key: 'networking',     label: 'Networking' },
  { key: 'storage',        label: 'Storage' },
  { key: 'compute',        label: 'Compute' },
  { key: 'securityCenter', label: 'Security Center' },
  { key: 'keyVault',       label: 'Key Vault' },
  { key: 'monitor',        label: 'Monitor' },
  { key: 'resourceGroups', label: 'Resource Groups' },
  { key: 'policy',         label: 'Azure Policy' },
];

let activeStream          = null;
let resourcesBySection    = {};
let currentConversationId = null;
let selectedReviewId      = null;
const modalStore          = {};
let   modalIdCtr          = 0;
