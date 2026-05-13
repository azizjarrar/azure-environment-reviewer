const { AIProjectClient } = require("@azure/ai-projects");
const { DefaultAzureCredential } = require("@azure/identity");
const fs = require('fs');
const path = require('path');
const { findLatestScanDir } = require('./reviewEngine');
const ConcurrentBuilder = require('../agents/class/ConcurrentBuilder');
const Review        = require('../models/Review');
const ReviewSection = require('../models/ReviewSection');
const AIUsage = require('../models/AIUsage');

// Maps agent list keys → ReviewSection keys
const AGENT_TO_SECTION = {
    compute:          'compute',
    networking:       'networking',
    storage:          'storage',
    iam_rbac:         'iam',
    key_vault:        'keyVault',
    monitor:          'monitor',
    security_center:  'securityCenter',
    resource_groups:  'resourceGroups',
    policy:           'policy',
};

// GPT-4.1 pricing (USD per token)
const PRICE_INPUT  = 2.00  / 1_000_000;
const PRICE_OUTPUT = 8.00  / 1_000_000;

async function _saveUsage(userId, type, reviewId, inputTokens, outputTokens) {
    if (!userId) return;
    const costUSD = inputTokens * PRICE_INPUT + outputTokens * PRICE_OUTPUT;
    try {
        await AIUsage.create({ userId, type, reviewId, inputTokens, outputTokens, costUSD });
    } catch (e) {
        console.error('[ai] Failed to save usage record:', e.message);
    }
}

// Import specialized agents
const agentsList = {
    compute: require('../agents/compute'),
    networking: require('../agents/networking'),
    storage: require('../agents/storage'),
    iam_rbac: require('../agents/iam_rbac'),
    key_vault: require('../agents/key_vault'),
    monitor: require('../agents/monitor'),
    security_center: require('../agents/security_center'),
    resource_groups: require('../agents/resource_groups'),
    policy: require('../agents/policy'),
};

/**
 * Helper to build client
 */
function getClient() {
    const projectEndpoint = process.env.PROJECT_ENDPOINT;
    if (!projectEndpoint) {
        throw new Error("PROJECT_ENDPOINT is not defined.");
    }
    return new AIProjectClient(projectEndpoint, new DefaultAzureCredential());
}

/**
 * Internal helper to retrieve an agent by ID or Name.
 */
async function _getAgent(projectClient, nameOrId) {
    try {
        // First, try direct retrieval (assumes nameOrId is an ID like 'asst_...')
        return await projectClient.agents.get(nameOrId);
    } catch (err) {
        // If that fails, list agents and look for a name match.
        // list returns an async iterator in this version of the SDK.
        const agents = await projectClient.agents.list();
        for await (const agent of agents) {
            if (agent.name === nameOrId) {
                return agent;
            }
        }
        
        throw new Error(`Agent "${nameOrId}" not found by ID or Name. Please check your AGENT_NAME in .env and ensures it matches exactly with the agent created in ai.azure.com.`);
    }
}

/**
 * Orchestrates the AI report generation process.
 * It coordinates multiple specialized agents to analyze domain-specific data,
 * then uses a master agent to synthesize those findings into a final Markdown report.
 * 
 * @param {string} subscriptionId - The Azure subscription ID.
 * @param {string|null} reviewId - Optional specific review ID to analyze.
 * @param {string|null} userId - The ID of the user requesting the report.
 * @returns {Promise<Object>} - The generated report and metadata.
 */
async function generateReport(subscriptionId, reviewId, userId = null) {
    if (!reviewId) {
        throw new Error("A specific Review ID is required for AI report generation.");
    }
    const masterAgentName = process.env.AGENT_NAME || "ai-azure-report-generator";

    try {
        let scanDir;
        let effectiveReviewId = reviewId;

        const reviewDoc = await Review.findOne({ reviewId, subscriptionId }).lean();
        if (!reviewDoc) throw new Error(`Review ${reviewId} not found.`);
        scanDir = reviewDoc.scanDir;

        const projectClient = getClient();
        const openaiClient = projectClient.getOpenAIClient();

        // 1. Prepare specialized agents with their data
        const participants = [];
        const fileMapping = {
            compute: 'compute.json',
            networking: 'networking.json',
            storage: 'storage.json',
            iam_rbac: 'iam.json',
            key_vault: 'keyVault.json',
            monitor: 'monitor.json',
            security_center: 'securityCenter.json',
            resource_groups: 'resourceGroups.json',
            policy: 'policy.json',
        };

        const masterAgent = await _getAgent(projectClient, masterAgentName);

        // Load section data from DB, fall back to files for old reviews
        const sectionDocs = await ReviewSection.find({ reviewId }).lean();
        const sectionDataMap = {};
        for (const doc of sectionDocs) {
            sectionDataMap[doc.key] = JSON.stringify(doc.data, null, 2);
        }

        for (const [key, agent] of Object.entries(agentsList)) {
            const sectionKey = AGENT_TO_SECTION[key];
            let data = sectionDataMap[sectionKey];

            if (!data) {
                // Fallback to file for old reviews not yet in DB
                const filePath = path.join(scanDir, fileMapping[key]);
                if (fs.existsSync(filePath)) data = fs.readFileSync(filePath, 'utf8');
            }

            if (data) {
                agent.client = openaiClient;
                agent.masterAgentName = masterAgent.name;
                agent.data = data;
                participants.push(agent);
            }
        }

        // 2. Load findings + summary from DB, fall back to files for old reviews
        const allFindings = reviewDoc.findings?.length
            ? reviewDoc.findings
            : (() => {
                const fp = path.join(scanDir, 'findings.json');
                return fs.existsSync(fp) ? (JSON.parse(fs.readFileSync(fp, 'utf8')).findings || []) : [];
            })();

        const scanSummary = reviewDoc.summary && Object.keys(reviewDoc.summary).length
            ? reviewDoc.summary
            : (() => {
                const sp = path.join(scanDir, 'summary.json');
                return fs.existsSync(sp) ? JSON.parse(fs.readFileSync(sp, 'utf8')) : {};
            })();

        // Map each agent key to its finding ID prefix so we inject only relevant findings
        const findingPrefixMap = {
            iam_rbac:        ['IAM-'],
            networking:      ['NET-'],
            storage:         ['STG-'],
            compute:         ['CMP-'],
            security_center: ['SEC-'],
            key_vault:       ['KV-'],
            monitor:         ['MON-'],
            resource_groups: ['RG-'],
            policy:          ['POL-'],
        };

        // Append deterministic findings to each agent's data payload
        for (const [key, agent] of Object.entries(agentsList)) {
            const prefixes = findingPrefixMap[key] || [];
            const relevant = allFindings.filter(f =>
                prefixes.some(p => (f.id || '').startsWith(p))
            );
            if (relevant.length > 0) {
                agent.data += `\n\nDETERMINISTIC FINDINGS ALREADY IDENTIFIED (rule-based checks — expand on these with deeper analysis):\n${JSON.stringify(relevant, null, 2)}`;
            }
        }

        // 3. Run specialized agents concurrently
        console.log(`Starting specialized analysis with ${participants.length} agents...`);
        const builder = new ConcurrentBuilder();
        const runner = builder.participants(...participants).build();

        let specializedResults = "";
        const runGenerator = runner.run("Execute all security checks.");

        for await (const result of runGenerator) {
            if (result.type === "agent_response") {
                console.log(`Agent '${result.data.agent}' finished analysis.`);
                specializedResults += `\n\n---\n## DOMAIN: ${result.data.agent}\n${result.data.content}`;
            }
        }

        // 4. Final Master Synthesis
        console.log("Specialized analysis complete. Master agent is synthesizing the final report...");

        const conversation = await openaiClient.conversations.create({ items: [] });

        const scanErrorsSection = Object.keys(scanSummary.errors || {}).length > 0
            ? `\nSCAN ERRORS (sections that failed — treat as data gaps, not clean environments):\n${JSON.stringify(scanSummary.errors, null, 2)}`
            : '';

        const finalPrompt = `You are the Lead Azure Security Architect.
        You have received exhaustive analyses from several specialized security experts.
        Your task is to synthesize these findings into a high-quality, professional, and deeply detailed Azure Security Assessment Report.

        SCAN METADATA:
        - Subscription ID: ${scanSummary.subscriptionId || 'unknown'}
        - Scan Date: ${scanSummary.generatedAt || 'unknown'}
        - Sections Audited: ${(scanSummary.sectionsRun || []).join(', ')}
        - Resource Counts by Section: ${JSON.stringify(scanSummary.summary?.bySection || {}, null, 2)}
        ${scanErrorsSection}

        STRUCTURED FINDINGS (deterministic rule-based checks):
        ${JSON.stringify(allFindings || [], null, 2)}

        SPECIALIZED EXPERT FINDINGS (AI analysis per domain):
        ${specializedResults}

        CRITICAL RULE: You are a COMPILER, not a summarizer. Your job is to take every finding from every expert and reproduce it fully in the final report. Do NOT collapse, merge, or omit any finding. If 9 experts each produced 10 findings, the report must contain all 90 findings as separate ### sections.

        INSTRUCTIONS:
        1. **EXECUTIVE SUMMARY**: Start with a professional overview. Include:
           - A "Key Metrics" table: findings by severity (Critical / High / Medium / Low) with count and affected resources.
           - A "Scan Coverage" table: each section audited, number of resources reviewed, and whether any scan errors occurred.
           - A "Top 5 Risks" list with a one-sentence description of each.
        2. **DOMAIN SECTIONS**: One ## section per audit domain (IAM/RBAC, Networking, Storage, Compute, Security Center, Key Vault, Monitor/Logging, Resource Groups, Azure Policy).
        3. **MANDATORY INVENTORY TABLES**: Every ## section MUST start with a "Reviewed Resources Inventory" table (Name, Type, Location).
        4. **REPRODUCE ALL FINDINGS**: For EVERY finding from the expert analyses AND structured findings:
           - Keep it as its own ### sub-section. Do NOT merge findings together.
           - Include: Severity, Risk Description, Business Impact, Affected Resources table, Remediation Steps with CLI.
           - If the expert listed 8 findings for a domain, the report must show all 8.
        5. **ZERO TRUNCATION**: Never write "and others", "similar issues exist", or "see above". List every resource, every finding, every table in full.
        6. **SCAN GAPS**: If any sections errored, add a "Data Collection Gaps" subsection.
        7. **COMPLIANCE MAPPING**: Note CIS Azure Benchmark, ISO 27001, NIST 800-53, or PCI-DSS where applicable.
        8. **APPENDIX**: End with a prioritized remediation roadmap table: Finding ID, Severity, Effort (Low/Medium/High), Recommended Timeline.
        9. **LENGTH**: This report should be 20-40 pages. A short report means findings were dropped — that is a failure.

        Produce the final report in Markdown format. Be exhaustive, data-driven, and professional.`;

        await openaiClient.conversations.items.create(conversation.id, {
            items: [{
                type: "message",
                role: "user",
                content: finalPrompt,
            }],
        });

        const response = await openaiClient.responses.create(
            { conversation: conversation.id },
            {
                body: {
                    agent_reference: { name: masterAgent.name, type: "agent_reference" }
                }
            }
        );

        // Track token usage
        const inputTokens  = response.usage?.input_tokens  ?? Math.ceil(finalPrompt.length / 4);
        const outputTokens = response.usage?.output_tokens ?? Math.ceil((response.output_text || '').length / 4);
        await _saveUsage(userId, 'report', effectiveReviewId, inputTokens, outputTokens);

        // Update Review doc with report content
        try {
            await Review.findOneAndUpdate({ reviewId: effectiveReviewId }, {
            reportContent:     response.output_text,
            reportGeneratedAt: new Date(),
        });
        } catch (e) {
            console.error('[ai] Failed to update Review reportPath:', e.message);
        }

        return {
            report: response.output_text,
            generatedAt: new Date().toISOString(),
            agentName: masterAgent.name,
            conversationId: conversation.id,
            reviewId: effectiveReviewId,
        };

    } catch (error) {
        console.error("AI Service Error:", error);
        throw error;
    }
}


/**
 * Handles interactive follow-up questions about a generated report.
 * 
 * @param {string} conversationId - The existing Azure AI conversation ID.
 * @param {string} userMessage - The user's question or prompt.
 * @param {string|null} userId - The ID of the user.
 * @param {string|null} reviewId - Optional review ID context.
 * @returns {Promise<Object>} - The AI's response and conversation ID.
 */
async function chatWithAgent(conversationId, userMessage, userId = null, reviewId = null) {
    try {
        const projectClient = getClient();
        const agentName = process.env.AGENT_NAME || "ai-azure-repport-generator";
        const agent = await _getAgent(projectClient, agentName);
        const openaiClient = projectClient.getOpenAIClient();

        await openaiClient.conversations.items.create(conversationId, {
            items: [{ type: "message", role: "user", content: userMessage }],
        });

        const response = await openaiClient.responses.create(
            { conversation: conversationId },
            { 
                body: { 
                    agent_reference: { name: agent.name, type: "agent_reference" }
                } 
            }
        );

        const inputTokens  = response.usage?.input_tokens  ?? Math.ceil(userMessage.length / 4);
        const outputTokens = response.usage?.output_tokens ?? Math.ceil((response.output_text || '').length / 4);
        await _saveUsage(userId, 'chat', reviewId, inputTokens, outputTokens);

        return {
            reply: response.output_text,
            conversationId: conversationId
        };
    } catch (error) {
        console.error("AI Chat Service Error:", error);
        throw error;
    }
}

function isConfigured() {
    return !!(process.env.PROJECT_ENDPOINT && process.env.AGENT_NAME);
}

module.exports = {
    generateReport,
    chatWithAgent,
    isConfigured,
};
