require("dotenv").config();

class ConcurrentBuilder {
    #participants = [];

    participants(...agents) {
        this.#participants.push(...agents);
        return this;
    }

    build() {
        const agents = this.#participants;
        return {
            async *run(globalTask) {
                console.log(`\nRunning ${agents.length} specialized expert analyses in parallel...\n`);

                const agentRuns = agents.map(async (agent) => {
                    const content = agent.data || globalTask;

                    try {
                        // 1. Create a private conversation for this specific expert persona
                        const conversation = await agent.client.conversations.create({ items: [] });

                        // 2. Inject the Persona and the Data
                        const prompt = `You are now acting as the ${agent.name}.

INSTRUCTIONS:
${agent.instructions}

DATA:
${typeof content === 'string' ? content : JSON.stringify(content, null, 2)}

MANDATORY REQUIREMENTS — READ CAREFULLY:
- You MUST execute EVERY numbered security check listed in your instructions above, one by one.
- For EACH check, produce a separate ### finding section even if only one resource is affected.
- Do NOT merge multiple checks into a single finding. Each check = its own ### section.
- Do NOT skip any check. If a check passes cleanly, write "No issues found" for that check and move on.
- List EVERY affected resource in a markdown table — do not say "and others" or truncate.
- Your output must be lengthy and data-rich. A 2-sentence finding is not acceptable.
- Follow the exact output format described in your instructions (severity badge, description, compliance mapping, remediation CLI).`;

                        await agent.client.conversations.items.create(conversation.id, {
                            items: [{
                                type: "message",
                                role: "user",
                                content: prompt,
                            }],
                        });

                        // 3. Generate response using the shared GPT-4o-mini agent
                        const response = await agent.client.responses.create(
                            { conversation: conversation.id },
                            {
                                body: {
                                    agent_reference: { name: agent.masterAgentName, type: "agent_reference" }
                                }
                            }
                        );

                        return {
                            agent: agent.name,
                            content: response.output_text,
                        };
                    } catch (error) {
                        console.error(`Error in ${agent.name} analysis:`, error);
                        return {
                            agent: agent.name,
                            content: `Error during specialized analysis: ${error.message}`,
                        };
                    }
                });

                // Run all experts concurrently
                const results = await Promise.all(agentRuns);
                
                for (const result of results) {
                    yield { type: "agent_response", data: result };
                }

                yield { type: "output", data: results };
            },
        };
    }
}

module.exports = ConcurrentBuilder;

