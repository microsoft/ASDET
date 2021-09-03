# Entity Classification

### Entities and why they matter
An Azure Sentinel workspace contains many tables, which contain different types of data that we classify into categories called entities. For example, the data of a particular column in a particular table might be an instance of an entity like IP address. Other common entities are account, host, file, process, and URL. It’s useful for Security Analysts to know what entities are in their dataset because they can then pivot on a suspicious data point or find anomalous events.

### What we're doing and how we're doing it
The goal of the entity identification module is to automatically infer entities in the dataset. We want to do this because entities are key elements for analysts to use in investigations and can be effectively used to join different datasets where common entities occur. We detect entities using regular expressions for the entities, which are applied to each column in a table. Since most entities have unique identifiers with patterns specific to that entity, using regular expressions usually leads to accurate results. When more than one regular expression matches for a column, we resolve this conflict by first comparing the match percentages and choosing the entity for the regular expression with the highest match percentage. If the match percentages are the same, we use a priority system which assigns a priority level to each entity based on the specificity of the regular expression. For example, an Azure Resource Identifier also matches the regex for a file so the Azure Resource ID regex has a higher priority than the file regex.

> Note: some entity identifiers such as GUIDs/UUIDs are not generally detectable as entities since patterns like this are not specific to any single entity.
